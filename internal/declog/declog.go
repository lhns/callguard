// Package declog writes and reads callguard's decision log (design §11):
// one JSON object per line, appended.
package declog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// TailBytes is how much of the log's end the deny-streak reader looks at.
const TailBytes = 1 << 20

// Entry is one log line. It never holds transcript text. Reason is empty for
// llm verdicts unless input logging is on, because it can quote arguments.
type Entry struct {
	TS           string          `json:"ts"`
	ID           string          `json:"id"`
	SessionID    string          `json:"session_id,omitempty"`
	ToolUseID    string          `json:"tool_use_id,omitempty"`
	Harness      string          `json:"harness,omitempty"`
	Tool         string          `json:"tool"`
	Kind         string          `json:"kind"`
	InputSHA256  string          `json:"input_sha256"`
	Decision     string          `json:"decision"`
	Enforced     bool            `json:"enforced"`
	Layer        string          `json:"layer"`
	Rule         string          `json:"rule,omitempty"`
	Confidence   float64         `json:"confidence"`
	Backend      string          `json:"backend,omitempty"`
	PolicyRev    string          `json:"policy_rev,omitempty"`
	LatencyMS    int64           `json:"latency_ms"`
	Unattended   bool            `json:"unattended,omitempty"`
	InputTokens  int             `json:"input_tokens,omitempty"`
	OutputTokens int             `json:"output_tokens,omitempty"`
	Escalated    bool            `json:"escalated,omitempty"` // an llm deny turned into ask by the deny streak
	Shadow       []ShadowVerdict `json:"shadow,omitempty"`    // verdicts of layers in shadow mode that did not end the pipeline
	Reason       string          `json:"reason,omitempty"`
	Input        json.RawMessage `json:"input,omitempty"`
}

// ShadowVerdict is what a layer in shadow mode would have decided. It has no
// reason text: that can quote arguments.
type ShadowVerdict struct {
	Layer    string `json:"layer"`
	Decision string `json:"decision"`
	Rule     string `json:"rule,omitempty"`
}

// DefaultPath is <state dir>/callguard/decisions.jsonl.
func DefaultPath() string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "callguard", "decisions.jsonl")
	}
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LocalAppData")
		if base == "" {
			base = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(base, "callguard", "decisions.jsonl")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "callguard", "decisions.jsonl")
	}
	return filepath.Join(home, ".local", "state", "callguard", "decisions.jsonl")
}

// Logger appends entries to one file. It is safe for concurrent use.
type Logger struct {
	path string
	mu   sync.Mutex
}

// New returns a logger for path. The file and its directory are created on
// the first Append (dir 0700, file 0600).
func New(path string) *Logger { return &Logger{path: path} }

// Path returns the log file path.
func (l *Logger) Path() string { return l.path }

// Append writes e as one line.
func (l *Logger) Append(e Entry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(line) // one write: concurrent processes do not interleave lines
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// ReadTail returns the entries of sessionID within the last TailBytes of the
// file, oldest first. A missing file is no entries. Unparseable lines (a cut
// first line, a corrupt line) are skipped.
func ReadTail(path, sessionID string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	skipFirst := false
	if st.Size() > TailBytes {
		if _, err := f.Seek(st.Size()-TailBytes, io.SeekStart); err != nil {
			return nil, err
		}
		skipFirst = true
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if skipFirst {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	var out []Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.SessionID == sessionID {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// LLMDenies counts the session's enforced llm-layer denies: those in a row at
// the end of the llm-layer history (consecutive) and all of them (total).
// Entries of other layers neither count nor break the run, and neither do
// escalated denies (shown to a human as ask), so an escalation stays in force
// until the judge allows something.
func LLMDenies(entries []Entry) (consecutive, total int) {
	run := true
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.Layer != "llm" || e.Escalated {
			continue
		}
		if e.Decision == "deny" && e.Enforced {
			total++
			if run {
				consecutive++
			}
		} else {
			run = false
		}
	}
	return consecutive, total
}
