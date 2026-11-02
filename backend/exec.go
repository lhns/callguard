package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lhns/callguard/policy"
)

const maxExecOutput = 64 << 10

type execBackend struct {
	command []string
	classes []string
}

func newExec(cfg policy.Backend) (*execBackend, error) {
	if len(cfg.Command) == 0 || cfg.Command[0] == "" {
		return nil, errors.New("exec backend needs command")
	}
	return &execBackend{command: cfg.Command, classes: cfg.DataClasses}, nil
}

func (e *execBackend) Name() string {
	base := filepath.Base(e.command[0])
	return "exec:" + strings.TrimSuffix(base, filepath.Ext(base))
}
func (e *execBackend) DataClasses() []string { return e.classes }

// limitWriter keeps at most max bytes and records overflow.
type limitWriter struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	n := len(p)
	if room := w.max - w.buf.Len(); len(p) > room {
		w.overflow = true
		p = p[:room]
	}
	w.buf.Write(p)
	return n, nil // never fail: the process finishes or ctx kills it
}

func (e *execBackend) Classify(ctx context.Context, req ClassifyRequest) (ClassifyResult, error) {
	in, err := json.Marshal(struct {
		Schema string `json:"schema"`
		ClassifyRequest
	}{ClassifySchema, req})
	if err != nil {
		return ClassifyResult{}, err
	}
	cmd := exec.CommandContext(ctx, e.command[0], e.command[1:]...)
	cmd.Stdin = bytes.NewReader(in)
	out := &limitWriter{max: maxExecOutput}
	stderr := &limitWriter{max: 2048}
	cmd.Stdout, cmd.Stderr = out, stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ClassifyResult{}, fmt.Errorf("exec: %w", ctx.Err())
		}
		return ClassifyResult{}, fmt.Errorf("exec: %w: %s", err, clip(strings.TrimSpace(stderr.buf.String()), maxErrBody))
	}
	if out.overflow {
		return ClassifyResult{}, errors.New("exec: output exceeds 64 KiB")
	}
	var res ClassifyResult
	if err := json.Unmarshal(out.buf.Bytes(), &res); err != nil {
		return ClassifyResult{}, fmt.Errorf("exec: bad output: %w", err)
	}
	return res, nil
}
