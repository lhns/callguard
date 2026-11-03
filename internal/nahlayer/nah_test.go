package nahlayer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is the fake nah: the tests re-run the test binary with
// NAH_FAKE set. It is not a test when NAH_FAKE is unset.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("NAH_FAKE")
	if mode == "" {
		return
	}
	in, _ := io.ReadAll(os.Stdin)
	var req struct {
		V    int    `json:"v"`
		Tool string `json:"tool"`
		Cwd  string `json:"cwd"`
	}
	_ = json.Unmarshal(in, &req)
	out := func(code int, verdict, reason, name string) {
		attr := "[]"
		if name != "" {
			attr = fmt.Sprintf(`[{"kind":"guard","name":%q},{"kind":"x","name":"second"}]`, name)
		}
		fmt.Printf(`{"schema":"nah/decide/v1","verdict":%q,"reason":%q,"policy_attributions":%s}`, verdict, reason, attr)
		os.Exit(code)
	}
	switch mode {
	case "block":
		out(1, "block", fmt.Sprintf("v=%d tool=%s cwd=%s last-arg=%s", req.V, req.Tool, req.Cwd, os.Args[len(os.Args)-1]), "git-force")
	case "block-no-attr":
		out(1, "block", "blocked", "")
	case "delegate":
		out(2, "delegate", "not mine", "")
	case "coverage":
		fmt.Print(`{"schema":"nah/decide/v1","verdict":"delegate","coverage":"partial","duration_us":12}`)
		os.Exit(2)
	case "coverage-object":
		fmt.Print(`{"schema":"nah/decide/v1","verdict":"delegate","coverage":{"x":1}}`)
		os.Exit(2)
	case "fail":
		os.Exit(3)
	case "badargs":
		os.Exit(4)
	case "garbage":
		fmt.Print("not json")
		os.Exit(1)
	case "wrong-schema":
		fmt.Print(`{"schema":"other","verdict":"block"}`)
		os.Exit(1)
	case "mismatch":
		out(2, "block", "x", "")
	case "slow":
		time.Sleep(30 * time.Second)
	}
	os.Exit(9)
}

func fake(t *testing.T, mode string) []string {
	t.Helper()
	t.Setenv("NAH_FAKE", mode)
	return []string{os.Args[0], "-test.run=TestHelperProcess", "--"}
}

func TestRun(t *testing.T) {
	input := json.RawMessage(`{"command":"git push -f"}`)
	r, err := Run(context.Background(), fake(t, "block"), 5*time.Second, "Bash", input, "/w")
	if err != nil || r.Verdict != Block || r.Rule != "git-force" {
		t.Fatalf("block: %+v %v", r, err)
	}
	if !strings.Contains(r.Reason, "v=1 tool=Bash cwd=/w") || !strings.HasSuffix(r.Reason, "last-arg=decide") {
		t.Errorf("stdin or argv wrong: %q", r.Reason)
	}
	if r, err = Run(context.Background(), fake(t, "block-no-attr"), 5*time.Second, "Bash", nil, ""); err != nil || r.Rule != "" || r.Verdict != Block {
		t.Errorf("no attribution: %+v %v", r, err)
	}
	if r, err = Run(context.Background(), fake(t, "delegate"), 5*time.Second, "Bash", input, "/w"); err != nil || r.Verdict != Delegate {
		t.Errorf("delegate: %+v %v", r, err)
	}
	if r, err = Run(context.Background(), fake(t, "coverage"), 5*time.Second, "Bash", input, "/w"); err != nil || r.Coverage != "partial" {
		t.Errorf("coverage: %+v %v", r, err)
	}
	if r, err = Run(context.Background(), fake(t, "coverage-object"), 5*time.Second, "Bash", input, "/w"); err != nil || r.Coverage != "" || r.Verdict != Delegate {
		t.Errorf("non-string coverage must not break nah: %+v %v", r, err)
	}
	for _, mode := range []string{"fail", "badargs", "garbage", "wrong-schema", "mismatch"} {
		if _, err := Run(context.Background(), fake(t, mode), 5*time.Second, "Bash", input, "/w"); err == nil {
			t.Errorf("%s: want error", mode)
		}
	}
}

func TestRunTimeoutAndMissing(t *testing.T) {
	start := time.Now()
	_, err := Run(context.Background(), fake(t, "slow"), 300*time.Millisecond, "Bash", nil, "")
	if err == nil || time.Since(start) > 10*time.Second {
		t.Errorf("timeout: %v after %v", err, time.Since(start))
	}
	if _, err := Run(context.Background(), []string{"/definitely/not/nah"}, time.Second, "Bash", nil, ""); err == nil {
		t.Error("missing binary must fail")
	}
	if _, err := Run(context.Background(), nil, time.Second, "Bash", nil, ""); err == nil {
		t.Error("empty argv must fail")
	}
}
