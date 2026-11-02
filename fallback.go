package callguard

import (
	"os"
	"path/filepath"
)

// ResolveProjectDir returns req.ProjectDir if set, else the nearest
// directory at or above req.Cwd that contains .git, else req.Cwd.
func ResolveProjectDir(req *Request) string {
	if req == nil {
		return ""
	}
	if req.ProjectDir != "" {
		return req.ProjectDir
	}
	if req.Cwd == "" {
		return ""
	}
	for dir := req.Cwd; ; {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return req.Cwd
		}
		dir = parent
	}
}

// FallbackVerdict is the verdict for a call callguard could not evaluate
// (bad request, policy load error, internal error): ask, or deny when
// req.Unattended, enforced, layer "fallback". cause goes into the reason.
// It is safe to call with a nil or partial req.
func FallbackVerdict(req *Request, cause string) Verdict {
	v := Verdict{
		Schema: VerdictSchema, V: 1, ID: newID(), Decision: Ask, Enforced: true, Layer: LayerFallback,
		Reason: "callguard could not evaluate this call: " + cause + ". A human should confirm it.",
	}
	if req != nil && req.Unattended {
		v.Decision = Deny
		v.Reason = "callguard could not evaluate this call: " + cause + ". A human must approve it; " +
			"ask the user to approve it or add a policy rule."
	}
	return v
}
