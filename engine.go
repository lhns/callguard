package callguard

import (
	"context"
	"time"

	"github.com/lhns/callguard/backend"
	"github.com/lhns/callguard/policy"
)

// Options tune an Engine. Zero values mean the policy's settings.
type Options struct {
	// Backend, when set, replaces the policy's configured LLM backend
	// (used by eval and tests).
	Backend backend.Backend
	// LogPath overrides the policy's decision log path; "-" disables logging.
	LogPath string
	// NahPath overrides policy.Nah.Path (tests point it at a fake binary).
	NahPath string
	// Now is the clock; defaults to time.Now.
	Now func() time.Time
	// Warnings from policy loading, copied into every verdict.
	Warnings []string
}

// LoadOptions select the policy layers for Load.
type LoadOptions struct {
	// SystemPolicy is the system layer file; "" means the platform default
	// (/etc/callguard/policy.json, %ProgramData%\callguard\policy.json).
	// A missing default file is not an error; a missing explicit file is.
	SystemPolicy string
	// ProjectDir selects <ProjectDir>/.callguard/policy.json; "" skips it.
	ProjectDir string
	// UserConfigDir overrides os.UserConfigDir() (tests); "-" skips the user layer.
	UserConfigDir string
	Options
}

// Engine decides tool calls against one merged policy. It is safe for
// concurrent use.
type Engine struct {
	pol  policy.Policy
	rev  string
	opts Options
	impl engineImpl
}

// Policy returns the merged policy the engine uses.
func (e *Engine) Policy() policy.Policy { return e.pol }

// PolicyRev returns "sha256:<hex>" of the merged policy.
func (e *Engine) PolicyRev() string { return e.rev }

// Decide returns the verdict for req. It never returns an error: every
// failure becomes a fallback verdict (ask, or deny when unattended), and it
// returns before the policy deadline.
func (e *Engine) Decide(ctx context.Context, req *Request) Verdict {
	return e.decide(ctx, req)
}
