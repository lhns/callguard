package callguard

import (
	"context"
	"errors"

	"github.com/lhns/callguard/policy"
)

// STUB: worker A replaces this file.

type engineImpl struct{}

// New builds an engine from an already merged policy.
func New(pol policy.Policy, opts Options) (*Engine, error) {
	return nil, errors.New("not implemented")
}

// Load reads and merges the policy layers and builds an engine.
func Load(opts LoadOptions) (*Engine, error) {
	return nil, errors.New("not implemented")
}

func (e *Engine) decide(ctx context.Context, req *Request) Verdict {
	panic("not implemented")
}

// ResolveProjectDir returns req.ProjectDir if set, else the nearest
// directory at or above req.Cwd that contains .git, else req.Cwd.
func ResolveProjectDir(req *Request) string {
	panic("not implemented")
}

// FallbackVerdict is the verdict for a call callguard could not evaluate
// (bad request, policy load error, internal error): ask, or deny when
// req.Unattended, enforced, layer "fallback". cause goes into the reason.
// It is safe to call with a nil or partial req.
func FallbackVerdict(req *Request, cause string) Verdict {
	panic("not implemented")
}
