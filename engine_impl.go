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
