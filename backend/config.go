package backend

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lhns/callguard/policy"
)

// FromConfig builds the backend described by cfg. It does not read
// credentials: a missing API key is reported by Classify.
func FromConfig(cfg policy.Backend) (Backend, error) {
	if strings.HasSuffix(cfg.Model, "-latest") {
		return nil, fmt.Errorf("backend model %q: use an exact model id, not a -latest alias", cfg.Model)
	}
	switch cfg.Type {
	case "anthropic":
		return newAnthropic(cfg), nil
	case "openai":
		return newOpenAI(cfg)
	case "exec":
		return newExec(cfg)
	case "fake":
		return newFake(cfg)
	case "":
		return nil, errors.New("backend type is empty")
	default:
		return nil, fmt.Errorf("unknown backend type %q", cfg.Type)
	}
}

const (
	defaultMaxTokens = 1024
	maxErrBody       = 200
	maxResponseBytes = 1 << 20
)

func maxTokens(cfg policy.Backend) int {
	if cfg.MaxTokens > 0 {
		return cfg.MaxTokens
	}
	return defaultMaxTokens
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
