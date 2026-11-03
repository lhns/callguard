package callguard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/lhns/callguard/backend"
	"github.com/lhns/callguard/internal/declog"
	"github.com/lhns/callguard/internal/judge"
	"github.com/lhns/callguard/internal/rules"
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
	// ProtectPaths are extra files the self-protection rules guard, such as
	// an explicit --policy file. Load adds an explicit system policy
	// file and the user policy file.
	ProtectPaths []string
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

// judgeFunc is judge.Judge; tests replace it.
type judgeFunc func(ctx context.Context, b backend.Backend, cfg judge.Config, in judge.Input) (judge.Result, error)

type engineImpl struct {
	env     rules.Env
	builtin *rules.Builtin
	rules   *rules.Set
	logger  *declog.Logger // nil when logging is off
	nahArgv []string       // command prefix of nah; tests point it at a helper process
	judge   judgeFunc
}

// New builds an engine from an already merged policy. Unset settings take
// their defaults; rules are used as given (use policy.Default() for the
// default rules).
func New(pol policy.Policy, opts Options) (*Engine, error) {
	pol = policy.WithDefaults(pol)
	if problems := policy.Validate(pol, false); len(problems) > 0 {
		return nil, errors.New("invalid policy: " + strings.Join(problems, "; "))
	}
	env := rules.DefaultEnv()
	set, err := rules.Compile(pol.Rules, env)
	if err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	bi, err := rules.NewBuiltin(env, pol.DisableBuiltin, opts.ProtectPaths...)
	if err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	nahPath := pol.Nah.Path
	if opts.NahPath != "" {
		nahPath = opts.NahPath
	}
	e := &Engine{pol: pol, rev: policy.Rev(pol), opts: opts, impl: engineImpl{
		env: env, builtin: bi, rules: set, nahArgv: []string{nahPath}, judge: judge.Judge,
	}}
	if path := logPath(pol, opts); path != "" {
		e.impl.logger = declog.New(path)
	}
	return e, nil
}

func logPath(pol policy.Policy, opts Options) string {
	if opts.LogPath == "-" || (pol.Log != nil && pol.Log.Disabled) {
		return ""
	}
	if opts.LogPath != "" {
		return opts.LogPath
	}
	if pol.Log != nil && pol.Log.Path != "" {
		return pol.Log.Path
	}
	return declog.DefaultPath()
}

// Load reads and merges the policy layers and builds an engine.
func Load(opts LoadOptions) (*Engine, error) {
	l, err := policy.Load(policy.LoadOptions{
		SystemPolicy: opts.SystemPolicy, ProjectDir: opts.ProjectDir, UserConfigDir: opts.UserConfigDir,
	})
	if err != nil {
		return nil, err
	}
	if p := l.Problems(); len(p) > 0 {
		return nil, errors.New("invalid policy: " + strings.Join(p, "; "))
	}
	o := opts.Options
	o.Warnings = append(append([]string(nil), o.Warnings...), l.Warnings...)
	// The system default directory is protected by a built-in glob; an
	// explicit --policy file and the user layer file are protected here.
	o.ProtectPaths = append([]string(nil), o.ProtectPaths...)
	for _, p := range []string{opts.SystemPolicy, policy.UserPath(opts.UserConfigDir)} {
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			o.ProtectPaths = append(o.ProtectPaths, abs)
		}
	}
	return New(l.Policy, o)
}

// outcome is what the pipeline hands back before the common finishing steps.
type outcome struct {
	v             Verdict
	layerEnforced bool // the deciding layer's own mode is enforce
	inTok, outTok int
	escalated     bool // llm deny turned into ask by the deny streak
	warnings      []string
}

// Decide returns the verdict for req. It never returns an error: every
// failure becomes a fallback verdict (ask, or deny when unattended), and it
// returns before the policy deadline.
func (e *Engine) Decide(ctx context.Context, req *Request) (v Verdict) {
	defer func() {
		if r := recover(); r != nil { // last resort: finish itself panicked
			v = FallbackVerdict(req, fmt.Sprintf("internal error: %v", r))
		}
	}()
	start := e.opts.Now()
	if req == nil {
		req = &Request{}
	}
	deadline := time.Duration(e.pol.DeadlineMS) * time.Millisecond
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	ch := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- outcome{v: FallbackVerdict(req, fmt.Sprintf("internal error: %v", r)), layerEnforced: true}
			}
		}()
		ch <- e.pipeline(ctx, req)
	}()
	var out outcome
	select {
	case out = <-ch:
	case <-ctx.Done():
		cause := "deadline of " + deadline.String() + " exceeded"
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			cause = "request canceled"
		}
		out = outcome{v: FallbackVerdict(req, cause), layerEnforced: true}
	}
	return e.finish(req, out, start)
}

// finish applies shadow mode, the unattended rule, identity and logging.
func (e *Engine) finish(req *Request, out outcome, start time.Time) Verdict {
	v := out.v
	v.Schema, v.V = VerdictSchema, 1
	v.ID = newID()
	v.PolicyRev = e.rev
	v.Enforced = out.layerEnforced && e.pol.Mode != policy.ModeShadow && v.Layer != LayerNone
	v.Warnings = append(append([]string(nil), e.opts.Warnings...), out.warnings...)
	if v.Enforced && v.Decision == Ask && req.Unattended && e.pol.UnattendedAsk == "deny" {
		v.Decision = Deny
		v.Reason += " " + noHuman
	}
	v.LatencyMS = e.opts.Now().Sub(start).Milliseconds()
	if err := e.log(req, v, out); err != nil {
		v.Warnings = append(v.Warnings, "decision log: "+err.Error())
	}
	return v
}

const noHuman = "No human is available to approve this call; ask the user to approve it or add a policy rule."

func (e *Engine) log(req *Request, v Verdict, out outcome) error {
	if e.impl.logger == nil {
		return nil
	}
	sum := sha256.Sum256(req.Tool.Input)
	ent := declog.Entry{
		TS: e.opts.Now().UTC().Format(time.RFC3339Nano), ID: v.ID, SessionID: req.SessionID,
		Harness: req.Harness, Tool: req.Tool.Name, Kind: rules.KindOf(req.Tool.Name),
		InputSHA256: hex.EncodeToString(sum[:]), Decision: string(v.Decision), Enforced: v.Enforced,
		Layer: v.Layer, Rule: v.Rule, Confidence: v.Confidence, Backend: v.Backend,
		PolicyRev: v.PolicyRev, LatencyMS: v.LatencyMS, Unattended: req.Unattended,
		InputTokens: out.inTok, OutputTokens: out.outTok, Escalated: out.escalated,
	}
	includeInput := e.pol.Log != nil && e.pol.Log.IncludeInput
	if v.Layer != LayerLLM || includeInput {
		ent.Reason = v.Reason
	}
	if includeInput && json.Valid(req.Tool.Input) {
		ent.Input = req.Tool.Input
	}
	return e.impl.logger.Append(ent)
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms; Decide recovers
	}
	return hex.EncodeToString(b[:])
}
