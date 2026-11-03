package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/lhns/callguard/policy"
)

const (
	anthropicVersion      = "2026-10-21"
	anthropicDefaultModel = "claude-haiku-5-5"
	anthropicDefaultURL   = "https://api.anthropic.com"
)

type anthropic struct {
	model     string
	baseURL   string
	keyEnv    string
	maxTokens int
	classes   []string
	client    *http.Client
}

func newAnthropic(cfg policy.Backend) *anthropic {
	a := &anthropic{
		model:     cfg.Model,
		baseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		keyEnv:    cfg.APIKeyEnv,
		maxTokens: maxTokens(cfg),
		classes:   cfg.DataClasses,
		client:    &http.Client{},
	}
	if a.model == "" {
		a.model = anthropicDefaultModel
	}
	if a.baseURL == "" {
		a.baseURL = anthropicDefaultURL
	}
	if a.keyEnv == "" {
		a.keyEnv = "ANTHROPIC_API_KEY"
	}
	return a
}

func (a *anthropic) Name() string          { return "anthropic:" + a.model }
func (a *anthropic) DataClasses() []string { return a.classes }

func (a *anthropic) Classify(ctx context.Context, req ClassifyRequest) (ClassifyResult, error) {
	key := os.Getenv(a.keyEnv)
	if key == "" {
		return ClassifyResult{}, fmt.Errorf("anthropic: environment variable %s is not set", a.keyEnv)
	}
	outCfg := map[string]any{
		"format": map[string]any{"type": "json_schema", "schema": json.RawMessage(req.Schema)},
	}
	body := map[string]any{
		"model":      a.model,
		"max_tokens": a.maxTokens,
		"system": []map[string]any{{
			"type": "text", "text": req.System,
			"cache_control": map[string]string{"type": "ephemeral"},
		}},
		"messages":      []map[string]string{{"role": "user", "content": req.Prompt}},
		"output_config": outCfg,
	}
	// Haiku 5.5 takes disabled thinking and effort "low". Sonnet 5.5 and Opus
	// 5.5 reject disabled thinking, and Haiku 4.5 rejects effort, so other
	// models get neither and run with their defaults. No sampling parameters
	// (temperature, top_p, top_k): this API version answers 400.
	if strings.HasPrefix(a.model, "claude-haiku-5") {
		body["thinking"] = map[string]string{"type": "disabled"}
		outCfg["effort"] = "low"
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return ClassifyResult{}, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/v1/messages", bytes.NewReader(buf))
	if err != nil {
		return ClassifyResult{}, err
	}
	hreq.Header.Set("x-api-key", key)
	hreq.Header.Set("anthropic-version", anthropicVersion)
	hreq.Header.Set("content-type", "application/json")
	raw, err := doJSON(a.client, hreq, "anthropic")
	if err != nil {
		return ClassifyResult{}, err
	}
	var resp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
			CacheRead    int `json:"cache_read_input_tokens"`
			CacheWrite   int `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return ClassifyResult{}, fmt.Errorf("anthropic: bad response: %w", err)
	}
	if resp.StopReason == "refusal" || resp.StopReason == "max_tokens" {
		return ClassifyResult{}, fmt.Errorf("anthropic: stop_reason %s", resp.StopReason)
	}
	for _, c := range resp.Content {
		if c.Type != "text" {
			continue
		}
		res, err := parseVerdictJSON(c.Text)
		if err != nil {
			return ClassifyResult{}, fmt.Errorf("anthropic: %w", err)
		}
		res.InputTokens, res.OutputTokens = resp.Usage.InputTokens, resp.Usage.OutputTokens
		res.CacheReadTokens, res.CacheWriteTokens = resp.Usage.CacheRead, resp.Usage.CacheWrite
		return res, nil
	}
	return ClassifyResult{}, errors.New("anthropic: no text block in response")
}

// doJSON sends hreq and returns the body of a 2xx response.
func doJSON(c *http.Client, hreq *http.Request, who string) ([]byte, error) {
	resp, err := c.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", who, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: reading response: %w", who, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s: HTTP %d: %s", who, resp.StatusCode, clip(string(raw), maxErrBody))
	}
	return raw, nil
}

// parseVerdictJSON decodes the model's {decision, confidence, rule, reason}
// text, tolerating a surrounding code fence.
func parseVerdictJSON(text string) (ClassifyResult, error) {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "```") {
		text = strings.TrimPrefix(text, "```")
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			text = text[i+1:]
		}
		text = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(text), "```"))
	}
	var v struct {
		Decision   string  `json:"decision"`
		Confidence float64 `json:"confidence"`
		Rule       string  `json:"rule"`
		Reason     string  `json:"reason"`
	}
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return ClassifyResult{}, fmt.Errorf("model output is not the expected JSON: %w", err)
	}
	return ClassifyResult{Label: v.Decision, Confidence: v.Confidence, Rule: v.Rule, Reason: v.Reason}, nil
}
