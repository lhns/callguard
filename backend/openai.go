package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/lhns/callguard/policy"
)

type openAI struct {
	model     string
	baseURL   string
	keyEnv    string
	maxTokens int
	classes   []string
	client    *http.Client
}

func newOpenAI(cfg policy.Backend) (*openAI, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("openai backend needs base_url (e.g. http://127.0.0.1:8080/v1)")
	}
	return &openAI{
		model:     cfg.Model,
		baseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		keyEnv:    cfg.APIKeyEnv,
		maxTokens: maxTokens(cfg),
		classes:   cfg.DataClasses,
		client:    &http.Client{},
	}, nil
}

func (o *openAI) Name() string          { return "openai:" + o.model }
func (o *openAI) DataClasses() []string { return o.classes }

func (o *openAI) Classify(ctx context.Context, req ClassifyRequest) (ClassifyResult, error) {
	body := map[string]any{
		"model": o.model,
		"messages": []map[string]string{
			{"role": "system", "content": req.System},
			{"role": "user", "content": req.Prompt},
		},
		"max_tokens": o.maxTokens,
		"response_format": map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name": "callguard_verdict", "strict": true, "schema": json.RawMessage(req.Schema),
			},
		},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return ClassifyResult{}, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return ClassifyResult{}, err
	}
	hreq.Header.Set("content-type", "application/json")
	if o.keyEnv != "" {
		if k := os.Getenv(o.keyEnv); k != "" {
			hreq.Header.Set("Authorization", "Bearer "+k)
		}
	}
	raw, err := doJSON(o.client, hreq, "openai")
	if err != nil {
		return ClassifyResult{}, err
	}
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return ClassifyResult{}, fmt.Errorf("openai: bad response: %w", err)
	}
	if len(resp.Choices) == 0 {
		return ClassifyResult{}, errors.New("openai: no choices in response")
	}
	res, err := parseVerdictJSON(resp.Choices[0].Message.Content)
	if err != nil {
		return ClassifyResult{}, fmt.Errorf("openai: %w", err)
	}
	res.InputTokens, res.OutputTokens = resp.Usage.PromptTokens, resp.Usage.CompletionTokens
	return res, nil
}
