package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Provider abstracts an AI LLM provider (e.g. Anthropic or OpenAI).
type Provider interface {
	Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

// AnthropicProvider implements Provider using Anthropic Messages API.
type AnthropicProvider struct {
	APIKey string
	Model  string
	Client *http.Client
}

func (p *AnthropicProvider) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if p.APIKey == "" {
		return "", fmt.Errorf("API Key Anthropic belum dikonfigurasi")
	}
	model := p.Model
	if model == "" {
		model = "claude-3-5-sonnet-20241022"
	}

	payload := map[string]any{
		"model":       model,
		"max_tokens":  1500,
		"system":      systemPrompt,
		"messages":    []map[string]string{{"role": "user", "content": userPrompt}},
		"temperature": 0.2,
	}

	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", p.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	hc := p.Client
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic api returned status %d", resp.StatusCode)
	}

	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if len(res.Content) == 0 {
		return "", fmt.Errorf("empty response content")
	}
	return res.Content[0].Text, nil
}

// MockProvider is a fallback provider for testing or offline mode.
type MockProvider struct{}

func (m *MockProvider) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	var sb strings.Builder
	sb.WriteString("{\n")
	sb.WriteString(`  "observed": "Terdeteksi aktivitas anomali pada subjek log yang sedang dianalisis.",` + "\n")
	sb.WriteString(`  "analysis": "Pola permintaan menunjukkan rasio kegagalan tinggi atau lonjakan beban melebihi ambang batas yang ditentukan.",` + "\n")
	sb.WriteString(`  "recommendation": "Pertimbangkan untuk memblokir IP sementara (TTL 1 jam) atau menyesuaikan rate-limit pada backend terkait.",` + "\n")
	sb.WriteString(`  "risk": "HIGH"` + "\n")
	sb.WriteString("}")
	return sb.String(), nil
}
