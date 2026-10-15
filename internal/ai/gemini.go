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

const defaultGeminiModel = "gemini-2.0-flash"

// GeminiProvider implements Provider using the Google Gemini generateContent
// API. The key travels in the x-goog-api-key header, never in the URL, so it
// cannot leak into proxy or access logs.
type GeminiProvider struct {
	APIKey string
	Model  string
	Client *http.Client
	// BaseURL overrides the API origin; tests point it at an httptest server.
	BaseURL string
}

func (p *GeminiProvider) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if p.APIKey == "" {
		return "", fmt.Errorf("API key Gemini belum dikonfigurasi")
	}
	model := p.Model
	if model == "" {
		model = defaultGeminiModel
	}
	base := p.BaseURL
	if base == "" {
		base = "https://generativelanguage.googleapis.com"
	}

	payload := map[string]any{
		"systemInstruction": map[string]any{"parts": []map[string]string{{"text": systemPrompt}}},
		"contents":          []map[string]any{{"role": "user", "parts": []map[string]string{{"text": userPrompt}}}},
		"generationConfig": map[string]any{
			"temperature":      0.1,
			"maxOutputTokens":  1024,
			"responseMimeType": "application/json",
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1beta/models/"+model+":generateContent", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-goog-api-key", p.APIKey)
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
		return "", fmt.Errorf("gemini api returned status %d", resp.StatusCode)
	}

	var res struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if len(res.Candidates) == 0 || len(res.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("empty response content")
	}
	return res.Candidates[0].Content.Parts[0].Text, nil
}

// ExtractJSON returns the outermost {...} object in a model reply, which
// drops the ```json fences and chatter models sometimes wrap around it. If
// no object is present the trimmed text is returned unchanged.
func ExtractJSON(text string) string {
	text = strings.TrimSpace(text)
	i, j := strings.IndexByte(text, '{'), strings.LastIndexByte(text, '}')
	if i < 0 || j <= i {
		return text
	}
	return text[i : j+1]
}
