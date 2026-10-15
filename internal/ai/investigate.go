package ai

import (
	"context"
	"regexp"
	"strings"
)

var passwordRegex = regexp.MustCompile(`(?i)(password|passwd|secret|token|bearer)=[^& \n\r]+`)

// RedactSensitive removes passwords, tokens, and secret parameters from raw text.
func RedactSensitive(input string) string {
	return passwordRegex.ReplaceAllString(input, "$1=[REDACTED]")
}

// InvestigateData sends redacted context to AI Provider and returns structured analysis.
func InvestigateData(ctx context.Context, p Provider, subjectType, subjectData string) (string, error) {
	if p == nil {
		p = &MockProvider{}
	}

	cleanData := RedactSensitive(subjectData)

	sysPrompt := "Anda adalah asisten AI SRE & Keamanan Jaringan Konsol Gateway (HAProxy). Analisis data berikut dan kembalikan analisis dalam format JSON dengan kunci: observed, analysis, recommendation, risk."
	userPrompt := "Subjek: " + subjectType + "\nData: " + cleanData

	raw, err := p.Analyze(ctx, sysPrompt, userPrompt)
	if err != nil {
		// Fallback to mock analysis if external AI fails
		mock := &MockProvider{}
		return mock.Analyze(ctx, sysPrompt, userPrompt)
	}
	return strings.TrimSpace(raw), nil
}
