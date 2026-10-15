package ai

// FromEnv picks the AI provider configured through environment variables, or
// nil when none is set (callers then fall back to the offline MockProvider).
// Gemini is preferred over Anthropic when both keys exist. The result is
// wrapped in a response cache.
//
//	KONSOLGW_GEMINI_API_KEY / KONSOLGW_GEMINI_MODEL
//	KONSOLGW_ANTHROPIC_API_KEY / KONSOLGW_ANTHROPIC_MODEL
func FromEnv(getenv func(string) string) Provider {
	if key := getenv("KONSOLGW_GEMINI_API_KEY"); key != "" {
		return &CachedProvider{Inner: &GeminiProvider{APIKey: key, Model: getenv("KONSOLGW_GEMINI_MODEL")}}
	}
	if key := getenv("KONSOLGW_ANTHROPIC_API_KEY"); key != "" {
		return &CachedProvider{Inner: &AnthropicProvider{APIKey: key, Model: getenv("KONSOLGW_ANTHROPIC_MODEL")}}
	}
	return nil
}
