package ai

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

const (
	defaultCacheTTL = 10 * time.Minute
	maxCacheEntries = 256
)

// CachedProvider remembers successful answers for a short time, so a
// repeated click on "analyze" for the same event costs one upstream call
// instead of many. Errors are never cached.
type CachedProvider struct {
	Inner Provider
	TTL   time.Duration
	// Now defaults to time.Now; overridable for tests.
	Now func() time.Time

	mu      sync.Mutex
	entries map[[32]byte]cacheEntry
}

type cacheEntry struct {
	at   time.Time
	text string
}

func (c *CachedProvider) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *CachedProvider) Analyze(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	ttl := c.TTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	key := sha256.Sum256([]byte(systemPrompt + "\x00" + userPrompt))
	now := c.now()

	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Sub(e.at) < ttl {
		c.mu.Unlock()
		return e.text, nil
	}
	c.mu.Unlock()

	text, err := c.Inner.Analyze(ctx, systemPrompt, userPrompt)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[[32]byte]cacheEntry{}
	}
	if len(c.entries) >= maxCacheEntries {
		for k, e := range c.entries {
			if now.Sub(e.at) >= ttl {
				delete(c.entries, k)
			}
		}
		for k := range c.entries { // still full: drop one arbitrary entry
			if len(c.entries) < maxCacheEntries {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[key] = cacheEntry{at: now, text: text}
	return text, nil
}
