package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type IndexEntry struct {
	CacheKey        string
	SecretPath      string
	EnvironmentSlug string
	ProjectId       string
}

type CachedRequest struct {
	Method     string
	RequestURI string
	Headers    http.Header
	CachedAt   time.Time
}

type CachedResponse struct {
	StatusCode int
	Header     http.Header
	BodyBytes  []byte
}

type CacheEntry struct {
	Request  *CachedRequest
	Response *CachedResponse
}

// Cache is an in-memory cache for HTTP responses
type Cache struct {
	entries    map[string]*CacheEntry           // main store: cacheKey -> cache entry (request + response)
	tokenIndex map[string]map[string]IndexEntry // secondary index: token -> map[cacheKey]IndexEntry, used for token invalidation
	mu         sync.RWMutex                     // for thread-safe access
}

func NewCache() *Cache {
	return &Cache{
		entries:    make(map[string]*CacheEntry),
		tokenIndex: make(map[string]map[string]IndexEntry),
	}
}

// Only GET requests to /v3/secrets/* and /v4/secrets/* routes are cacheable
func IsCacheableRequest(path string, method string) bool {
	if method != http.MethodGet {
		return false
	}

	return (strings.HasPrefix(path, "/api/v3/secrets/") || strings.HasPrefix(path, "/api/v4/secrets/")) ||
		path == "/api/v3/secrets" || path == "/api/v4/secrets"
}

func (c *Cache) Get(cacheKey string) (*http.Response, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[cacheKey]
	if !exists {
		return nil, false
	}

	resp := &http.Response{
		StatusCode: entry.Response.StatusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(entry.Response.BodyBytes)),
	}

	CopyHeaders(resp.Header, entry.Response.Header)

	return resp, true
}

func (c *Cache) Set(cacheKey string, req *http.Request, resp *http.Response, token string, indexEntry IndexEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// We can't use the response body directly because it will be closed by the time we need to use it
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
	}

	// Extract request metadata
	requestURI := req.URL.RequestURI()
	requestHeaders := make(http.Header)
	CopyHeaders(requestHeaders, req.Header)

	// Extract response data
	responseHeader := make(http.Header)
	CopyHeaders(responseHeader, resp.Header)

	entry := &CacheEntry{
		Request: &CachedRequest{
			Method:     req.Method,
			RequestURI: requestURI,
			Headers:    requestHeaders,
			CachedAt:   time.Now(),
		},
		Response: &CachedResponse{
			StatusCode: resp.StatusCode,
			Header:     responseHeader,
			BodyBytes:  bodyBytes,
		},
	}

	c.entries[cacheKey] = entry

	// Update secondary index for token
	if c.tokenIndex[token] == nil {
		c.tokenIndex[token] = make(map[string]IndexEntry)
	}
	c.tokenIndex[token][cacheKey] = indexEntry
}

// UpdateResponse updates only the response data and cachedAt timestamp for an existing cache entry
// This is used during resync when the request parameters (and thus IndexEntry) haven't changed
func (c *Cache) UpdateResponse(cacheKey string, statusCode int, header http.Header, bodyBytes []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[cacheKey]
	if !exists {
		return
	}

	// Deep copy response header
	responseHeader := make(http.Header)
	CopyHeaders(responseHeader, header)

	// Deep copy bodyBytes
	bodyBytesCopy := make([]byte, len(bodyBytes))
	copy(bodyBytesCopy, bodyBytes)

	entry.Response.StatusCode = statusCode
	entry.Response.Header = responseHeader
	entry.Response.BodyBytes = bodyBytesCopy
	entry.Request.CachedAt = time.Now()
}

func CopyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func ExtractTokenFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// Parse "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// GenerateCacheKey generates a cache key for a request by hashing the method, path, query, and token
func GenerateCacheKey(method, path, query, token string) string {
	data := method + path + query + token
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// GetExpiredRequests returns only expired request data for resync
func (c *Cache) GetExpiredRequests(cacheTTL time.Duration) map[string]*CachedRequest {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	requests := make(map[string]*CachedRequest, 0)

	for key, entry := range c.entries {
		// Only include entries where cache-ttl has expired
		age := now.Sub(entry.Request.CachedAt)
		if age <= cacheTTL {
			continue
		}

		// Create a deep copy of request data only
		requestCopy := &CachedRequest{
			Method:     entry.Request.Method,
			RequestURI: entry.Request.RequestURI,
			Headers:    make(http.Header),
			CachedAt:   entry.Request.CachedAt,
		}

		CopyHeaders(requestCopy.Headers, entry.Request.Headers)

		requests[key] = requestCopy
	}

	return requests
}

func (c *Cache) EvictEntry(cacheKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[cacheKey]
	if !exists {
		return
	}

	token := ExtractTokenFromRequest(&http.Request{Header: entry.Request.Headers})

	// Remove from main store
	delete(c.entries, cacheKey)

	// Remove from token index
	if token != "" {
		if tokenEntries, ok := c.tokenIndex[token]; ok {
			delete(tokenEntries, cacheKey)
			if len(tokenEntries) == 0 {
				delete(c.tokenIndex, token)
			}
		}
	}
}

// CacheDebugInfo contains debug information about the cache
type CacheDebugInfo struct {
	TotalEntries   int                     `json:"totalEntries"`
	TotalTokens    int                     `json:"totalTokens"`
	TotalSizeBytes int64                   `json:"totalSizeBytes"`
	EntriesByToken map[string]int          `json:"entriesByToken"`
	CacheKeys      []string                `json:"cacheKeys"`
	TokenIndex     map[string][]IndexEntry `json:"tokenIndex"`
}

// GetDebugInfo returns debug information about the cache (dev mode only)
func (c *Cache) GetDebugInfo() CacheDebugInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var totalSize int64
	entriesByToken := make(map[string]int)
	tokenIndex := make(map[string][]IndexEntry)
	cacheKeys := make([]string, 0, len(c.entries))

	// Calculate sizes
	for cacheKey, entry := range c.entries {
		cacheKeys = append(cacheKeys, cacheKey)
		totalSize += int64(len(entry.Response.BodyBytes))
	}

	// Build token index and count entries per token
	for token, entries := range c.tokenIndex {
		entriesByToken[token] = len(entries)
		tokenIndex[token] = make([]IndexEntry, 0, len(entries))
		for _, entry := range entries {
			tokenIndex[token] = append(tokenIndex[token], entry)
		}
	}

	return CacheDebugInfo{
		TotalEntries:   len(c.entries),
		TotalTokens:    len(c.tokenIndex),
		TotalSizeBytes: totalSize,
		EntriesByToken: entriesByToken,
		CacheKeys:      cacheKeys,
		TokenIndex:     tokenIndex,
	}
}
