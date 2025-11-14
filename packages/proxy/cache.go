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
	entries           map[string]*CacheEntry                                          // main store: cacheKey -> cache entry (request + response)
	tokenIndex        map[string]map[string]IndexEntry                                // secondary index: token -> map[cacheKey]IndexEntry, used for token invalidation
	compoundPathIndex map[string]map[string]map[string]map[string]map[string]struct{} // token -> projectID -> envSlug -> secretPath -> cacheKey -> struct{}, used for evictions after mutation calls
	mu                sync.RWMutex                                                    // for thread-safe access
}

func NewCache() *Cache {
	return &Cache{
		entries:           make(map[string]*CacheEntry),
		tokenIndex:        make(map[string]map[string]IndexEntry),
		compoundPathIndex: make(map[string]map[string]map[string]map[string]map[string]struct{}),
	}
}

func IsSecretsEndpoint(path string) bool {
	return (strings.HasPrefix(path, "/api/v3/secrets/") || strings.HasPrefix(path, "/api/v4/secrets/")) ||
		path == "/api/v3/secrets" || path == "/api/v4/secrets"
}

func IsCacheableRequest(path string, method string) bool {
	if method != http.MethodGet {
		return false
	}

	return IsSecretsEndpoint(path)
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

	// Update compound path index
	if c.compoundPathIndex[token] == nil {
		c.compoundPathIndex[token] = make(map[string]map[string]map[string]map[string]struct{})
	}
	if c.compoundPathIndex[token][indexEntry.ProjectId] == nil {
		c.compoundPathIndex[token][indexEntry.ProjectId] = make(map[string]map[string]map[string]struct{})
	}
	if c.compoundPathIndex[token][indexEntry.ProjectId][indexEntry.EnvironmentSlug] == nil {
		c.compoundPathIndex[token][indexEntry.ProjectId][indexEntry.EnvironmentSlug] = make(map[string]map[string]struct{})
	}
	if c.compoundPathIndex[token][indexEntry.ProjectId][indexEntry.EnvironmentSlug][indexEntry.SecretPath] == nil {
		c.compoundPathIndex[token][indexEntry.ProjectId][indexEntry.EnvironmentSlug][indexEntry.SecretPath] = make(map[string]struct{})
	}
	c.compoundPathIndex[token][indexEntry.ProjectId][indexEntry.EnvironmentSlug][indexEntry.SecretPath][cacheKey] = struct{}{}
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

func matchesPath(storedPath, queryPath string) bool {
	if strings.HasSuffix(storedPath, "/*") {
		base := strings.TrimSuffix(storedPath, "/*")

		if queryPath == base {
			return true
		}

		// Check if queryPath is under base (e.g., base="/test", queryPath="/test/sub")
		return strings.HasPrefix(queryPath+"/", base+"/")
	}

	if storedPath == queryPath {
		return true
	}

	return false
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

	// Remove from token index and get IndexEntry for compound index cleanup
	var indexEntry IndexEntry
	if token != "" {
		if tokenEntries, ok := c.tokenIndex[token]; ok {
			indexEntry = tokenEntries[cacheKey]
			delete(tokenEntries, cacheKey)
			if len(tokenEntries) == 0 {
				delete(c.tokenIndex, token)
			}
		}
	}

	// Remove from compound path index
	if token == "" || indexEntry.ProjectId == "" || indexEntry.EnvironmentSlug == "" || indexEntry.SecretPath == "" {
		return
	}

	projectMap := c.compoundPathIndex[token]
	if projectMap == nil {
		return
	}

	envMap := projectMap[indexEntry.ProjectId]
	if envMap == nil {
		// Orphaned project entry
		delete(projectMap, indexEntry.ProjectId)
		if len(projectMap) == 0 {
			delete(c.compoundPathIndex, token)
		}
		return
	}

	pathsMap := envMap[indexEntry.EnvironmentSlug]
	if pathsMap == nil {
		// Orphaned environment entry
		delete(envMap, indexEntry.EnvironmentSlug)
		if len(envMap) == 0 {
			delete(projectMap, indexEntry.ProjectId)
		}
		if len(projectMap) == 0 {
			delete(c.compoundPathIndex, token)
		}
		return
	}

	cacheKeys := pathsMap[indexEntry.SecretPath]
	if cacheKeys == nil {
		// Orphaned path entry
		delete(pathsMap, indexEntry.SecretPath)
		if len(pathsMap) == 0 {
			delete(envMap, indexEntry.EnvironmentSlug)
		}
		if len(envMap) == 0 {
			delete(projectMap, indexEntry.ProjectId)
		}
		if len(projectMap) == 0 {
			delete(c.compoundPathIndex, token)
		}
		return
	}

	delete(cacheKeys, cacheKey)

	// If no more cacheKeys for this path, remove the path entry
	if len(cacheKeys) == 0 {
		delete(pathsMap, indexEntry.SecretPath)
	}

	// Clean up empty nested maps
	if len(pathsMap) == 0 {
		delete(envMap, indexEntry.EnvironmentSlug)
	}
	if len(envMap) == 0 {
		delete(projectMap, indexEntry.ProjectId)
	}
	if len(projectMap) == 0 {
		delete(c.compoundPathIndex, token)
	}
}

func (c *Cache) GetAllTokens() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tokens := make([]string, 0, len(c.tokenIndex))
	for token := range c.tokenIndex {
		tokens = append(tokens, token)
	}
	return tokens
}

// GetFirstRequestForToken gets the first request (any, regardless of expiration) for a token
func (c *Cache) GetFirstRequestForToken(token string) (cacheKey string, request *CachedRequest, found bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tokenEntries, exists := c.tokenIndex[token]
	if !exists || len(tokenEntries) == 0 {
		return "", nil, false
	}

	// Get the first cacheKey from the token's entries
	for key := range tokenEntries {
		entry, exists := c.entries[key]
		if !exists {
			// Delete orphan cache entry
			delete(tokenEntries, key)
			continue
		}

		requestCopy := &CachedRequest{
			Method:     entry.Request.Method,
			RequestURI: entry.Request.RequestURI,
			Headers:    make(http.Header),
			CachedAt:   entry.Request.CachedAt,
		}

		CopyHeaders(requestCopy.Headers, entry.Request.Headers)

		return key, requestCopy, true
	}

	return "", nil, false
}

func (c *Cache) EvictAllEntriesForToken(token string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	tokenEntries, exists := c.tokenIndex[token]
	if !exists {
		return 0
	}

	evictedCount := len(tokenEntries)

	// Delete all entries from main store
	for cacheKey := range tokenEntries {
		delete(c.entries, cacheKey)
	}

	// Delete token from token index
	delete(c.tokenIndex, token)

	return evictedCount
}

func (c *Cache) RemoveTokenFromIndex(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.tokenIndex, token)
}

// PurgeByMutation purges cache entries across ALL tokens that match the mutation path
func (c *Cache) PurgeByMutation(projectID, envSlug, mutationPath string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	purgedCount := 0

	// Iterate through all tokens in the compound index
	for token, projectMap := range c.compoundPathIndex {
		envMap, ok := projectMap[projectID]
		if !ok {
			continue
		}

		pathsMap, ok := envMap[envSlug]
		if !ok {
			continue
		}

		// Iterate through all paths and check matches
		for storedPath, cacheKeys := range pathsMap {
			if matchesPath(storedPath, mutationPath) {
				for cacheKey := range cacheKeys {
					// Remove from main store
					delete(c.entries, cacheKey)

					// Remove from token index
					if tokenEntries, ok := c.tokenIndex[token]; ok {
						delete(tokenEntries, cacheKey)
						if len(tokenEntries) == 0 {
							delete(c.tokenIndex, token)
						}
					}

					purgedCount++
				}
				delete(pathsMap, storedPath)
			}
		}

		// Clean up empty nested maps for this token
		if len(pathsMap) == 0 {
			delete(envMap, envSlug)
		}
		if len(envMap) == 0 {
			delete(projectMap, projectID)
		}
		if len(projectMap) == 0 {
			delete(c.compoundPathIndex, token)
		}
	}

	return purgedCount
}

// CompoundPathIndexDebugInfo represents the compound path index structure
type CompoundPathIndexDebugInfo struct {
	Token      string                      `json:"token"`
	Projects   map[string]ProjectDebugInfo `json:"projects"`
	TotalPaths int                         `json:"totalPaths"`
	TotalKeys  int                         `json:"totalKeys"`
}

// ProjectDebugInfo represents project-level debug info
type ProjectDebugInfo struct {
	ProjectID    string                          `json:"projectId"`
	Environments map[string]EnvironmentDebugInfo `json:"environments"`
	TotalPaths   int                             `json:"totalPaths"`
	TotalKeys    int                             `json:"totalKeys"`
}

// EnvironmentDebugInfo represents environment-level debug info
type EnvironmentDebugInfo struct {
	EnvironmentSlug string                   `json:"environmentSlug"`
	Paths           map[string]PathDebugInfo `json:"paths"`
	TotalKeys       int                      `json:"totalKeys"`
}

// CacheKeyDebugInfo represents a cache key with its timestamp
type CacheKeyDebugInfo struct {
	CacheKey string    `json:"cacheKey"`
	CachedAt time.Time `json:"cachedAt"`
}

// PathDebugInfo represents path-level debug info
type PathDebugInfo struct {
	SecretPath string              `json:"secretPath"`
	CacheKeys  []CacheKeyDebugInfo `json:"cacheKeys"`
	KeyCount   int                 `json:"keyCount"`
}

// CacheDebugInfo contains debug information about the cache
type CacheDebugInfo struct {
	TotalEntries      int                          `json:"totalEntries"`
	TotalTokens       int                          `json:"totalTokens"`
	TotalSizeBytes    int64                        `json:"totalSizeBytes"`
	EntriesByToken    map[string]int               `json:"entriesByToken"`
	CacheKeys         []CacheKeyDebugInfo          `json:"cacheKeys"`
	TokenIndex        map[string][]IndexEntry      `json:"tokenIndex"`
	CompoundPathIndex []CompoundPathIndexDebugInfo `json:"compoundPathIndex"`
}

// GetDebugInfo returns debug information about the cache (dev mode only)
func (c *Cache) GetDebugInfo() CacheDebugInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var totalSize int64
	entriesByToken := make(map[string]int)
	tokenIndex := make(map[string][]IndexEntry)
	cacheKeys := make([]CacheKeyDebugInfo, 0, len(c.entries))

	// Calculate sizes and build cache keys with timestamps
	for cacheKey, entry := range c.entries {
		cacheKeys = append(cacheKeys, CacheKeyDebugInfo{
			CacheKey: cacheKey,
			CachedAt: entry.Request.CachedAt,
		})
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

	// Build compound path index debug info
	compoundPathIndex := make([]CompoundPathIndexDebugInfo, 0, len(c.compoundPathIndex))
	for token, projectMap := range c.compoundPathIndex {
		projects := make(map[string]ProjectDebugInfo)
		totalPaths := 0
		totalKeys := 0

		for projectID, envMap := range projectMap {
			environments := make(map[string]EnvironmentDebugInfo)
			projectTotalPaths := 0
			projectTotalKeys := 0

			for envSlug, pathsMap := range envMap {
				paths := make(map[string]PathDebugInfo)
				envTotalKeys := 0

				for secretPath, cacheKeys := range pathsMap {
					keys := make([]CacheKeyDebugInfo, 0, len(cacheKeys))
					for cacheKey := range cacheKeys {

						if entry, exists := c.entries[cacheKey]; exists {
							keys = append(keys, CacheKeyDebugInfo{
								CacheKey: cacheKey,
								CachedAt: entry.Request.CachedAt,
							})
						}
					}
					paths[secretPath] = PathDebugInfo{
						SecretPath: secretPath,
						CacheKeys:  keys,
						KeyCount:   len(cacheKeys),
					}
					envTotalKeys += len(cacheKeys)
					projectTotalPaths++
				}

				environments[envSlug] = EnvironmentDebugInfo{
					EnvironmentSlug: envSlug,
					Paths:           paths,
					TotalKeys:       envTotalKeys,
				}
				projectTotalKeys += envTotalKeys
			}

			projects[projectID] = ProjectDebugInfo{
				ProjectID:    projectID,
				Environments: environments,
				TotalPaths:   projectTotalPaths,
				TotalKeys:    projectTotalKeys,
			}
			totalPaths += projectTotalPaths
			totalKeys += projectTotalKeys
		}

		compoundPathIndex = append(compoundPathIndex, CompoundPathIndexDebugInfo{
			Token:      token,
			Projects:   projects,
			TotalPaths: totalPaths,
			TotalKeys:  totalKeys,
		})
	}

	return CacheDebugInfo{
		TotalEntries:      len(c.entries),
		TotalTokens:       len(c.tokenIndex),
		TotalSizeBytes:    totalSize,
		EntriesByToken:    entriesByToken,
		CacheKeys:         cacheKeys,
		TokenIndex:        tokenIndex,
		CompoundPathIndex: compoundPathIndex,
	}
}
