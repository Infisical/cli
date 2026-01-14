package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/util/cache"
	"github.com/rs/zerolog/log"
)

// Storage key prefixes
const (
	prefixEntry = "entry:"
	prefixToken = "token:"
	prefixPath  = "path:"
)

type IndexEntry struct {
	CacheKey        string `json:"cacheKey"`
	SecretPath      string `json:"secretPath"`
	EnvironmentSlug string `json:"environmentSlug"`
	ProjectId       string `json:"projectId"`
}

type CachedRequest struct {
	Method     string      `json:"method"`
	RequestURI string      `json:"requestUri"`
	Headers    http.Header `json:"headers"`
	CachedAt   time.Time   `json:"cachedAt"`
}

type CachedResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	BodyBytes  []byte      `json:"bodyBytes"`
}

// StoredCacheEntry is the structure stored in EncryptedStorage
type StoredCacheEntry struct {
	Request  *CachedRequest  `json:"request"`
	Response *CachedResponse `json:"response"`
	Token    string          `json:"token"`
	Index    IndexEntry      `json:"index"`
}

// PathIndexMarker is a simple marker stored at path index keys
type PathIndexMarker struct {
	CacheKey string `json:"cacheKey"`
}

// Cache is an HTTP response cache fully backed by EncryptedStorage
type Cache struct {
	storage *cache.EncryptedStorage
	mu      sync.RWMutex
}

// NewCache creates a cache with the specified options
func NewCache(opts cache.EncryptedStorageOptions) (*Cache, error) {
	storage, err := cache.NewEncryptedStorage(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache storage: %w", err)
	}

	return &Cache{
		storage: storage,
	}, nil
}

// Close closes the underlying storage
func (c *Cache) Close() error {
	return c.storage.Close()
}

// hashToken creates a short hash of the token for use in storage keys
// This avoids storing the full token in key names while still being unique
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:8]) // First 8 bytes = 16 hex chars
}

// buildEntryKey builds the storage key for a cache entry
func buildEntryKey(cacheKey string) string {
	return prefixEntry + cacheKey
}

// buildTokenIndexKey builds the storage key for token index entry
func buildTokenIndexKey(token, cacheKey string) string {
	return prefixToken + hashToken(token) + ":" + cacheKey
}

// buildTokenIndexPrefix builds the prefix for all token index entries for a token
func buildTokenIndexPrefix(token string) string {
	return prefixToken + hashToken(token) + ":"
}

// buildPathIndexKey builds the storage key for path index entry
// Key format: path:{projectId}:{envSlug}:{tokenHash}:{escapedSecretPath}:{cacheKey}
func buildPathIndexKey(token string, indexEntry IndexEntry) string {
	// Escape colons in secretPath to avoid key parsing issues.
	// Currently not relevant as we don't support colons in secret paths, but if we decide to broaden our allowed folder naming in the future, this would be needed
	escapedPath := strings.ReplaceAll(indexEntry.SecretPath, ":", "\\:")
	key := fmt.Sprintf("%s%s:%s:%s:%s:%s",
		prefixPath,
		indexEntry.ProjectId,
		indexEntry.EnvironmentSlug,
		hashToken(token),
		escapedPath,
		indexEntry.CacheKey,
	)

	log.Debug().Str("pathIndexKey", key).Msg("Built path index key")

	return key
}

// buildPathIndexPrefixForProject builds the prefix for all path entries matching a project+env
func buildPathIndexPrefixForProject(projectId, envSlug string) string {
	return fmt.Sprintf("%s%s:%s:", prefixPath, projectId, envSlug)
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

	var entry StoredCacheEntry
	err := c.storage.Get(buildEntryKey(cacheKey), &entry)
	if err != nil {
		return nil, false
	}

	if entry.Response == nil {
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

	// Read response body
	var bodyBytes []byte
	if resp.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Err(err).Str("cacheKey", cacheKey).Msg("Failed to read response body")
			bodyBytes = nil
		}
	}

	// Extract request metadata
	requestURI := req.URL.RequestURI()
	requestHeaders := make(http.Header)
	CopyHeaders(requestHeaders, req.Header)

	// Extract response data
	responseHeader := make(http.Header)
	CopyHeaders(responseHeader, resp.Header)

	entry := StoredCacheEntry{
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
		Token: token,
		Index: indexEntry,
	}

	// Store main entry
	if err := c.storage.Set(buildEntryKey(cacheKey), entry); err != nil {
		log.Error().Err(err).Str("cacheKey", cacheKey).Msg("Failed to store cache entry")
		return
	}

	// Store token index entry
	tokenIndexKey := buildTokenIndexKey(token, cacheKey)
	if err := c.storage.Set(tokenIndexKey, indexEntry); err != nil {
		log.Error().Err(err).Str("cacheKey", cacheKey).Msg("Failed to store token index entry")
	}

	// Store path index entry
	pathIndexKey := buildPathIndexKey(token, indexEntry)
	if err := c.storage.Set(pathIndexKey, PathIndexMarker{CacheKey: cacheKey}); err != nil {
		log.Error().Err(err).Str("cacheKey", cacheKey).Msg("Failed to store path index entry")
	}
}

// UpdateResponse updates only the response data and cachedAt timestamp for an existing cache entry
func (c *Cache) UpdateResponse(cacheKey string, statusCode int, header http.Header, bodyBytes []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var entry StoredCacheEntry
	err := c.storage.Get(buildEntryKey(cacheKey), &entry)
	if err != nil {
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

	// Update in storage
	if err := c.storage.Set(buildEntryKey(cacheKey), entry); err != nil {
		log.Error().Err(err).Str("cacheKey", cacheKey).Msg("Failed to update cache entry")
	}
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
	requests := make(map[string]*CachedRequest)

	// Get all entry keys
	entryKeys, err := c.storage.GetKeysByPrefix(prefixEntry)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get entry keys for expired requests check")
		return requests
	}

	for _, key := range entryKeys {
		var entry StoredCacheEntry
		if err := c.storage.Get(key, &entry); err != nil {
			continue
		}

		if entry.Request == nil {
			continue
		}

		// Only include entries where cache-ttl has expired
		age := now.Sub(entry.Request.CachedAt)
		if age <= cacheTTL {
			continue
		}

		// Extract cacheKey from storage key (remove prefix)
		cacheKey := strings.TrimPrefix(key, prefixEntry)

		requestCopy := &CachedRequest{
			Method:     entry.Request.Method,
			RequestURI: entry.Request.RequestURI,
			Headers:    make(http.Header),
			CachedAt:   entry.Request.CachedAt,
		}

		CopyHeaders(requestCopy.Headers, entry.Request.Headers)

		requests[cacheKey] = requestCopy
	}

	return requests
}

func (c *Cache) EvictEntry(cacheKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictEntryUnsafe(cacheKey)
}

// evictEntryUnsafe evicts an entry without acquiring the lock (caller must hold lock)
func (c *Cache) evictEntryUnsafe(cacheKey string) {
	// Get the entry to find its token and index info
	var entry StoredCacheEntry
	if err := c.storage.Get(buildEntryKey(cacheKey), &entry); err != nil {
		return
	}

	// Remove main entry
	if err := c.storage.Delete(buildEntryKey(cacheKey)); err != nil {
		log.Error().Err(err).Str("cacheKey", cacheKey).Msg("Failed to delete cache entry")
	}

	// Remove token index entry
	tokenIndexKey := buildTokenIndexKey(entry.Token, cacheKey)
	if err := c.storage.Delete(tokenIndexKey); err != nil {
		log.Debug().Err(err).Str("cacheKey", cacheKey).Msg("Failed to delete token index entry")
	}

	// Remove path index entry
	pathIndexKey := buildPathIndexKey(entry.Token, entry.Index)
	if err := c.storage.Delete(pathIndexKey); err != nil {
		log.Debug().Err(err).Str("cacheKey", cacheKey).Msg("Failed to delete path index entry")
	}
}

// GetAllTokens returns all unique tokens that have cached entries
func (c *Cache) GetAllTokens() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Get all token index keys and extract unique token hashes
	tokenKeys, err := c.storage.GetKeysByPrefix(prefixToken)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get token index keys")
		return nil
	}

	// We need to get unique tokens, but we only have hashes in the keys
	// We need to look up the actual token from entries
	tokenHashToToken := make(map[string]string)

	for _, key := range tokenKeys {
		// Key format: token:{tokenHash}:{cacheKey}
		parts := strings.SplitN(strings.TrimPrefix(key, prefixToken), ":", 2)
		if len(parts) < 2 {
			continue
		}
		tokenHash := parts[0]
		cacheKey := parts[1]

		if _, exists := tokenHashToToken[tokenHash]; exists {
			continue // Already found this token
		}

		// Get the entry to find the actual token
		var entry StoredCacheEntry
		if err := c.storage.Get(buildEntryKey(cacheKey), &entry); err == nil {
			tokenHashToToken[tokenHash] = entry.Token
		}
	}

	tokens := make([]string, 0, len(tokenHashToToken))
	for _, token := range tokenHashToToken {
		tokens = append(tokens, token)
	}

	return tokens
}

// GetFirstRequestForToken gets the first request (any, regardless of expiration) for a token
func (c *Cache) GetFirstRequestForToken(token string) (cacheKey string, request *CachedRequest, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	tokenPrefix := buildTokenIndexPrefix(token)
	tokenKeys, err := c.storage.GetKeysByPrefix(tokenPrefix)
	if err != nil || len(tokenKeys) == 0 {
		return "", nil, false
	}

	// Get the first cacheKey from the token's entries
	for _, key := range tokenKeys {
		// Key format: token:{tokenHash}:{cacheKey}
		parts := strings.SplitN(strings.TrimPrefix(key, prefixToken), ":", 2)
		if len(parts) < 2 {
			continue
		}
		cacheKey := parts[1]

		var entry StoredCacheEntry
		if err := c.storage.Get(buildEntryKey(cacheKey), &entry); err != nil {
			// Delete orphan index entry
			c.storage.Delete(key)
			continue
		}

		if entry.Request == nil {
			c.storage.Delete(key)
			continue
		}

		requestCopy := &CachedRequest{
			Method:     entry.Request.Method,
			RequestURI: entry.Request.RequestURI,
			Headers:    make(http.Header),
			CachedAt:   entry.Request.CachedAt,
		}

		CopyHeaders(requestCopy.Headers, entry.Request.Headers)

		return cacheKey, requestCopy, true
	}

	return "", nil, false
}

// EvictAllEntriesForToken evicts all cache entries for a given token
func (c *Cache) EvictAllEntriesForToken(token string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	tokenPrefix := buildTokenIndexPrefix(token)
	tokenKeys, err := c.storage.GetKeysByPrefix(tokenPrefix)
	if err != nil {
		return 0
	}

	evictedCount := 0

	for _, key := range tokenKeys {
		// Key format: token:{tokenHash}:{cacheKey}
		parts := strings.SplitN(strings.TrimPrefix(key, prefixToken), ":", 2)
		if len(parts) < 2 {
			continue
		}
		cacheKey := parts[1]

		c.evictEntryUnsafe(cacheKey)
		evictedCount++
	}

	return evictedCount
}

// RemoveTokenFromIndex removes all index entries for a token (without deleting main entries)
// This is a cleanup function called rarely for orphaned tokens
func (c *Cache) RemoveTokenFromIndex(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	tokenPrefix := buildTokenIndexPrefix(token)
	c.storage.DeleteByPrefix(tokenPrefix)

	// Also delete path index entries for this token
	// since path keys are prefixed by projectId:envSlug
	// we need to scan all path keys to find those containing this token's hash
	tokenHash := hashToken(token)
	pathKeys, err := c.storage.GetKeysByPrefix(prefixPath)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get path keys for token index cleanup")
		return
	}

	for _, key := range pathKeys {
		// Key format: path:{projectId}:{envSlug}:{tokenHash}:{secretPath}:{cacheKey}
		withoutPrefix := strings.TrimPrefix(key, prefixPath)
		parts := strings.SplitN(withoutPrefix, ":", 4)
		if len(parts) < 3 {
			continue
		}
		keyTokenHash := parts[2]
		if keyTokenHash == tokenHash {
			c.storage.Delete(key)
		}
	}
}

// PurgeByMutation purges cache entries across ALL tokens that match the mutation path
func (c *Cache) PurgeByMutation(projectID, envSlug, mutationPath string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	purgedCount := 0

	prefix := buildPathIndexPrefixForProject(projectID, envSlug)
	pathKeys, err := c.storage.GetKeysByPrefix(prefix)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get path index keys for mutation purge")
		return 0
	}

	for _, key := range pathKeys {
		// Key format: path:{projectId}:{envSlug}:{tokenHash}:{escapedSecretPath}:{cacheKey}
		// We already filtered by projectId:envSlug via prefix, so extract remaining parts
		withoutPrefix := strings.TrimPrefix(key, prefix)
		parts := strings.SplitN(withoutPrefix, ":", 3)
		if len(parts) < 3 {
			continue
		}

		// parts[0] = tokenHash (not needed for matching)
		keySecretPath := strings.ReplaceAll(parts[1], "\\:", ":") // Unescape colons
		keyCacheKey := parts[2]

		if matchesPath(keySecretPath, mutationPath) {
			c.evictEntryUnsafe(keyCacheKey)
			purgedCount++
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
	cacheKeys := make([]CacheKeyDebugInfo, 0)
	totalEntries := 0

	// Get all entry keys
	entryKeys, err := c.storage.GetKeysByPrefix(prefixEntry)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get entry keys for debug info")
		return CacheDebugInfo{}
	}

	// Maps for building compound path index debug info
	// tokenHash -> projectID -> envSlug -> secretPath -> []CacheKeyDebugInfo
	pathIndexData := make(map[string]map[string]map[string]map[string][]CacheKeyDebugInfo)
	tokenHashToToken := make(map[string]string)

	for _, key := range entryKeys {
		var entry StoredCacheEntry
		if err := c.storage.Get(key, &entry); err != nil {
			continue
		}

		cacheKey := strings.TrimPrefix(key, prefixEntry)
		tokenHash := hashToken(entry.Token)
		tokenHashToToken[tokenHash] = entry.Token

		// Count entries per token
		entriesByToken[entry.Token]++

		// Add to token index
		if tokenIndex[entry.Token] == nil {
			tokenIndex[entry.Token] = make([]IndexEntry, 0)
		}
		tokenIndex[entry.Token] = append(tokenIndex[entry.Token], entry.Index)

		// Calculate size
		if entry.Response != nil {
			totalSize += int64(len(entry.Response.BodyBytes))
		}

		// Add to cache keys list
		if entry.Request != nil {
			cacheKeys = append(cacheKeys, CacheKeyDebugInfo{
				CacheKey: cacheKey,
				CachedAt: entry.Request.CachedAt,
			})
		}

		totalEntries++

		// Build path index data
		if pathIndexData[tokenHash] == nil {
			pathIndexData[tokenHash] = make(map[string]map[string]map[string][]CacheKeyDebugInfo)
		}
		if pathIndexData[tokenHash][entry.Index.ProjectId] == nil {
			pathIndexData[tokenHash][entry.Index.ProjectId] = make(map[string]map[string][]CacheKeyDebugInfo)
		}
		if pathIndexData[tokenHash][entry.Index.ProjectId][entry.Index.EnvironmentSlug] == nil {
			pathIndexData[tokenHash][entry.Index.ProjectId][entry.Index.EnvironmentSlug] = make(map[string][]CacheKeyDebugInfo)
		}
		keyInfo := CacheKeyDebugInfo{CacheKey: cacheKey}
		if entry.Request != nil {
			keyInfo.CachedAt = entry.Request.CachedAt
		}
		pathIndexData[tokenHash][entry.Index.ProjectId][entry.Index.EnvironmentSlug][entry.Index.SecretPath] =
			append(pathIndexData[tokenHash][entry.Index.ProjectId][entry.Index.EnvironmentSlug][entry.Index.SecretPath], keyInfo)
	}

	// Build compound path index debug info
	compoundPathIndex := make([]CompoundPathIndexDebugInfo, 0)
	for tokenHash, projectMap := range pathIndexData {
		token := tokenHashToToken[tokenHash]
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

				for secretPath, keyInfos := range pathsMap {
					paths[secretPath] = PathDebugInfo{
						SecretPath: secretPath,
						CacheKeys:  keyInfos,
						KeyCount:   len(keyInfos),
					}
					envTotalKeys += len(keyInfos)
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
		TotalEntries:      totalEntries,
		TotalTokens:       len(tokenHashToToken),
		TotalSizeBytes:    totalSize,
		EntriesByToken:    entriesByToken,
		CacheKeys:         cacheKeys,
		TokenIndex:        tokenIndex,
		CompoundPathIndex: compoundPathIndex,
	}
}
