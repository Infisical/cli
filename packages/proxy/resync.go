package proxy

import (
	"context"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

var rateLimitSecondsRegex = regexp.MustCompile(`(\d+)\s+seconds?`)

// maskToken masks a token showing only first 5 and last 5 characters
func maskToken(token string) string {
	if len(token) <= 10 {
		return "***"
	}
	return token[:5] + "..." + token[len(token)-5:]
}

// parseRateLimitSeconds extracts retry-after seconds from rate limit error message
// Expected format: "Rate limit exceeded. Please try again in 57 seconds"
// Returns default of 10 seconds if parsing fails
func parseRateLimitSeconds(body []byte) int {
	var errorResponse struct {
		Message string `json:"message"`
	}

	var seconds int = 10

	if err := json.Unmarshal(body, &errorResponse); err != nil {
		return seconds
	}

	matches := rateLimitSecondsRegex.FindStringSubmatch(errorResponse.Message)
	if len(matches) < 2 {
		return 10
	}

	seconds, err := strconv.Atoi(matches[1])
	if err != nil {
		return 10
	}

	return seconds
}

func handleResyncResponse(cache *Cache, cacheKey string, requestURI string, resp *http.Response) (refetched bool, evicted bool, rateLimited bool, retryAfterSeconds int) {
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().
				Err(err).
				Str("cacheKey", cacheKey).
				Msg("Failed to read response body during resync")
			return false, false, false, 0
		}

		// Update only response data (IndexEntry doesn't change during resync)
		cache.UpdateResponse(cacheKey, resp.StatusCode, resp.Header, bodyBytes)

		log.Debug().
			Str("cacheKey", cacheKey).
			Str("requestURI", requestURI).
			Msg("Successfully refetched and updated cache entry")
		return true, false, false, 0
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		// Evict entry on 401/403/404
		cache.EvictEntry(cacheKey)

		log.Info().
			Str("hash", cacheKey).
			Msg("Entry evicted")
		return false, true, false, 0
	case http.StatusTooManyRequests:
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().
				Err(err).
				Str("cacheKey", cacheKey).
				Msg("Failed to read rate limit response body, using default 10 seconds")
			return false, false, true, 10
		}

		retryAfter := parseRateLimitSeconds(bodyBytes)

		log.Debug().
			Str("cacheKey", cacheKey).
			Str("requestURI", requestURI).
			Int("retryAfterSeconds", retryAfter).
			Msg("Rate limited during resync")
		return false, false, true, retryAfter
	default:
		// Other error status codes - keep stale entry
		log.Debug().
			Str("cacheKey", cacheKey).
			Str("requestURI", requestURI).
			Int("statusCode", resp.StatusCode).
			Msg("Unexpected status code during resync - keeping stale entry")
		return false, false, false, 0
	}
}

func reconstructProxyRequest(domainURL *url.URL, request *CachedRequest) (*http.Request, error) {
	targetURL := *domainURL
	parsedURI, err := url.Parse(request.RequestURI)
	if err != nil {
		return nil, err
	}

	targetURL.Path = domainURL.Path + parsedURI.Path
	targetURL.RawQuery = parsedURI.RawQuery

	proxyReq, err := http.NewRequest(request.Method, targetURL.String(), nil)
	if err != nil {
		return nil, err
	}

	CopyHeaders(proxyReq.Header, request.Headers)
	return proxyReq, nil
}

// runAccessTokenValidation validates all cached tokens and evicts entries for invalid tokens
func runAccessTokenValidation(cache *Cache, domainURL *url.URL, httpClient *http.Client) {
	log.Info().Msg("Starting access token validation")

	tokens := cache.GetAllTokens()
	tokensEvicted := 0

	for _, token := range tokens {
		// Add jitter to avoid bursts
		time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)

		cacheKey, request, found := cache.GetFirstRequestForToken(token)
		if !found {
			cache.RemoveTokenFromIndex(token)
			log.Debug().
				Str("token", maskToken(token)).
				Msg("Removed orphaned token entry during token validation")
			continue
		}

		proxyReq, err := reconstructProxyRequest(domainURL, request)
		if err != nil {
			log.Error().
				Err(err).
				Str("token", maskToken(token)).
				Str("cacheKey", cacheKey).
				Str("requestURI", request.RequestURI).
				Msg("Failed to reconstruct request during token validation")
			continue
		}

		resp, err := httpClient.Do(proxyReq)
		if err != nil || (resp != nil && resp.StatusCode >= 500) {
			// Keep entries for high availability (optimistic eviction strategy)
			if resp != nil {
				resp.Body.Close()
			}
			log.Error().
				Err(err).
				Str("token", maskToken(token)).
				Str("cacheKey", cacheKey).
				Str("requestURI", request.RequestURI).
				Msg("Network error during token validation - keeping entries (optimistic strategy)")
			continue
		}

		// If 401, evict all entries for this token
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			evictedCount := cache.EvictAllEntriesForToken(token)
			resp.Body.Close()
			tokensEvicted++

			if evictedCount == 1 {
				log.Info().
					Str("token", maskToken(token)).
					Msg("Token invalid - entry evicted")
			} else {
				log.Info().
					Int("evictedCount", evictedCount).
					Str("token", maskToken(token)).
					Msg("Token invalid - entries evicted")
			}
		} else {
			resp.Body.Close()
		}
	}

	log.Info().
		Int("tokensChecked", len(tokens)).
		Int("tokensEvicted", tokensEvicted).
		Msg("Access token validation completed")
}

// runStaticSecretsRefresh refreshes all cached secrets that have exceeded the refresh interval
func runStaticSecretsRefresh(cache *Cache, domainURL *url.URL, httpClient *http.Client, refreshInterval time.Duration) {
	log.Info().Msg("Starting static secrets refresh")

	cycleStartTime := time.Now()

	requests := cache.GetExpiredRequests(refreshInterval)

	// Convert map to slice and sort by CachedAt (oldest first)
	type orderedEntry struct {
		cacheKey string
		request  *CachedRequest
	}
	ordered := make([]orderedEntry, 0, len(requests))
	for key, req := range requests {
		ordered = append(ordered, orderedEntry{key, req})
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].request.CachedAt.Before(ordered[j].request.CachedAt)
	})

	refetched := 0
	evicted := 0

	for _, entry := range ordered {
		// Add jitter to avoid bursts
		time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)

		proxyReq, err := reconstructProxyRequest(domainURL, entry.request)
		if err != nil {
			log.Error().
				Err(err).
				Str("cacheKey", entry.cacheKey).
				Str("requestURI", entry.request.RequestURI).
				Msg("Failed to parse requestURI during secrets refresh")
			continue
		}

		resp, err := httpClient.Do(proxyReq)
		if err != nil || (resp != nil && resp.StatusCode >= 500) {
			// Keep stale entry for high availability (optimistic eviction strategy)
			if resp != nil {
				resp.Body.Close()
			}
			log.Error().
				Err(err).
				Str("cacheKey", entry.cacheKey).
				Str("requestURI", entry.request.RequestURI).
				Msg("Network error during secrets refresh - keeping stale entry (optimistic strategy)")
			continue
		}

		refetchedResult, evictedResult, rateLimited, retryAfterSeconds := handleResyncResponse(cache, entry.cacheKey, entry.request.RequestURI, resp)
		if refetchedResult {
			refetched++
		}
		if evictedResult {
			evicted++
		}

		// Handle rate limiting
		if rateLimited {
			pauseDuration := time.Duration(retryAfterSeconds+2) * time.Second // 2 seconds buffer
			timeUntilNextTick := refreshInterval - time.Since(cycleStartTime)

			if pauseDuration <= timeUntilNextTick {
				log.Info().
					Int("pauseSeconds", retryAfterSeconds+2).
					Msg("Rate limited, pausing secrets refresh")
				time.Sleep(pauseDuration)
			} else {
				log.Warn().
					Int("pauseSeconds", retryAfterSeconds+2).
					Msg("Rate limit pause exceeds refresh interval, remaining entries will be processed next cycle. Increase the static-secrets-refresh-interval value to prevent this behavior.")
				break
			}
		}
	}

	log.Info().
		Int("expiredEntries", len(requests)).
		Int("refetched", refetched).
		Int("evicted", evicted).
		Msg("Static secrets refresh completed")
}

func runProjectSecretsRefresh(cache *Cache, domainURL *url.URL, httpClient *http.Client, projectId, envSlug string) {
	log.Info().Str("projectId", projectId).Str("envSlug", envSlug).Msg("Starting project secrets refresh")

	requests := cache.GetEntriesForProjectEnv(projectId, envSlug)

	type orderedEntry struct {
		cacheKey string
		request  *CachedRequest
	}
	ordered := make([]orderedEntry, 0, len(requests))
	for key, req := range requests {
		ordered = append(ordered, orderedEntry{key, req})
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].request.CachedAt.Before(ordered[j].request.CachedAt)
	})

	refetched := 0
	evicted := 0

	for _, entry := range ordered {
		time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)

		proxyReq, err := reconstructProxyRequest(domainURL, entry.request)
		if err != nil {
			log.Error().
				Err(err).
				Str("cacheKey", entry.cacheKey).
				Str("requestURI", entry.request.RequestURI).
				Msg("Failed to parse requestURI during project secrets refresh")
			continue
		}

		resp, err := httpClient.Do(proxyReq)
		if err != nil || (resp != nil && resp.StatusCode >= 500) {
			if resp != nil {
				resp.Body.Close()
			}
			log.Error().
				Err(err).
				Str("cacheKey", entry.cacheKey).
				Str("requestURI", entry.request.RequestURI).
				Msg("Network error during project secrets refresh - keeping stale entry (optimistic strategy)")
			continue
		}

		refetchedResult, evictedResult, rateLimited, retryAfterSeconds := handleResyncResponse(cache, entry.cacheKey, entry.request.RequestURI, resp)
		if refetchedResult {
			refetched++
		}
		if evictedResult {
			evicted++
		}

		if rateLimited {
			pauseDuration := time.Duration(retryAfterSeconds+2) * time.Second
			log.Info().
				Int("pauseSeconds", retryAfterSeconds+2).
				Str("projectId", projectId).
				Msg("Rate limited during project secrets refresh, pausing")
			time.Sleep(pauseDuration)
		}
	}

	log.Info().
		Str("projectId", projectId).
		Int("totalEntries", len(requests)).
		Int("refetched", refetched).
		Int("evicted", evicted).
		Msg("Project secrets refresh completed")
}

func startProjectPollingLoop(ctx context.Context, cache *Cache, domainURL *url.URL, httpClient *http.Client, projectId, envSlug string, interval time.Duration, onPollComplete func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	firstTick := true
	for {
		select {
		case <-ticker.C:
			runProjectSecretsRefresh(cache, domainURL, httpClient, projectId, envSlug)
			if !firstTick && onPollComplete != nil {
				onPollComplete()
			}
			firstTick = false
		case <-ctx.Done():
			return
		}
	}
}

func startAccessTokenValidation(ctx context.Context, cache *Cache, domainURL *url.URL, httpClient *http.Client, accessTokenCheckInterval time.Duration) {
	tokenTicker := time.NewTicker(accessTokenCheckInterval)
	defer tokenTicker.Stop()

	for {
		select {
		case <-tokenTicker.C:
			runAccessTokenValidation(cache, domainURL, httpClient)
		case <-ctx.Done():
			return
		}
	}
}

func startStaticSecretsRefresh(ctx context.Context, cache *Cache, domainURL *url.URL, httpClient *http.Client, staticSecretsRefreshInterval time.Duration) {
	secretsTicker := time.NewTicker(staticSecretsRefreshInterval)
	defer secretsTicker.Stop()

	for {
		select {
		case <-secretsTicker.C:
			runStaticSecretsRefresh(cache, domainURL, httpClient, staticSecretsRefreshInterval)
		case <-ctx.Done():
			return
		}
	}
}

// StartBackgroundLoops starts the background loops for token validation and secrets refresh.
// When sseEnabled is true, the static secrets refresh loop is disabled (SSE handles cache invalidation).
func StartBackgroundLoops(ctx context.Context, cache *Cache, domainURL *url.URL, httpClient *http.Client, evictionStrategy string, accessTokenCheckInterval time.Duration, staticSecretsRefreshInterval time.Duration, sseEnabled bool) {
	log.Info().
		Str("evictionStrategy", evictionStrategy).
		Str("accessTokenCheckInterval", accessTokenCheckInterval.String()).
		Str("staticSecretsRefreshInterval", staticSecretsRefreshInterval.String()).
		Bool("sseEnabled", sseEnabled).
		Msg("Background loops started")

	go startAccessTokenValidation(ctx, cache, domainURL, httpClient, accessTokenCheckInterval)
	if !sseEnabled {
		go startStaticSecretsRefresh(ctx, cache, domainURL, httpClient, staticSecretsRefreshInterval)
	}
}
