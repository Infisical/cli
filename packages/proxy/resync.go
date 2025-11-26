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

	re := regexp.MustCompile(`(\d+)\s+seconds?`)
	matches := re.FindStringSubmatch(errorResponse.Message)
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

// StartResyncLoop starts the background resync loop for cache entries
func StartResyncLoop(ctx context.Context, cache *Cache, domainURL *url.URL, httpClient *http.Client, resyncInterval int, cacheTTL int) {
	ticker := time.NewTicker(time.Duration(resyncInterval) * time.Minute)
	defer ticker.Stop()

	log.Info().
		Int("resyncInterval", resyncInterval).
		Int("cacheTTL", cacheTTL).
		Msg("Resync loop started")

	for {
		select {
		case <-ticker.C:
			log.Info().Msg("Starting resync cycle")
			cacheTTLDuration := time.Duration(cacheTTL) * time.Minute

			// -- Token testing phase (before expired requests) --

			tokens := cache.GetAllTokens()
			tokensEvicted := 0

			for _, token := range tokens {
				// Add jitter
				time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)

				cacheKey, request, found := cache.GetFirstRequestForToken(token)
				if !found {
					cache.RemoveTokenFromIndex(token)
					log.Debug().
						Str("token", token).
						Msg("Removed orphaned token entry during token testing")
					continue
				}

				proxyReq, err := reconstructProxyRequest(domainURL, request)
				if err != nil {
					log.Error().
						Err(err).
						Str("token", token).
						Str("cacheKey", cacheKey).
						Str("requestURI", request.RequestURI).
						Msg("Failed to reconstruct request during token testing")
					continue
				}

				resp, err := httpClient.Do(proxyReq)
				if err != nil {
					// Keep entries for high availability

					log.Error().
						Err(err).
						Str("token", token).
						Str("cacheKey", cacheKey).
						Str("requestURI", request.RequestURI).
						Msg("Network error during token testing - keeping entries")

					continue
				}

				// If 401, evict all entries for this token
				if resp.StatusCode == http.StatusUnauthorized {
					evictedCount := cache.EvictAllEntriesForToken(token)
					resp.Body.Close()
					tokensEvicted++

					if evictedCount == 1 {
						log.Info().
							Str("token", token).
							Msg("Entry evicted")
					} else {
						log.Info().
							Int("evictedCount", evictedCount).
							Str("token", token).
							Msg("Entries evicted")
					}
				} else {
					resp.Body.Close()
				}
			}

			if tokensEvicted > 0 {
				log.Debug().
					Int("tokensEvicted", tokensEvicted).
					Msg("Token testing phase completed")
			}

			// -- Expired entries processing phase --

			cycleStartTime := time.Now()
			resyncIntervalDuration := time.Duration(resyncInterval) * time.Minute

			requests := cache.GetExpiredRequests(cacheTTLDuration)

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
				// Add jitter
				time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)

				proxyReq, err := reconstructProxyRequest(domainURL, entry.request)
				if err != nil {
					log.Error().
						Err(err).
						Str("cacheKey", entry.cacheKey).
						Str("requestURI", entry.request.RequestURI).
						Msg("Failed to parse requestURI during resync")
					continue
				}

				resp, err := httpClient.Do(proxyReq)
				if err != nil {
					// Keep stale entry for high availability

					log.Error().
						Err(err).
						Str("cacheKey", entry.cacheKey).
						Str("requestURI", entry.request.RequestURI).
						Msg("Network error during resync - keeping stale entry")

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
					timeUntilNextTick := resyncIntervalDuration - time.Since(cycleStartTime)

					if pauseDuration <= timeUntilNextTick {
						log.Info().
							Int("pauseSeconds", retryAfterSeconds+2).
							Msg("Rate limited, pausing resync")
						time.Sleep(pauseDuration)
					} else {
						log.Warn().
							Int("pauseSeconds", retryAfterSeconds+2).
							Msg("Rate limit pause exceeds resync interval, remaining entries will be processed next cycle. Increase the resync-interval value and the cache-ttl value to prevent this behavior.")
						break
					}
				}
			}

			log.Info().
				Int("expiredEntries", len(requests)).
				Int("refetched", refetched).
				Int("evicted", evicted).
				Msg("Resync cycle completed")

		case <-ctx.Done():
			log.Info().Msg("Resync loop stopped")
			return
		}
	}
}
