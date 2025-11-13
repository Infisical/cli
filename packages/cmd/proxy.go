package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/proxy"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Example:               `infisical proxy start`,
	Short:                 "Used to run Infisical proxy server",
	Use:                   "proxy",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
}

var proxyStartCmd = &cobra.Command{
	Example:               `infisical proxy start --domain=https://app.infisical.com --listen-address=localhost:8081`,
	Short:                 "Start the Infisical proxy server",
	Use:                   "start",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run:                   startProxyServer,
}

var proxyDebugCmd = &cobra.Command{
	Example:               `infisical proxy debug --listen-address=localhost:8081`,
	Short:                 "Print cache debug information (dev mode only)",
	Use:                   "debug",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run:                   printCacheDebug,
}

func startResyncLoop(ctx context.Context, cache *proxy.Cache, domainURL *url.URL, httpClient *http.Client, resyncInterval int, cacheTTL int) {
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
			requests := cache.GetExpiredRequests(cacheTTLDuration)

			refetched := 0
			evicted := 0

			for cacheKey, request := range requests {
				// --- Reconstruct the request --

				targetURL := *domainURL
				parsedURI, err := url.Parse(request.RequestURI)
				if err != nil {
					log.Error().
						Err(err).
						Str("cacheKey", cacheKey).
						Str("requestURI", request.RequestURI).
						Msg("Failed to parse requestURI during resync")
					continue
				}

				targetURL.Path = domainURL.Path + parsedURI.Path
				targetURL.RawQuery = parsedURI.RawQuery

				proxyReq, err := http.NewRequest(request.Method, targetURL.String(), nil)
				if err != nil {
					log.Error().
						Err(err).
						Str("cacheKey", cacheKey).
						Str("targetURL", targetURL.String()).
						Msg("Failed to create proxy request during resync")
					continue
				}

				proxy.CopyHeaders(proxyReq.Header, request.Headers)

				resp, err := httpClient.Do(proxyReq)
				if err != nil {
					log.Error().
						Err(err).
						Str("cacheKey", cacheKey).
						Str("requestURI", request.RequestURI).
						Msg("Network error during resync - keeping stale entry")
					// Keep stale entry for high availability
					continue
				}

				// --- Handle response --

				if resp.StatusCode == http.StatusOK {
					bodyBytes, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						log.Error().
							Err(err).
							Str("cacheKey", cacheKey).
							Msg("Failed to read response body during resync")
						continue
					}

					// Update only response data (IndexEntry doesn't change during resync)
					cache.UpdateResponse(cacheKey, resp.StatusCode, resp.Header, bodyBytes)
					refetched++

					log.Debug().
						Str("cacheKey", cacheKey).
						Str("requestURI", request.RequestURI).
						Msg("Successfully refetched and updated cache entry")
				} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
					// Evict entry on 401/403
					cache.EvictEntry(cacheKey)
					evicted++
					resp.Body.Close()

					log.Info().
						Str("cacheKey", cacheKey).
						Str("requestURI", request.RequestURI).
						Int("statusCode", resp.StatusCode).
						Msg("Evicted cache entry due to authorization failure")
				} else {
					// Other error status codes - keep stale entry
					resp.Body.Close()
					log.Warn().
						Str("cacheKey", cacheKey).
						Str("requestURI", request.RequestURI).
						Int("statusCode", resp.StatusCode).
						Msg("Unexpected status code during resync - keeping stale entry")
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

func startProxyServer(cmd *cobra.Command, args []string) {
	domain, err := cmd.Flags().GetString("domain")
	if err != nil {
		util.HandleError(err, "Unable to parse domain flag")
	}

	if domain == "" {
		util.PrintErrorMessageAndExit("Domain flag is required")
	}

	listenAddress, err := cmd.Flags().GetString("listen-address")
	if err != nil {
		util.HandleError(err, "Unable to parse listen-address flag")
	}

	if listenAddress == "" {
		util.PrintErrorMessageAndExit("Listen-address flag is required")
	}

	resyncInterval, err := cmd.Flags().GetInt("resync-interval")
	if err != nil {
		util.HandleError(err, "Unable to parse resync-interval flag")
	}

	cacheTTL, err := cmd.Flags().GetInt("cache-ttl")
	if err != nil {
		util.HandleError(err, "Unable to parse cache-ttl flag")
	}

	domainURL, err := url.Parse(domain)
	if err != nil {
		util.HandleError(err, fmt.Sprintf("Invalid domain URL: %s", domain))
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	cache := proxy.NewCache()
	devMode := util.CLI_VERSION == "devel"
	mux := http.NewServeMux()

	// Debug endpoint (dev mode only)
	if devMode {
		mux.HandleFunc("/_debug/cache", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			debugInfo := cache.GetDebugInfo()
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(debugInfo); err != nil {
				log.Error().Err(err).Msg("Failed to encode cache debug info")
				http.Error(w, "Failed to encode debug info", http.StatusInternalServerError)
				return
			}
		})
		log.Info().Msg("Dev mode enabled: debug endpoint available at /_debug/cache")
	}

	proxyHandler := func(w http.ResponseWriter, r *http.Request) {
		// Skip debug endpoints - they're handled by mux
		if strings.HasPrefix(r.URL.Path, "/_debug/") {
			http.NotFound(w, r)
			return
		}

		token := proxy.ExtractTokenFromRequest(r)

		isCacheable := proxy.IsCacheableRequest(r.URL.Path, r.Method)

		// -- Cache Check --

		if isCacheable && token != "" {
			cacheKey := proxy.GenerateCacheKey(r.Method, r.URL.Path, r.URL.RawQuery, token)

			if cachedResp, found := cache.Get(cacheKey); found {
				log.Info().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Str("cacheKey", cacheKey).
					Msg("Cache hit - serving from cache")

				proxy.CopyHeaders(w.Header(), cachedResp.Header)
				w.WriteHeader(cachedResp.StatusCode)
				_, err := io.Copy(w, cachedResp.Body)
				if err != nil {
					log.Error().Err(err).Msg("Failed to copy cached response body")
					return
				}
				return
			}

			log.Debug().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("cacheKey", cacheKey).
				Msg("Cache miss - forwarding request")
		}

		// -- Proxy Request --

		targetURL := *domainURL
		targetURL.Path = domainURL.Path + r.URL.Path
		targetURL.RawQuery = r.URL.RawQuery

		proxyReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create proxy request")
			http.Error(w, fmt.Sprintf("Failed to create proxy request: %v", err), http.StatusInternalServerError)
			return
		}

		proxy.CopyHeaders(proxyReq.Header, r.Header)

		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("target", targetURL.String()).
			Msg("Forwarding request")

		resp, err := httpClient.Do(proxyReq)
		if err != nil {
			log.Error().Err(err).Msg("Failed to forward request")
			http.Error(w, fmt.Sprintf("Failed to forward request: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Read response body into memory for caching (if needed) and serving
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read response body")
			http.Error(w, fmt.Sprintf("Failed to read response body: %v", err), http.StatusInternalServerError)
			return
		}

		// -- Proxy Response --

		proxy.CopyHeaders(w.Header(), resp.Header)

		w.WriteHeader(resp.StatusCode)

		_, err = w.Write(bodyBytes)
		if err != nil {
			log.Error().Err(err).Msg("Failed to write response body")
			return
		}

		// -- Cache Set --

		if isCacheable && token != "" && resp.StatusCode == http.StatusOK {
			cacheKey := proxy.GenerateCacheKey(r.Method, r.URL.Path, r.URL.RawQuery, token)

			queryParams := r.URL.Query()
			projectId := queryParams.Get("projectId")
			environment := queryParams.Get("environment")
			secretPath := queryParams.Get("secretPath")
			if secretPath == "" {
				secretPath = "/"
			}

			indexEntry := proxy.IndexEntry{
				CacheKey:        cacheKey,
				SecretPath:      secretPath,
				EnvironmentSlug: environment,
				ProjectId:       projectId,
			}

			cachedResp := &http.Response{
				StatusCode: resp.StatusCode,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
			}

			proxy.CopyHeaders(cachedResp.Header, resp.Header)

			cache.Set(cacheKey, r, cachedResp, token, indexEntry)

			log.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("cacheKey", cacheKey).
				Msg("Response cached successfully")
		}

		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", resp.StatusCode).
			Msg("Request forwarded successfully")
	}

	// Add proxy handler to mux
	mux.HandleFunc("/", proxyHandler)

	server := &http.Server{
		Addr:    listenAddress,
		Handler: mux,
	}

	resyncCtx, resyncCancel := context.WithCancel(context.Background())
	defer resyncCancel()

	go startResyncLoop(resyncCtx, cache, domainURL, httpClient, resyncInterval, cacheTTL)

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info().Msgf("Received signal %v, shutting down proxy server...", sig)

		// Cancel resync goroutine
		resyncCancel()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Error during server shutdown")
			os.Exit(1)
		}

		log.Info().Msg("Proxy server shutdown complete")
		os.Exit(0)
	}()

	log.Info().Msgf("Infisical proxy server starting on %s", listenAddress)
	log.Info().Msgf("Forwarding requests to %s", domain)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		util.HandleError(err, "Failed to start proxy server")
	}
}

func printCacheDebug(cmd *cobra.Command, args []string) {
	if util.CLI_VERSION != "devel" {
		util.PrintErrorMessageAndExit("This command is only available in dev mode (when CLI_VERSION is 'devel').")
	}

	listenAddress, err := cmd.Flags().GetString("listen-address")
	if err != nil {
		util.HandleError(err, "Unable to parse listen-address flag")
	}

	if listenAddress == "" {
		util.PrintErrorMessageAndExit("Listen-address flag is required")
	}

	baseURL := "http://" + listenAddress
	if strings.HasPrefix(listenAddress, ":") {
		baseURL = "http://localhost" + listenAddress
	}

	debugURL := baseURL + "/_debug/cache"
	resp, err := http.Get(debugURL)
	if err != nil {
		util.HandleError(err, fmt.Sprintf("Failed to connect to proxy at %s. Make sure the proxy is running in dev mode (CLI_VERSION='devel')", listenAddress))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to get cache debug info: %s", string(body)))
	}

	var debugInfo proxy.CacheDebugInfo
	if err := json.NewDecoder(resp.Body).Decode(&debugInfo); err != nil {
		util.HandleError(err, "Failed to decode cache debug info")
	}

	output, err := json.MarshalIndent(debugInfo, "", "  ")
	if err != nil {
		util.HandleError(err, "Failed to marshal cache debug info")
	}

	fmt.Println("Cache Debug Information:")
	fmt.Println(string(output))
}

func init() {
	proxyStartCmd.Flags().String("domain", "", "Domain of your Infisical instance (e.g., https://app.infisical.com for cloud, https://my-self-hosted-instance.com for self-hosted)")
	proxyStartCmd.Flags().String("listen-address", "localhost:8081", "The address for the proxy server to listen on. Defaults to localhost:8081")
	proxyStartCmd.Flags().Int("resync-interval", 10, "Interval in minutes for resyncing cached secrets. Defaults to 10 minutes.")
	proxyStartCmd.Flags().Int("cache-ttl", 60, "TTL in minutes for individual cache entries. Defaults to 60 minutes.")

	proxyDebugCmd.Flags().String("listen-address", "localhost:8081", "The address where the proxy server is listening. Defaults to localhost:8081")

	proxyCmd.AddCommand(proxyStartCmd)
	proxyCmd.AddCommand(proxyDebugCmd)
	rootCmd.AddCommand(proxyCmd)
}
