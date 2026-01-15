package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	"github.com/Infisical/infisical-merge/packages/util/cache"
	"github.com/awnumar/memguard"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type CacheEvictionStrategy string

const (
	CacheEvictionStrategyOptimistic CacheEvictionStrategy = "optimistic"
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
	Hidden:                true,
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

	tlsEnabled, err := cmd.Flags().GetBool("tls-enabled")
	if err != nil {
		util.HandleError(err, "Unable to parse tls-enabled flag")
	}

	tlsCertFile, err := cmd.Flags().GetString("tls-cert-file")
	if err != nil {
		util.HandleError(err, "Unable to parse tls-cert-file flag")
	}

	tlsKeyFile, err := cmd.Flags().GetString("tls-key-file")
	if err != nil {
		util.HandleError(err, "Unable to parse tls-key-file flag")
	}

	if tlsEnabled && (tlsCertFile == "" || tlsKeyFile == "") {
		util.PrintErrorMessageAndExit("`tls-cert-file` and `tls-key-file` are required when `tls-enabled` is set to true")
	}

	if listenAddress == "" {
		util.PrintErrorMessageAndExit("Listen-address flag is required")
	}

	evictionStrategy, err := cmd.Flags().GetString("eviction-strategy")
	if err != nil {
		util.HandleError(err, "Unable to parse eviction-strategy flag")
	}

	if evictionStrategy != string(CacheEvictionStrategyOptimistic) {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Invalid eviction-strategy '%s'. Currently only 'optimistic' is supported.", evictionStrategy))
	}

	accessTokenCheckIntervalStr, err := cmd.Flags().GetString("access-token-check-interval")
	if err != nil {
		util.HandleError(err, "Unable to parse access-token-check-interval flag")
	}

	accessTokenCheckInterval, err := util.ParseTimeDurationString(accessTokenCheckIntervalStr, true)
	if err != nil {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Invalid access-token-check-interval format '%s'. Use formats like 5m, 1h, 1d", accessTokenCheckIntervalStr))
	}

	staticSecretsRefreshIntervalStr, err := cmd.Flags().GetString("static-secrets-refresh-interval")
	if err != nil {
		util.HandleError(err, "Unable to parse static-secrets-refresh-interval flag")
	}

	staticSecretsRefreshInterval, err := util.ParseTimeDurationString(staticSecretsRefreshIntervalStr, true)
	if err != nil {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Invalid static-secrets-refresh-interval format '%s'. Use formats like 30m, 1h, 1d", staticSecretsRefreshIntervalStr))
	}

	domainURL, err := url.Parse(domain)
	if err != nil {
		util.HandleError(err, fmt.Sprintf("Invalid domain URL: %s", domain))
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create a separate client for streaming endpoints (no timeout for long-lived connections)
	streamingClient := &http.Client{
		Timeout: 0,
	}

	// Create in-memory cache (no persistence, no encryption needed for ephemeral data)
	// For persistent cache with encryption, use proxy.NewCacheWithOptions
	encryptionKey := memguard.NewBufferRandom(32)
	defer encryptionKey.Destroy()

	cache, err := proxy.NewCache(cache.EncryptedStorageOptions{
		InMemory:      true,
		EncryptionKey: encryptionKey,
	})

	if err != nil {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to create cache: %v", err))
	}

	defer cache.Close()

	mux := http.NewServeMux()

	// Debug endpoint (dev mode only)
	if util.IsDevelopmentMode() {
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
		isStreaming := isStreamingEndpoint(r.URL.Path)

		// -- Cache Check --

		if isCacheable && token != "" {
			cacheKey := proxy.GenerateCacheKey(r.Method, r.URL.Path, r.URL.RawQuery, token)

			if cachedResp, found := cache.Get(cacheKey); found {
				log.Info().
					Str("hash", cacheKey).
					Msg("Cache hit")

				proxy.CopyHeaders(w.Header(), cachedResp.Header)
				w.WriteHeader(cachedResp.StatusCode)
				_, err := io.Copy(w, cachedResp.Body)
				if err != nil {
					log.Error().Err(err).Msg("Failed to copy cached response body")
					return
				}
				return
			}

			log.Info().
				Str("hash", cacheKey).
				Msg("Cache miss")
		}

		// -- Proxy Request --

		// Read request body for mutation eviction (PATCH/DELETE) or restore for forwarding
		var requestBodyBytes []byte
		if r.Body != nil {
			requestBodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("Failed to read request body")
				http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusInternalServerError)
				return
			}
		}

		targetURL := *domainURL
		targetURL.Path = domainURL.Path + r.URL.Path
		targetURL.RawQuery = r.URL.RawQuery

		var bodyReader io.Reader
		if requestBodyBytes != nil {
			bodyReader = bytes.NewReader(requestBodyBytes)
		}

		proxyReq, err := http.NewRequest(r.Method, targetURL.String(), bodyReader)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create proxy request")
			http.Error(w, fmt.Sprintf("Failed to create proxy request: %v", err), http.StatusInternalServerError)
			return
		}

		proxy.CopyHeaders(proxyReq.Header, r.Header)

		log.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("target", targetURL.String()).
			Msg("Forwarding request")

		// Use streaming client for SSE/streaming endpoints, regular client for others
		clientToUse := httpClient
		if isStreaming {
			clientToUse = streamingClient
		}

		resp, err := clientToUse.Do(proxyReq)
		if err != nil {
			log.Error().Err(err).Msg("Failed to forward request")
			http.Error(w, fmt.Sprintf("Failed to forward request: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// -- Proxy Response --

		proxy.CopyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)

		// For streaming endpoints, stream directly instead of buffering
		if isStreaming {
			// Flush headers immediately for SSE
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}

			// Stream with periodic flushing for SSE events
			buf := make([]byte, 1024)
			for {
				n, err := resp.Body.Read(buf)
				if n > 0 {
					if _, writeErr := w.Write(buf[:n]); writeErr != nil {
						log.Error().Err(writeErr).Msg("Failed to write streaming response")
						return
					}
					// Flush after each write to send SSE events immediately
					if flusher, ok := w.(http.Flusher); ok {
						flusher.Flush()
					}
				}
				if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					break
				}
				if err != nil {
					log.Error().Err(err).Msg("Failed to read streaming response")
					return
				}
			}
			return
		}

		// For non-streaming endpoints, read into memory for caching and serving
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read response body")
			http.Error(w, fmt.Sprintf("Failed to read response body: %v", err), http.StatusInternalServerError)
			return
		}

		_, err = w.Write(bodyBytes)
		if err != nil {
			log.Error().Err(err).Msg("Failed to write response body")
			return
		}

		// -- Secret Mutation Purging --

		if (r.Method == http.MethodPatch || r.Method == http.MethodDelete || r.Method == http.MethodPost) &&
			proxy.IsSecretsEndpoint(r.URL.Path) &&
			resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var projectId, environment, secretPath string

			if len(requestBodyBytes) > 0 {
				var bodyData map[string]interface{}
				if err := json.Unmarshal(requestBodyBytes, &bodyData); err == nil {
					// Support both v3 (workspaceId/workspaceSlug) and v4 (projectId)
					if projId, ok := bodyData["projectId"].(string); ok {
						projectId = projId
					} else if workspaceId, ok := bodyData["workspaceId"].(string); ok {
						projectId = workspaceId
					} else if workspaceSlug, ok := bodyData["workspaceSlug"].(string); ok {
						projectId = workspaceSlug
					}
					if env, ok := bodyData["environment"].(string); ok {
						environment = env
					}
					if path, ok := bodyData["secretPath"].(string); ok {
						secretPath = path
					}
				} else {
					log.Error().
						Err(err).
						Str("method", r.Method).
						Str("path", r.URL.Path).
						Msg("Failed to parse mutation request body for cache purging - cache may serve stale data")
				}
			}

			if secretPath == "" {
				secretPath = "/"
			}

			if projectId == "" || environment == "" {
				log.Warn().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Msg("Missing projectId or environment for cache purging - skipping cache purge")
				return
			} else {

				log.Debug().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Str("projectId", projectId).
					Str("environment", environment).
					Str("secretPath", secretPath).
					Msg("Attempting mutation purging across all tokens")
				purgedCount := cache.PurgeByMutation(projectId, environment, secretPath)

				if purgedCount == 1 {
					log.Info().
						Str("mutationPath", secretPath).
						Msg("Entry purged")
				} else {
					log.Info().
						Int("purgedCount", purgedCount).
						Str("mutationPath", secretPath).
						Msg("Entries purged")
				}
			}
		}

		// -- Cache Set --

		if isCacheable && token != "" && resp.StatusCode == http.StatusOK {
			cacheKey := proxy.GenerateCacheKey(r.Method, r.URL.Path, r.URL.RawQuery, token)

			queryParams := r.URL.Query()
			// Support both v3 (workspaceId/workspaceSlug) and v4 (projectId)
			projectId := queryParams.Get("projectId")
			if projectId == "" {
				projectId = queryParams.Get("workspaceId")
			}
			if projectId == "" {
				projectId = queryParams.Get("workspaceSlug")
			}
			environment := queryParams.Get("environment")
			secretPath := queryParams.Get("secretPath")
			if secretPath == "" {
				secretPath = "/"
			}

			if r.URL.Path == "/api/v3/secrets" || r.URL.Path == "/api/v4/secrets" ||
				r.URL.Path == "/api/v3/secrets/raw" || r.URL.Path == "/api/v4/secrets/raw" {
				recursive := queryParams.Get("recursive")
				if recursive == "true" {
					secretPath = secretPath + "*"
				}
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

			if indexEntry.ProjectId != "" && indexEntry.EnvironmentSlug != "" {

				cache.Set(cacheKey, r, cachedResp, token, indexEntry)

				log.Debug().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Str("cacheKey", cacheKey).
					Msg("Secret response cached successfully")
			} else {
				log.Warn().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Str("cacheKey", cacheKey).
					Msg("Secret response not cached because project ID or environment slug is empty")
			}
		}

		log.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", resp.StatusCode).
			Msg("Request forwarded successfully")
	}

	// Add proxy handler to mux
	mux.HandleFunc("/", proxyHandler)

	var tlsConfig *tls.Config
	if tlsEnabled {
		cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
		if err != nil {
			util.HandleError(err, fmt.Sprintf("Failed to load TLS certificate and key: %s", err))
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	server := &http.Server{
		Addr:      listenAddress,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	resyncCtx, resyncCancel := context.WithCancel(context.Background())
	defer resyncCancel()

	go proxy.StartBackgroundLoops(resyncCtx, cache, domainURL, httpClient, evictionStrategy, accessTokenCheckInterval, staticSecretsRefreshInterval)

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

	if tlsEnabled {
		log.Info().Msgf("Infisical proxy server starting on %s with TLS enabled", listenAddress)
	} else {
		log.Info().Msgf("Infisical proxy server starting on %s", listenAddress)
	}

	log.Info().Msgf("Forwarding requests to %s", domain)

	if tlsEnabled {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			util.HandleError(err, "Failed to start proxy server with TLS")
		}
	} else {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			util.HandleError(err, "Failed to start proxy server")
		}
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

func isStreamingEndpoint(path string) bool {
	return strings.HasPrefix(path, "/api/v1/events/")
}

func init() {
	proxyStartCmd.Flags().String("domain", "", "Domain of your Infisical instance (e.g., https://app.infisical.com for cloud, https://my-self-hosted-instance.com for self-hosted)")
	proxyStartCmd.Flags().String("listen-address", "localhost:8081", "The address for the proxy server to listen on. Defaults to localhost:8081")
	proxyStartCmd.Flags().String("eviction-strategy", string(CacheEvictionStrategyOptimistic), "Cache eviction strategy. 'optimistic' keeps cached data when Infisical is unreachable for high availability. Currently only 'optimistic' is supported.")
	proxyStartCmd.Flags().String("access-token-check-interval", "5m", "How often to validate that access tokens are still valid (e.g., 5m, 1h). Defaults to 5m.")
	proxyStartCmd.Flags().String("static-secrets-refresh-interval", "1h", "How often to refresh cached secrets (e.g., 30m, 1h, 1d). Defaults to 1h.")
	proxyStartCmd.Flags().String("tls-cert-file", "", "The path to the TLS certificate file for the proxy server. Required when `tls-enabled` is set to true (default)")
	proxyStartCmd.Flags().String("tls-key-file", "", "The path to the TLS key file for the proxy server. Required when `tls-enabled` is set to true (default)")
	proxyStartCmd.Flags().Bool("tls-enabled", true, "Whether to enable TLS for the proxy server. Defaults to true")

	proxyDebugCmd.Flags().String("listen-address", "localhost:8081", "The address where the proxy server is listening. Defaults to localhost:8081")

	proxyCmd.AddCommand(proxyStartCmd)
	proxyCmd.AddCommand(proxyDebugCmd)
	rootCmd.AddCommand(proxyCmd)
}
