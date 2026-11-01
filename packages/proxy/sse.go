package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type SSEEventType string

const (
	SSEEventSecretCreate         SSEEventType = "secret:create"
	SSEEventSecretUpdate         SSEEventType = "secret:update"
	SSEEventSecretDelete         SSEEventType = "secret:delete"
	SSEEventSecretImportMutation SSEEventType = "secret:import-mutation"
)

type SSEEvent struct {
	EventType SSEEventType
	Data      SSEEventData
}

type SSEEventData struct {
	Environment string `json:"environment"`
	SecretPath  string `json:"secretPath"`
	ProjectId   string `json:"projectId"`
	SecretKey   string `json:"secretKey"`
}

type sseRawMessage struct {
	ProjectType string            `json:"projectType"`
	Data        sseRawMessageData `json:"data"`
}

type sseRawMessageData struct {
	EventType string           `json:"eventType"`
	Payload   []ssePayloadItem `json:"payload"`
}

type ssePayloadItem struct {
	Environment string `json:"environment"`
	SecretPath  string `json:"secretPath"`
	SecretKey   string `json:"secretKey"`
}

type SSESubscriptionRegisterItem struct {
	Event SSEEventType `json:"event"`
}

type SSESubscriptionRequest struct {
	ProjectId string                        `json:"projectId"`
	Register  []SSESubscriptionRegisterItem `json:"register"`
}

type universalAuthLoginRequest struct {
	ClientSecret string `json:"clientSecret"`
	ClientId     string `json:"clientId"`
}

type universalAuthLoginResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
	TokenType   string `json:"tokenType"`
}

// SSEAuthState manages authentication state for SSE operations.
// It holds a reusable token and credentials for re-authentication.
type SSEAuthState struct {
	mu           sync.RWMutex
	token        string
	clientId     string
	clientSecret string
	domainURL    *url.URL
	httpClient   *http.Client
}

func NewSSEAuthState(clientId, clientSecret string, domainURL *url.URL, httpClient *http.Client) (*SSEAuthState, error) {
	authState := &SSEAuthState{
		clientId:     clientId,
		clientSecret: clientSecret,
		domainURL:    domainURL,
		httpClient:   httpClient,
	}

	// ensure we have a valid token
	_, err := authState.UniversalAuthLogin()
	if err != nil {
		log.Error().Err(err).Msg("Failed to authenticate machine identity")
		return nil, err
	}

	return authState, nil
}

func (s *SSEAuthState) GetToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

func (s *SSEAuthState) SetToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
}

func (s *SSEAuthState) UniversalAuthLogin() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newToken, err := CallUniversalAuthLogin(s.domainURL, s.clientId, s.clientSecret, s.httpClient)
	if err != nil {
		return "", err
	}
	s.token = newToken
	return newToken, nil
}

// CallUniversalAuthLogin authenticates a machine identity via universal auth.
// Uses net/http directly (not resty) since the proxy module does not depend on resty.
func CallUniversalAuthLogin(domainURL *url.URL, clientId, clientSecret string, httpClient *http.Client) (string, error) {
	loginURL := *domainURL
	loginURL.Path = domainURL.Path + "/api/v1/auth/universal-auth/login/"

	reqBody, err := json.Marshal(universalAuthLoginRequest{
		ClientId:     clientId,
		ClientSecret: clientSecret,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal login request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call universal auth login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("universal auth login returned status %d: %s", resp.StatusCode, string(body))
	}

	var loginResp universalAuthLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return "", fmt.Errorf("failed to decode login response: %w", err)
	}

	return loginResp.AccessToken, nil
}

// SSEConnection represents a single SSE connection for a project.
// One connection per project tracks all environments automatically.
type SSEConnection struct {
	ProjectID       string
	EnvironmentSlug string
	Cancel          context.CancelFunc
}

type pollingState struct {
	cancel      context.CancelFunc
	retryingSSE bool // true while a background SSE reconnection attempt is in progress
}

// SSEManager manages demand-driven SSE connections. Connections are opened when
// user requests hit secrets endpoints, not eagerly at startup.
// When SSE connections fail repeatedly for a project, the manager transitions
// that project to a polling fallback and tracks it in pollingProjects.
type SSEManager struct {
	mu                      sync.Mutex
	connections             map[string]*SSEConnection // active SSE connections
	pollingProjects         map[string]*pollingState  // projects in polling fallback
	cache                   *Cache
	domainURL               *url.URL
	httpClient              *http.Client // streaming client (no timeout) for SSE connections
	resyncHttpClient        *http.Client // regular client (with timeout) for cache resync requests
	authState               *SSEAuthState
	pollingFallbackInterval time.Duration
	ctx                     context.Context
}

func NewSSEManager(ctx context.Context, cache *Cache, domainURL *url.URL, httpClient *http.Client, resyncHttpClient *http.Client, authState *SSEAuthState, pollingFallbackInterval time.Duration) *SSEManager {
	return &SSEManager{
		connections:             make(map[string]*SSEConnection),
		pollingProjects:         make(map[string]*pollingState),
		cache:                   cache,
		domainURL:               domainURL,
		httpClient:              httpClient,
		resyncHttpClient:        resyncHttpClient,
		authState:               authState,
		pollingFallbackInterval: pollingFallbackInterval,
		ctx:                     ctx,
	}
}

// EnsureSubscription ensures an SSE connection exists for the given projectId.
// One connection per project tracks all environments, so only the projectId matters.
// If the connection is not established, the connection fall back to polling fallback
func (m *SSEManager) EnsureSubscription(projectId, environmentSlug string) {
	log.Info().Str("projectId", projectId).Msg("Ensuring SSE subscription for project")
	if projectId == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// SSE connection already active — nothing to do
	if m.connections[projectId] != nil {
		log.Info().Str("projectId", projectId).Msg("SSE connection already exists for project, skipping")
		return
	}

	// the project is in polling fallback mode
	// try to connect using SSE
	if ps, ok := m.pollingProjects[projectId]; ok {
		if !ps.retryingSSE {
			ps.retryingSSE = true
			log.Info().Str("projectId", projectId).Str("envSlug", environmentSlug).Msg("Project in polling fallback, attempting SSE reconnection in background")
			go m.attemptSSEReconnection(projectId, environmentSlug)
		}
		return
	}

	log.Info().
		Str("projectId", projectId).
		Msg("Opening new SSE connection for project")

	connCtx, connCancel := context.WithCancel(m.ctx)
	conn := &SSEConnection{
		ProjectID:       projectId,
		EnvironmentSlug: environmentSlug,
		Cancel:          connCancel,
	}
	m.connections[projectId] = conn

	go m.runConnection(conn, connCtx)
}

// runConnection runs a single SSE connection with retry, cache resync, and backoff.
// if the connection is not stablished, the connection fall back to polling fallback
func (m *SSEManager) runConnection(conn *SSEConnection, ctx context.Context) {
	const (
		maxRetries      = 5
		baseDelay       = 2 * time.Second
		maxDelay        = 60 * time.Second
		healthyDuration = 30 * time.Second
	)

	retries := 0

	for {
		if ctx.Err() != nil {
			return
		}

		connStart := time.Now()

		err := connectSSEForProject(ctx, m.cache, m.domainURL, m.authState, m.httpClient, m.resyncHttpClient, m.cancelPollingIfActive, conn.ProjectID)
		if ctx.Err() != nil {
			return
		}

		// Connection stayed up long enough — reset retry counter and cancel polling if active
		if time.Since(connStart) > healthyDuration {
			retries = 0
			m.cancelPollingIfActive(conn.ProjectID)
		}

		if err == nil {
			// Stream closed cleanly, reconnect immediately
			continue
		}

		retries++
		if retries > maxRetries {
			log.Warn().
				Str("projectId", conn.ProjectID).
				Int("maxRetries", maxRetries).
				Msg("SSE connection retries exhausted, transitioning to polling fallback")

			// the fallback to pooling only happens if the SSE connection is lost for a project
			m.transitionToPolling(conn.ProjectID, conn.EnvironmentSlug)
			return
		}

		// move the retry counter to the top, since it is possible
		// to the be authenticated, but don't have the necessary roles
		if isAuthError(err) {
			log.Warn().Err(err).
				Str("projectId", conn.ProjectID).
				Msg("SSE auth error, re-authenticating...")

			if _, authErr := m.authState.UniversalAuthLogin(); authErr == nil {
				log.Info().Str("projectId", conn.ProjectID).
					Msg("Machine identity re-authenticated successfully")
				continue
			}
			log.Error().Str("projectId", conn.ProjectID).
				Msg("Failed to re-authenticate machine identity")

		}

		log.Warn().Err(err).
			Str("projectId", conn.ProjectID).
			Int("retry", retries).
			Int("maxRetries", maxRetries).
			Msg("SSE connection lost, resyncing cache before retrying")

		// Exponential backoff with jitter
		delay := baseDelay * time.Duration(math.Pow(2, float64(retries-1)))

		if delay > maxDelay {
			delay = maxDelay
		}
		jitter := time.Duration(rand.Int63n(int64(delay) / 2))
		select {
		case <-time.After(delay + jitter):
		case <-ctx.Done():
			return
		}
	}
}

// transitionToPolling moves a project from SSE mode to polling fallback.
func (m *SSEManager) transitionToPolling(projectId, environmentSlug string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove SSE connection
	delete(m.connections, projectId)

	if ps, alreadyPolling := m.pollingProjects[projectId]; alreadyPolling {
		// Already polling — this was a reconnection attempt that failed
		ps.retryingSSE = false
		log.Info().Str("projectId", projectId).Str("envSlug", environmentSlug).
			Msg("SSE reconnection failed, continuing existing polling fallback")
		return
	}

	pollCtx, pollCancel := context.WithCancel(m.ctx)
	m.pollingProjects[projectId] = &pollingState{
		cancel:      pollCancel,
		retryingSSE: false,
	}

	log.Info().Str("projectId", projectId).Str("envSlug", environmentSlug).
		Msg("Starting polling fallback for project")

	// Resync the project cache immediately — events might have been missed during the outage
	go runProjectSecretsRefresh(m.cache, m.domainURL, m.resyncHttpClient, projectId, environmentSlug)

	// On each polling tick (except the first), attempt SSE reconnection
	retrySSE := func() {
		m.mu.Lock()
		ps, ok := m.pollingProjects[projectId]
		if !ok || ps.retryingSSE {
			m.mu.Unlock()
			return
		}
		ps.retryingSSE = true
		m.mu.Unlock()
		go m.attemptSSEReconnection(projectId, environmentSlug)
	}

	go startProjectPollingLoop(pollCtx, m.cache, m.domainURL, m.resyncHttpClient, projectId, environmentSlug, m.pollingFallbackInterval, retrySSE)
}

func (m *SSEManager) cancelPollingIfActive(projectId string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ps, ok := m.pollingProjects[projectId]; ok {
		ps.cancel()
		delete(m.pollingProjects, projectId)
		log.Info().Str("projectId", projectId).Msg("Cancelled polling fallback")
	}

}

// attemptSSEReconnection tries to re-establish an SSE connection for a project
// that is currently in polling fallback mode.
func (m *SSEManager) attemptSSEReconnection(projectId, environmentSlug string) {
	log.Info().Str("projectId", projectId).Str("envSlug", environmentSlug).Msg("Attempting SSE reconnection from polling fallback")

	m.mu.Lock()

	// Re-check state: if another goroutine already created a connection, bail out
	if m.connections[projectId] != nil {
		if ps, ok := m.pollingProjects[projectId]; ok {
			ps.retryingSSE = false
		}
		m.mu.Unlock()
		return
	}

	connCtx, connCancel := context.WithCancel(m.ctx)
	conn := &SSEConnection{
		ProjectID:       projectId,
		EnvironmentSlug: environmentSlug,
		Cancel:          connCancel,
	}
	m.connections[projectId] = conn
	m.mu.Unlock()

	m.runConnection(conn, connCtx)
}

type sseAuthError struct {
	statusCode int
}

func (e *sseAuthError) Error() string {
	return fmt.Sprintf("SSE subscription returned auth error status %d", e.statusCode)
}

func isAuthError(err error) bool {
	var authErr *sseAuthError

	return errors.As(err, &authErr)
}

// connectSSEForProject establishes a single SSE connection for one project and processes events.
// One connection per project tracks all environments automatically.
func connectSSEForProject(ctx context.Context, cache *Cache, domainURL *url.URL, authState *SSEAuthState, httpClient *http.Client, resyncHttpClient *http.Client, cancelPolling func(projectId string), projectId string) error {
	subscribeURL := *domainURL
	subscribeURL.Path = domainURL.Path + "/api/v1/events/subscribe/project-events"

	reqBody, err := json.Marshal(SSESubscriptionRequest{
		ProjectId: projectId,
		Register: []SSESubscriptionRegisterItem{
			{Event: SSEEventSecretCreate},
			{Event: SSEEventSecretUpdate},
			{Event: SSEEventSecretDelete},
			{Event: SSEEventSecretImportMutation},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal SSE subscription request: %w", err)
	}

	token := authState.GetToken()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, subscribeURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create SSE subscription request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	log.Info().
		Str("projectId", projectId).
		Msg("Subscribing to SSE events")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &sseAuthError{statusCode: resp.StatusCode}
	}

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read SSE subscription response body: %w", err)
		}
		return fmt.Errorf("SSE subscription returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Info().
		Str("projectId", projectId).
		Msg("SSE connection established")

	// cancel the polling fallback if active
	cancelPolling(projectId)

	events := make(chan SSEEvent, 10)
	go parseSSEStream(ctx, resp.Body, projectId, events)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-events:
			if !ok {
				return fmt.Errorf("SSE stream closed for project %s", projectId)
			}
			handleSSEEvent(ctx, cache, domainURL, resyncHttpClient, event)
		}
	}
}

// parseSSEStream reads from an io.Reader and emits SSEEvent values on a channel.
// Implements the standard SSE protocol: "event:" lines set the type, "data:" lines set the payload,
// blank lines delimit events. The JSON body carries a nested structure with the event type and
// a payload array; each payload item becomes a separate SSEEvent on the channel.
func parseSSEStream(ctx context.Context, reader io.Reader, projectId string, events chan<- SSEEvent) {
	defer close(events)

	scanner := bufio.NewScanner(reader)
	var currentData strings.Builder

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()

		if line == "" {
			if currentData.Len() > 0 {
				var raw sseRawMessage
				if err := json.Unmarshal([]byte(currentData.String()), &raw); err != nil {
					log.Error().Err(err).
						Str("rawData", currentData.String()).
						Msg("Failed to parse SSE event data")
				} else {
					eventType := SSEEventType(raw.Data.EventType)
					for _, item := range raw.Data.Payload {
						events <- SSEEvent{
							EventType: eventType,
							Data: SSEEventData{
								Environment: item.Environment,
								SecretPath:  item.SecretPath,
								SecretKey:   item.SecretKey,
								ProjectId:   projectId,
							},
						}
					}
				}
			}
			currentData.Reset()
			continue
		}

		if strings.HasPrefix(line, "data:") {
			currentData.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}

	if err := scanner.Err(); err != nil {
		log.Error().Err(err).Msg("SSE stream scanner error")
	}
}

// handleSSEEvent processes a single SSE event and performs cache operations.
func handleSSEEvent(ctx context.Context, cache *Cache, domainURL *url.URL, resyncHttpClient *http.Client, event SSEEvent) {
	secretPath := event.Data.SecretPath
	if secretPath == "" {
		secretPath = "/"
	}

	log.Info().
		Str("eventType", string(event.EventType)).
		Str("projectId", event.Data.ProjectId).
		Str("environment", event.Data.Environment).
		Str("secretPath", secretPath).
		Str("secretKey", event.Data.SecretKey).
		Msg("Processing SSE event")

	switch event.EventType {
	case SSEEventSecretDelete:
		purged := cache.PurgeByMutation(event.Data.ProjectId, event.Data.Environment, secretPath)
		log.Info().Int("purgedCount", purged).Msg("Cache entries purged after secret deletion")

	case SSEEventSecretCreate, SSEEventSecretUpdate:
		collected := cache.CollectAndPurgeByMutation(event.Data.ProjectId, event.Data.Environment, secretPath)
		log.Info().Int("purgedCount", len(collected)).Msg("Cache entries purged, refetching...")
		if len(collected) > 0 {
			go refetchSecretsAfterSSEEvent(ctx, cache, domainURL, resyncHttpClient, collected)
		}

	case SSEEventSecretImportMutation:
		purged := cache.PurgeByMutation(event.Data.ProjectId, event.Data.Environment, secretPath)
		log.Info().Int("purgedCount", purged).Msg("Cache entries purged after import mutation")

	default:
		// ping event
		log.Warn().
			Str("eventType", string(event.EventType)).
			Msg("Unknown SSE event type, ignoring")
	}
}

// refetchSecretsAfterSSEEvent replays the original cached requests to repopulate the cache.
// Each collected entry is re-fetched using its original token and request, preserving
// per-user cache entries rather than using the SSE machine identity token.
func refetchSecretsAfterSSEEvent(ctx context.Context, cache *Cache, domainURL *url.URL, httpClient *http.Client, collectedEntries []CollectedCacheEntry) {
	refetched := 0
	failed := 0

	for _, entry := range collectedEntries {
		// Add jitter to avoid bursts
		time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
		proxyReq, err := reconstructProxyRequest(domainURL, entry.Request)
		if err != nil {
			log.Error().Err(err).
				Str("cacheKey", entry.CacheKey).
				Str("requestURI", entry.Request.RequestURI).
				Msg("Failed to reconstruct request during SSE refetch")
			failed++
			continue
		}

		resp, err := httpClient.Do(proxyReq)
		if err != nil {
			log.Error().Err(err).
				Str("cacheKey", entry.CacheKey).
				Str("requestURI", entry.Request.RequestURI).
				Msg("Network error during SSE refetch")
			failed++
			continue
		}

		if resp.StatusCode == http.StatusOK {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				log.Error().Err(readErr).
					Str("cacheKey", entry.CacheKey).
					Msg("Failed to read response body during SSE refetch")
				failed++
				continue
			}

			cachedResp := &http.Response{
				StatusCode: resp.StatusCode,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
			}
			CopyHeaders(cachedResp.Header, resp.Header)

			cache.Set(entry.CacheKey, proxyReq, cachedResp, entry.Token, entry.IndexEntry)
			refetched++
		} else {
			resp.Body.Close()
			log.Warn().
				Int("statusCode", resp.StatusCode).
				Str("cacheKey", entry.CacheKey).
				Str("requestURI", entry.Request.RequestURI).
				Msg("Non-OK status during SSE refetch, skipping cache repopulation")
			failed++
		}
	}

	log.Info().
		Int("refetched", refetched).
		Int("failed", failed).
		Int("total", len(collectedEntries)).
		Msg("SSE refetch completed")
}
