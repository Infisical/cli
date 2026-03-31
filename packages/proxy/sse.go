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

type SSESubscriptionRequest struct {
	ProjectId string `json:"projectId"`
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

// SSESecretCacheFunc is a callback invoked after an SSE event fetches a secret from the API.
// It receives the request, response body, and event data so the caller can cache the result
// using the same approach as regular proxy requests.
type SSESecretCacheFunc func(req *http.Request, resp *http.Response, bodyBytes []byte, event SSEEvent)

// SSEAuthState manages authentication state for SSE operations.
// It holds a reusable token and credentials for re-authentication.
type SSEAuthState struct {
	mu           sync.RWMutex
	token        string
	clientId     string
	clientSecret string
	domainURL    *url.URL
}

func NewSSEAuthState(clientId, clientSecret string, domainURL *url.URL) *SSEAuthState {
	return &SSEAuthState{
		clientId:     clientId,
		clientSecret: clientSecret,
		domainURL:    domainURL,
	}
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

func (s *SSEAuthState) RefreshToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newToken, err := CallUniversalAuthLogin(s.domainURL, s.clientId, s.clientSecret)
	if err != nil {
		return "", err
	}
	s.token = newToken
	return newToken, nil
}

// CallUniversalAuthLogin authenticates a machine identity via universal auth.
// Uses net/http directly (not resty) since the proxy module does not depend on resty.
func CallUniversalAuthLogin(domainURL *url.URL, clientId, clientSecret string) (string, error) {
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

	resp, err := http.DefaultClient.Do(req)
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
	ProjectID string
	Cancel    context.CancelFunc
}

// SSEManager manages demand-driven SSE connections. Connections are opened when
// user requests hit secrets endpoints, not eagerly at startup.
type SSEManager struct {
	mu               sync.Mutex
	connections      map[string]*SSEConnection // keyed by projectID
	cache            *Cache
	domainURL        *url.URL
	httpClient       *http.Client // streaming client (no timeout) for SSE connections
	resyncHttpClient *http.Client // regular client (with timeout) for cache resync requests
	authState        *SSEAuthState
	onSecretFetched  SSESecretCacheFunc
	ctx              context.Context
}

func NewSSEManager(ctx context.Context, cache *Cache, domainURL *url.URL, httpClient *http.Client, resyncHttpClient *http.Client, authState *SSEAuthState, onSecretFetched SSESecretCacheFunc) *SSEManager {
	return &SSEManager{
		connections:      make(map[string]*SSEConnection),
		cache:            cache,
		domainURL:        domainURL,
		httpClient:       httpClient,
		resyncHttpClient: resyncHttpClient,
		authState:        authState,
		onSecretFetched:  onSecretFetched,
		ctx:              ctx,
	}
}

// EnsureSubscription ensures an SSE connection exists for the given projectId.
// One connection per project tracks all environments, so only the projectId matters.
// Called from the proxy handler when a secrets request is seen.
func (m *SSEManager) EnsureSubscription(projectId string) {
	if projectId == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// connection already exists for that projectId, so we don't need to open a new one
	if m.connections[projectId] != nil {
		return
	}

	log.Info().
		Str("projectId", projectId).
		Msg("Opening new SSE connection for project")

	connCtx, connCancel := context.WithCancel(m.ctx)
	conn := &SSEConnection{
		ProjectID: projectId,
		Cancel:    connCancel,
	}
	m.connections[projectId] = conn

	go m.runConnection(conn, connCtx)
}

// runConnection runs a single SSE connection with retry, cache resync, and backoff.
// After maxRetries consecutive failures the connection is removed so the next user
// request can re-trigger EnsureSubscription.
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

		err := connectSSEForProject(ctx, m.cache, m.domainURL, m.authState, m.httpClient, conn.ProjectID, m.onSecretFetched)
		if ctx.Err() != nil {
			return
		}

		// Connection stayed up long enough — reset retry counter
		if time.Since(connStart) > healthyDuration {
			retries = 0
		}

		if err == nil {
			// Stream closed cleanly, reconnect immediately
			continue
		}

		// Handle auth errors with one re-auth attempt
		if isAuthError(err) {
			log.Warn().Err(err).
				Str("projectId", conn.ProjectID).
				Msg("SSE auth error, re-authenticating...")

			if _, authErr := m.authState.RefreshToken(); authErr == nil {
				log.Info().Str("projectId", conn.ProjectID).
					Msg("Machine identity re-authenticated successfully")
				continue
			}
			log.Error().Str("projectId", conn.ProjectID).
				Msg("Failed to re-authenticate machine identity")
		}

		retries++
		if retries > maxRetries {
			log.Error().
				Str("projectId", conn.ProjectID).
				Int("maxRetries", maxRetries).
				Msg("SSE connection retries exhausted, removing connection")
			m.removeConnection(conn.ProjectID)
			return
		}

		log.Warn().Err(err).
			Str("projectId", conn.ProjectID).
			Int("retry", retries).
			Int("maxRetries", maxRetries).
			Msg("SSE connection lost, resyncing cache before retrying")

		// Resync cache before reconnecting — we may have missed events during the outage
		runStaticSecretsRefresh(m.cache, m.domainURL, m.resyncHttpClient, 0)

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

// removeConnection removes a connection from the map so the next user request
// can re-trigger EnsureSubscription for this project.
func (m *SSEManager) removeConnection(projectId string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.connections, projectId)
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
func connectSSEForProject(ctx context.Context, cache *Cache, domainURL *url.URL, authState *SSEAuthState, httpClient *http.Client, projectId string, onSecretFetched SSESecretCacheFunc) error {
	subscribeURL := *domainURL
	subscribeURL.Path = domainURL.Path + "/api/v1/events/subscribe/project-events"

	reqBody, err := json.Marshal(SSESubscriptionRequest{
		ProjectId: projectId,
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

	events := make(chan SSEEvent, 10)
	go parseSSEStream(ctx, resp.Body, events)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-events:
			if !ok {
				return fmt.Errorf("SSE stream closed for project %s", projectId)
			}
			handleSSEEvent(cache, domainURL, httpClient, authState, event, onSecretFetched)
		}
	}
}

// parseSSEStream reads from an io.Reader and emits SSEEvent values on a channel.
// Implements the standard SSE protocol: "event:" lines set the type, "data:" lines set the payload,
// blank lines delimit events.
func parseSSEStream(ctx context.Context, reader io.Reader, events chan<- SSEEvent) {
	defer close(events)

	scanner := bufio.NewScanner(reader)
	var currentEvent string
	var currentData strings.Builder

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()

		if line == "" {
			// Blank line = event delimiter
			if currentData.Len() > 0 && currentEvent != "" {
				var data SSEEventData
				if err := json.Unmarshal([]byte(currentData.String()), &data); err != nil {
					log.Error().Err(err).
						Str("eventType", currentEvent).
						Str("rawData", currentData.String()).
						Msg("Failed to parse SSE event data")
				} else {
					events <- SSEEvent{
						EventType: SSEEventType(currentEvent),
						Data:      data,
					}
				}
			}
			currentEvent = ""
			currentData.Reset()
			continue
		}

		if strings.HasPrefix(line, "event:") {
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			currentData.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}

	if err := scanner.Err(); err != nil {
		log.Error().Err(err).Msg("SSE stream scanner error")
	}
}

// handleSSEEvent processes a single SSE event and performs cache operations.
func handleSSEEvent(cache *Cache, domainURL *url.URL, httpClient *http.Client, authState *SSEAuthState, event SSEEvent, onSecretFetched SSESecretCacheFunc) {
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
		purged := cache.PurgeByMutation(event.Data.ProjectId, event.Data.Environment, secretPath)
		log.Info().Int("purgedCount", purged).Msg("Cache entries purged, refetching...")
		refetchSecretsAfterSSEEvent(domainURL, httpClient, authState, event, onSecretFetched)

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

// refetchSecretsAfterSSEEvent fetches the created/updated secret from the Infisical API
// and delegates caching to the onSecretFetched callback.
func refetchSecretsAfterSSEEvent(domainURL *url.URL, httpClient *http.Client, authState *SSEAuthState, event SSEEvent, onSecretFetched SSESecretCacheFunc) {
	if event.Data.SecretKey == "" {
		log.Warn().
			Str("eventType", string(event.EventType)).
			Msg("SSE event missing secretKey, cannot refetch")
		return
	}

	secretPath := event.Data.SecretPath
	if secretPath == "" {
		secretPath = "/"
	}

	// This is performing the same request a user would perform when they access the secret directly
	resp, req, err := getSecretByName(domainURL, httpClient, authState.GetToken(), event.Data.SecretKey, event.Data.ProjectId, event.Data.Environment, secretPath)
	if err != nil {
		log.Error().Err(err).
			Str("secretKey", event.Data.SecretKey).
			Msg("Failed to fetch secret after SSE event")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Warn().
			Int("statusCode", resp.StatusCode).
			Str("secretKey", event.Data.SecretKey).
			Str("response", string(body)).
			Msg("Unexpected status during SSE refetch")
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read refetch response body")
		return
	}

	onSecretFetched(req, resp, bodyBytes, event)
}

func getSecretByName(domainURL *url.URL, httpClient *http.Client, token, secretName, projectId, environment, secretPath string) (*http.Response, *http.Request, error) {
	secretURL := *domainURL
	secretURL.Path = domainURL.Path + "/api/v4/secrets/" + url.PathEscape(secretName)

	query := url.Values{}
	query.Set("projectId", projectId)
	if environment != "" {
		query.Set("environment", environment)
	}
	if secretPath != "" {
		query.Set("secretPath", secretPath)
	}
	secretURL.RawQuery = query.Encode()

	req, err := http.NewRequest(http.MethodGet, secretURL.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create secret fetch request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch secret: %w", err)
	}

	return resp, req, nil
}
