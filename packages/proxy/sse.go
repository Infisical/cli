package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	ProjectId string                        `json:"projectId"`
	Register  []SSESubscriptionRegisterItem `json:"register"`
}

type SSESubscriptionRegisterItem struct {
	EnvironmentSlug string `json:"environmentSlug"`
	SecretPath      string `json:"secretPath" default:"/"`
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
}

func NewSSEAuthState(token, clientId, clientSecret string, domainURL *url.URL) *SSEAuthState {
	return &SSEAuthState{
		token:        token,
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

var errCacheEmpty = errors.New("cache is empty, no projects/environments to subscribe to")

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

	resp, err := http.Post(loginURL.String(), "application/json", bytes.NewReader(reqBody))
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

// StartSSEListener starts the SSE event listener with exponential backoff reconnection.
// It connects to the Infisical SSE endpoint and processes events to invalidate/refresh the cache.
// On 401/403, it re-authenticates using the provided client credentials.
func StartSSEListener(ctx context.Context, cache *Cache, domainURL *url.URL, initialToken string, httpClient *http.Client, clientId, clientSecret string) {
	const (
		baseDelay = 1 * time.Second
		maxDelay  = 60 * time.Second
	)

	authState := NewSSEAuthState(initialToken, clientId, clientSecret, domainURL)
	currentDelay := baseDelay

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("SSE listener stopped")
			return
		default:
		}

		connStart := time.Now()
		log.Info().Msg("Connecting to SSE event stream...")

		err := connectAndProcessSSE(ctx, cache, domainURL, authState, httpClient)

		if ctx.Err() != nil {
			return
		}

		// Reset backoff if connection lasted > 30s (was a real connection, not immediate failure)
		if time.Since(connStart) > 30*time.Second {
			currentDelay = baseDelay
		}

		if err != nil {
			// Re-authenticate on auth errors
			if isAuthError(err) {
				log.Warn().Err(err).Msg("SSE auth error, re-authenticating...")
				newToken, authErr := authState.RefreshToken()
				if authErr != nil {
					log.Error().Err(authErr).Msg("Failed to re-authenticate machine identity")
				} else {
					_ = newToken
					log.Info().Msg("Machine identity re-authenticated successfully")
					currentDelay = baseDelay
					continue
				}
			}

			log.Error().Err(err).
				Str("retryIn", currentDelay.String()).
				Msg("SSE connection failed, will retry")
		}

		// Exponential backoff with jitter
		jitter := time.Duration(rand.Int63n(int64(currentDelay) / 2))
		select {
		case <-time.After(currentDelay + jitter):
		case <-ctx.Done():
			return
		}

		currentDelay *= 2
		if currentDelay > maxDelay {
			currentDelay = maxDelay
		}
	}
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

// connectAndProcessSSE establishes SSE connections for all cached projects and blocks until they all disconnect.
func connectAndProcessSSE(ctx context.Context, cache *Cache, domainURL *url.URL, authState *SSEAuthState, httpClient *http.Client) error {
	projects := cache.GetUniqueProjectEnvironments()
	if len(projects) == 0 {
		log.Info().Msg("No cached projects/environments yet, waiting for cache to populate...")
		return errCacheEmpty
	}

	// One SSE connection per project and per, since the subscription API is per-project
	sseCtx, sseCancel := context.WithCancel(ctx)
	defer sseCancel()

	var wg sync.WaitGroup
	errCh := make(chan error, len(projects))

	for projectId, envSlugs := range projects {
		wg.Add(1)
		go func(projectId string, envSlugs []string) {
			defer wg.Done()
			err := connectSSEForProject(sseCtx, cache, domainURL, authState, httpClient, projectId, envSlugs)
			if err != nil {
				errCh <- err
				sseCancel()
			}
		}(projectId, envSlugs)
	}

	wg.Wait()
	close(errCh)

	// Return the first error
	for err := range errCh {
		return err
	}
	return nil
}

// connectSSEForProject establishes a single SSE connection for one project and processes events.
func connectSSEForProject(ctx context.Context, cache *Cache, domainURL *url.URL, authState *SSEAuthState, httpClient *http.Client, projectId string, envSlugs []string) error {
	subscribeURL := *domainURL
	subscribeURL.Path = domainURL.Path + "/api/v1/events/subscribe/project-events"

	registerItems := make([]SSESubscriptionRegisterItem, 0, len(envSlugs))
	for _, env := range envSlugs {
		registerItems = append(registerItems, SSESubscriptionRegisterItem{
			EnvironmentSlug: env,
			SecretPath:      "/",
		})
	}

	reqBody, err := json.Marshal(SSESubscriptionRequest{
		ProjectId: projectId,
		Register:  registerItems,
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
		Strs("environments", envSlugs).
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
		body, _ := io.ReadAll(resp.Body)
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
			handleSSEEvent(cache, domainURL, httpClient, authState, event)
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
		// Ignore "id:", "retry:", and comment lines (starting with ":")
	}

	if err := scanner.Err(); err != nil {
		log.Error().Err(err).Msg("SSE stream scanner error")
	}
}

// handleSSEEvent processes a single SSE event and performs cache operations.
func handleSSEEvent(cache *Cache, domainURL *url.URL, httpClient *http.Client, authState *SSEAuthState, event SSEEvent) {
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
		refetchSecretsAfterSSEEvent(cache, domainURL, httpClient, authState, event)

	case SSEEventSecretImportMutation:
		purged := cache.PurgeByMutation(event.Data.ProjectId, event.Data.Environment, secretPath)
		log.Info().Int("purgedCount", purged).Msg("Cache entries purged after import mutation")

	default:
		log.Warn().
			Str("eventType", string(event.EventType)).
			Msg("Unknown SSE event type, ignoring")
	}
}

// refetchSecretsAfterSSEEvent fetches the created/updated secret from the Infisical API
// and stores it in the cache. Uses the machine identity token from authState.
func refetchSecretsAfterSSEEvent(cache *Cache, domainURL *url.URL, httpClient *http.Client, authState *SSEAuthState, event SSEEvent) {
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

	resp, req, err := fetchSecretFromAPI(domainURL, httpClient, authState, event.Data.SecretKey, event.Data.ProjectId, event.Data.Environment, secretPath)
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

	token := authState.GetToken()
	cacheKey := GenerateCacheKey(req.Method, req.URL.Path, req.URL.RawQuery, token)

	cachedResp := &http.Response{
		StatusCode: resp.StatusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
	}
	CopyHeaders(cachedResp.Header, resp.Header)

	// I think this can also be refactored, since this is the same approach another function already uses
	indexEntry := IndexEntry{
		CacheKey:        cacheKey,
		SecretPath:      secretPath,
		EnvironmentSlug: event.Data.Environment,
		ProjectId:       event.Data.ProjectId,
	}

	cache.Set(cacheKey, req, cachedResp, token, indexEntry)

	log.Info().
		Str("secretKey", event.Data.SecretKey).
		Str("cacheKey", cacheKey).
		Msg("Successfully refetched and cached secret after SSE event")
}

// fetchSecretFromAPI calls GET /api/v4/secrets/{secretName} with the given parameters.
// On 401/403 it refreshes the token via authState and retries once.
// Returns the final HTTP response and the request used (for cache key generation).
func fetchSecretFromAPI(domainURL *url.URL, httpClient *http.Client, authState *SSEAuthState, secretName, projectId, environment, secretPath string) (*http.Response, *http.Request, error) {
	resp, req, err := doSecretGET(domainURL, httpClient, authState.GetToken(), secretName, projectId, environment, secretPath)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		log.Warn().Msg("Auth error during SSE refetch, refreshing token...")
		if _, authErr := authState.RefreshToken(); authErr != nil {
			log.Error().Err(authErr).Msg("Failed to refresh token during SSE refetch")
			return nil, nil, authErr
		}
		resp, req, err = doSecretGET(domainURL, httpClient, authState.GetToken(), secretName, projectId, environment, secretPath)
		if err != nil {
			return nil, nil, err
		}
	}
	return resp, req, nil
}

func doSecretGET(domainURL *url.URL, httpClient *http.Client, token, secretName, projectId, environment, secretPath string) (*http.Response, *http.Request, error) {
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
