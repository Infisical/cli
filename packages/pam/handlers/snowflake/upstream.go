package snowflake

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// The gateway's own client for Snowflake's REST API. Only login and query are implemented, which is all
// a proxied session does; stage file transfer and the Arrow result format are deliberately unsupported.
type upstream struct {
	config     SnowflakeProxyConfig
	client     *http.Client
	baseURL    string
	mu         sync.Mutex
	token      string
	masterTok  string
	requestID  string
	sessionCtx map[string]string
	parameters json.RawMessage
}

type upstreamEnvelope struct {
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
	Code    string          `json:"code"`
	Success bool            `json:"success"`
}

type loginResponse struct {
	Token       string          `json:"token"`
	MasterToken string          `json:"masterToken"`
	Parameters  json.RawMessage `json:"parameters"`
	SessionInfo struct {
		DatabaseName  string `json:"databaseName"`
		SchemaName    string `json:"schemaName"`
		WarehouseName string `json:"warehouseName"`
		RoleName      string `json:"roleName"`
	} `json:"sessionInfo"`
}

type resultChunk struct {
	URL      string `json:"url"`
	RowCount int    `json:"rowCount"`
}

type queryResponse struct {
	GetResultURL      string            `json:"getResultUrl"`
	QueryID           string            `json:"queryId"`
	RowType           []column          `json:"rowtype"`
	RowSet            [][]any           `json:"rowset"`
	Total             int64             `json:"total"`
	Chunks            []resultChunk     `json:"chunks"`
	ChunkHeaders      map[string]string `json:"chunkHeaders"`
	QueryResultFormat string            `json:"queryResultFormat"`
}

func newUpstream(config SnowflakeProxyConfig) *upstream {
	return &upstream{
		config:  config,
		baseURL: fmt.Sprintf("https://%s.snowflakecomputing.com", config.Account),
		client:  &http.Client{Transport: snowflakeTransport(), Timeout: statementTimeout},
	}
}

func (u *upstream) login(ctx context.Context) error {
	data := map[string]any{
		"CLIENT_APP_ID":      "Go",
		"CLIENT_APP_VERSION": "1.19.1",
		"SVN_REVISION":       "",
		"ACCOUNT_NAME":       u.config.Account,
		"LOGIN_NAME":         u.config.Username,
		"CLIENT_ENVIRONMENT": map[string]any{
			"APPLICATION":      "Infisical",
			"APPLICATION_PATH": "",
			"OS":               runtime.GOOS,
			"OS_VERSION":       runtime.GOARCH,
			"OCSP_MODE":        "FAIL_OPEN",
			"GO_VERSION":       runtime.Version(),
		},
		// JSON keeps results parseable without the Arrow decoder the official driver pulls in
		"SESSION_PARAMETERS": map[string]any{"CLIENT_RESULT_FORMAT": "JSON", "GO_QUERY_RESULT_FORMAT": "json"},
	}

	switch u.config.AuthMethod {
	case AuthMethodKeyPair:
		assertion, err := u.keyPairAssertion()
		if err != nil {
			return err
		}
		data["AUTHENTICATOR"] = "SNOWFLAKE_JWT"
		data["TOKEN"] = assertion
	case AuthMethodToken:
		data["AUTHENTICATOR"] = "PROGRAMMATIC_ACCESS_TOKEN"
		data["TOKEN"] = u.config.Token
		data["PASSWORD"] = u.config.Token
	default:
		data["PASSWORD"] = u.config.Password
	}

	params := url.Values{}
	for name, value := range map[string]string{
		"databaseName": u.config.Database,
		"schemaName":   u.config.Schema,
		"warehouse":    u.config.Warehouse,
		"roleName":     u.config.Role,
	} {
		if value != "" {
			params.Set(name, value)
		}
	}

	envelope, err := u.post(ctx, "/session/v1/login-request", params, map[string]any{"data": data}, false)
	if err != nil {
		return err
	}

	var parsed loginResponse
	if err := json.Unmarshal(envelope.Data, &parsed); err != nil {
		return fmt.Errorf("could not read the Snowflake login response: %w", err)
	}

	u.token, u.masterTok, u.parameters = parsed.Token, parsed.MasterToken, parsed.Parameters
	u.sessionCtx = map[string]string{
		"databaseName":  parsed.SessionInfo.DatabaseName,
		"schemaName":    parsed.SessionInfo.SchemaName,
		"warehouseName": parsed.SessionInfo.WarehouseName,
		"roleName":      parsed.SessionInfo.RoleName,
	}
	return nil
}

// Snowflake identifies a key pair by the SHA-256 fingerprint of its public key, carried in the issuer.
func (u *upstream) keyPairAssertion() (string, error) {
	key, err := parsePrivateKey(u.config.PrivateKey, u.config.PrivateKeyPass)
	if err != nil {
		return "", err
	}

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("could not read the public key: %w", err)
	}
	digest := sha256.Sum256(der)
	fingerprint := "SHA256:" + base64.StdEncoding.EncodeToString(digest[:])

	account := strings.ToUpper(strings.Split(u.config.Account, ".")[0])
	subject := fmt.Sprintf("%s.%s", account, strings.ToUpper(u.config.Username))

	return jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    fmt.Sprintf("%s.%s", subject, fingerprint),
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).SignedString(key)
}

// Bindings are passed through untouched: a prepared statement from a JDBC client carries its parameters
// here, and dropping them makes every parameterised query fail.
func (u *upstream) query(ctx context.Context, statement string, bindings json.RawMessage) (*queryResult, error) {
	started := time.Now()
	body := map[string]any{"sqlText": statement, "asyncExec": false, "sequenceId": 1, "isInternal": false}
	if len(bindings) > 0 && string(bindings) != "null" {
		body["bindings"] = bindings
	}

	// Kept so a cancellation can name this statement to Snowflake
	requestID := uuid.NewString()
	params := url.Values{}
	params.Set("requestId", requestID)
	u.mu.Lock()
	u.requestID = requestID
	u.mu.Unlock()

	envelope, err := u.post(ctx, "/queries/v1/query-request", params, body, true)
	// Snowflake expires a session token roughly hourly, well inside a long PAM session
	if isSessionExpired(err) {
		if renewErr := u.renew(ctx); renewErr != nil {
			return nil, renewErr
		}
		envelope, err = u.post(ctx, "/queries/v1/query-request", params, body, true)
	}
	if err != nil {
		return nil, err
	}

	parsed, err := decodeQueryResponse(envelope)
	if err != nil {
		return nil, err
	}

	// A query slower than about 45 seconds comes back "in progress" with a URL to poll until it lands
	for envelope.Code == queryInProgressCode || envelope.Code == queryInProgressAsyncCode {
		if parsed.GetResultURL == "" {
			return nil, fmt.Errorf("Snowflake reported the query as running but gave no result URL")
		}
		if envelope, err = u.get(ctx, parsed.GetResultURL); err != nil {
			return nil, err
		}
		if parsed, err = decodeQueryResponse(envelope); err != nil {
			return nil, err
		}
	}

	if format := strings.ToLower(parsed.QueryResultFormat); format != "" && format != "json" {
		return nil, fmt.Errorf("Snowflake returned an unsupported result format (%s)", format)
	}

	result := &queryResult{columns: parsed.RowType, rows: parsed.RowSet, queryID: parsed.QueryID}
	if result.rows == nil {
		result.rows = [][]any{}
	}

	// Rows past the first slice live in pre-signed object storage. The gateway fetches them so the data
	// stays on its side of the tunnel rather than flowing straight to the client.
	for _, chunk := range parsed.Chunks {
		if len(result.rows) >= maxRows {
			break
		}
		rows, err := u.fetchChunk(ctx, chunk, parsed.ChunkHeaders)
		if err != nil {
			return nil, err
		}
		result.rows = append(result.rows, rows...)
	}

	if len(result.rows) > maxRows {
		result.rows = result.rows[:maxRows]
	}
	result.truncated = int64(len(result.rows)) < parsed.Total
	result.elapsed = time.Since(started)
	return result, nil
}

// Snowflake keeps running a statement the client walked away from, and the warehouse bills for it.
func (u *upstream) abortQuery(ctx context.Context) error {
	u.mu.Lock()
	requestID := u.requestID
	u.mu.Unlock()
	if requestID == "" {
		return nil
	}

	_, err := u.post(ctx, "/queries/v1/abort-request", url.Values{}, map[string]string{"requestId": requestID}, true)
	return err
}

func (u *upstream) logout(ctx context.Context) error {
	params := url.Values{}
	params.Set("delete", "true")
	_, err := u.post(ctx, "/session", params, map[string]any{}, true)
	return err
}

func decodeQueryResponse(envelope *upstreamEnvelope) (*queryResponse, error) {
	var parsed queryResponse
	if err := json.Unmarshal(envelope.Data, &parsed); err != nil {
		return nil, fmt.Errorf("could not read the Snowflake response: %w", err)
	}
	return &parsed, nil
}

func (u *upstream) get(ctx context.Context, path string) (*upstreamEnvelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	token := u.token
	u.mu.Unlock()
	req.Header.Set("Authorization", fmt.Sprintf(`Snowflake Token="%s"`, token))
	req.Header.Set("Accept", "application/json")

	return u.send(req)
}

func (u *upstream) fetchChunk(ctx context.Context, chunk resultChunk, headers map[string]string) ([][]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chunk.URL, nil)
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not fetch a result chunk: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not fetch a result chunk (HTTP %d)", resp.StatusCode)
	}

	body, err := decompress(resp)
	if err != nil {
		return nil, err
	}

	// A chunk is a bare list of rows rather than a whole envelope
	var rows [][]any
	if err := json.Unmarshal([]byte("["+strings.TrimSuffix(strings.TrimSpace(string(body)), ",")+"]"), &rows); err != nil {
		return nil, fmt.Errorf("could not read a result chunk: %w", err)
	}
	return rows, nil
}

func (u *upstream) renew(ctx context.Context) error {
	u.mu.Lock()
	master, old := u.masterTok, u.token
	u.mu.Unlock()

	envelope, err := u.post(ctx, "/session/token-request", url.Values{},
		map[string]string{"oldSessionToken": old, "requestType": "RENEW"}, false, master)
	if err != nil {
		return fmt.Errorf("the Snowflake session expired and could not be renewed: %w", err)
	}

	var parsed struct {
		SessionToken string `json:"sessionToken"`
		MasterToken  string `json:"masterToken"`
	}
	if err := json.Unmarshal(envelope.Data, &parsed); err != nil {
		return fmt.Errorf("could not read the Snowflake renewal response: %w", err)
	}

	u.mu.Lock()
	u.token, u.masterTok = parsed.SessionToken, parsed.MasterToken
	u.mu.Unlock()
	return nil
}

type snowflakeError struct{ code, message string }

func (e *snowflakeError) Error() string { return e.message }

func isSessionExpired(err error) bool {
	var sfErr *snowflakeError
	return errors.As(err, &sfErr) && sfErr.code == sessionExpiredCode
}

// Snowflake rejects a request without its own identifiers, so they are set on every call.
func (u *upstream) post(ctx context.Context, path string, params url.Values, body any, authenticated bool, asToken ...string) (*upstreamEnvelope, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	if params.Get("requestId") == "" {
		params.Set("requestId", uuid.NewString())
	}
	params.Set("request_guid", uuid.NewString())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.baseURL+path+"?"+params.Encode(), bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	switch {
	case len(asToken) > 0:
		req.Header.Set("Authorization", fmt.Sprintf(`Snowflake Token="%s"`, asToken[0]))
	case authenticated:
		u.mu.Lock()
		token := u.token
		u.mu.Unlock()
		req.Header.Set("Authorization", fmt.Sprintf(`Snowflake Token="%s"`, token))
	}

	return u.send(req)
}

func (u *upstream) send(req *http.Request) (*upstreamEnvelope, error) {
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach Snowflake: %w", err)
	}
	defer resp.Body.Close()

	raw, err := decompress(resp)
	if err != nil {
		return nil, err
	}

	var envelope upstreamEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("Snowflake returned an unreadable response (HTTP %d)", resp.StatusCode)
	}
	// An in-progress response is not a failure; the caller polls on it
	if !envelope.Success && envelope.Code != queryInProgressCode && envelope.Code != queryInProgressAsyncCode {
		message := strings.TrimSpace(envelope.Message)
		if message == "" {
			message = fmt.Sprintf("Snowflake refused the request (HTTP %d)", resp.StatusCode)
		}
		return nil, &snowflakeError{code: envelope.Code, message: message}
	}
	return &envelope, nil
}

func decompress(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	body, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("the Snowflake response was too large to read safely")
	}
	return body, nil
}
