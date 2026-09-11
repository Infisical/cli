package snowflake

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog/log"
)

// Snowflake has no wire protocol, so the gateway answers the REST API its drivers speak and runs each
// statement itself. The client never holds a Snowflake token, so it cannot bypass the recorded session.
type SnowflakeProxyConfig struct {
	Account        string
	Username       string
	AuthMethod     string
	Password       string
	Token          string
	PrivateKey     string
	PrivateKeyPass string
	Warehouse      string
	Database       string
	Schema         string
	Role           string

	SessionID       string
	SessionLogger   session.SessionLogger
	BlockedCommands []*regexp.Regexp
}

const (
	AuthMethodKeyPair = "key-pair"
	AuthMethodToken   = "programmatic-access-token"

	loginTimeout = 30 * time.Second

	statementTimeout = 30 * time.Minute
)

type SnowflakeProxy struct {
	config     SnowflakeProxyConfig
	upstream   *upstream
	token      string
	sessionCtx map[string]string
	parameters json.RawMessage
}

func NewSnowflakeProxy(config SnowflakeProxyConfig) *SnowflakeProxy {
	return &SnowflakeProxy{config: config}
}

func (p *SnowflakeProxy) Connect(ctx context.Context) error {
	client := newUpstream(p.config)
	loginCtx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	if err := client.login(loginCtx); err != nil {
		return err
	}

	p.upstream, p.token, p.sessionCtx, p.parameters = client, sessionToken(p.config), client.sessionCtx, client.parameters
	return nil
}

// Probe runs one statement and checks what the session actually opened with: Snowflake accepts a
// warehouse, role or database the credential can't use and just leaves it unset.
func (p *SnowflakeProxy) Probe(ctx context.Context) error {
	for _, requested := range [][3]string{
		{"warehouse", p.config.Warehouse, p.sessionCtx["warehouseName"]},
		{"role", p.config.Role, p.sessionCtx["roleName"]},
		{"database", p.config.Database, p.sessionCtx["databaseName"]},
		{"schema", p.config.Schema, p.sessionCtx["schemaName"]},
	} {
		if requested[1] != "" && !strings.EqualFold(requested[1], requested[2]) {
			return fmt.Errorf("the user cannot use the %s %q", requested[0], requested[1])
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	_, err := p.upstream.query(probeCtx, "SELECT 1", nil)
	return err
}

func (p *SnowflakeProxy) Close() {
	if p.upstream == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()
	if err := p.upstream.logout(ctx); err != nil {
		log.Debug().Err(err).Str("sessionId", p.config.SessionID).Msg("Failed to close the Snowflake session")
	}
}

func (p *SnowflakeProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	l := log.With().Str("sessionId", p.config.SessionID).Str("resourceType", "snowflake").Logger()

	server := &http.Server{
		Handler:           p.router(l),
		ReadHeaderTimeout: 30 * time.Second,
	}

	listener := newSingleConnListener(clientConn)

	go func() {
		<-ctx.Done()
		listener.Close()
		server.Close()
	}()

	if err := server.Serve(listener); err != nil && !isListenerDone(err) {
		l.Debug().Err(err).Msg("Snowflake proxy stopped")
	}
	return nil
}

func (p *SnowflakeProxy) router(l zeroLogger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/session/v1/login-request", p.handleLogin)
	mux.HandleFunc("/session/token-request", p.handleTokenRequest)
	mux.HandleFunc("/session/heartbeat", p.handleOK)
	mux.HandleFunc("/session", p.handleOK)
	mux.HandleFunc("/queries/v1/query-request", p.handleQuery(l))
	mux.HandleFunc("/queries/v1/abort-request", p.handleAbort(l))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		l.Debug().Str("path", r.URL.Path).Msg("Snowflake proxy received an unsupported request")
		writeFailure(w, errCodeUnsupported, fmt.Sprintf("This session does not support %s.", r.URL.Path))
	})
	return mux
}

func (p *SnowflakeProxy) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeFailure(w, errCodeAuth, "Unsupported method")
		return
	}

	// The gateway already authenticated, so whatever the client sent is ignored rather than forwarded
	writeEnvelope(w, envelope{Success: true, Data: loginData(p.token, p.config, p.sessionCtx, p.parameters)})
}

func (p *SnowflakeProxy) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	if !p.authorize(r) {
		writeFailure(w, errCodeAuth, "Authentication token has expired")
		return
	}
	writeEnvelope(w, envelope{Success: true, Data: renewData(p.token)})
}

func (p *SnowflakeProxy) handleOK(w http.ResponseWriter, r *http.Request) {
	writeEnvelope(w, envelope{Success: true, Data: map[string]any{}})
}

func (p *SnowflakeProxy) handleQuery(l zeroLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.authorize(r) {
			writeFailure(w, errCodeAuth, "Authentication token has expired")
			return
		}

		var body struct {
			SqlText  string          `json:"sqlText"`
			Bindings json.RawMessage `json:"bindings"`
		}
		if err := decodeRequest(w, r, &body); err != nil {
			writeFailure(w, errCodeStatement, statementReadError(err))
			return
		}

		statement := strings.TrimSpace(body.SqlText)
		if statement == "" {
			writeFailure(w, errCodeStatement, "Empty statement")
			return
		}

		if blocked := p.blockedBy(statement); blocked != nil {
			p.logStatement(statement, fmt.Sprintf("BLOCKED: %s", blocked.String()))
			l.Info().Str("pattern", blocked.String()).Msg("Blocked a statement by policy")
			writeFailure(w, errCodeStatement, "This statement is blocked by the command blocking policy on this account.")
			return
		}

		queryCtx, cancel := context.WithTimeout(r.Context(), statementTimeout)
		defer cancel()

		if key := p.inflightKey(r.URL.Query().Get("requestId")); key != "" {
			inflightQueries.Store(key, &inflightQuery{upstream: p.upstream, cancel: cancel})
			defer inflightQueries.Delete(key)
		}

		result, err := p.upstream.query(queryCtx, statement, body.Bindings)
		if err != nil {
			if queryCtx.Err() != nil {
				abortUpstream(r.Context(), p.upstream, l)
			}
			p.logStatement(statement, fmt.Sprintf("ERROR: %s", err))
			writeUpstreamFailure(w, err)
			return
		}

		p.logStatement(statement, result.summary())
		writeEnvelope(w, envelope{Success: true, Data: result.data()})
	}
}

// A driver sends its cancellation on a second connection, which the tunnel makes a second proxy, so the
// statement is found by the request id the client gave it rather than through this proxy's own state.
var inflightQueries sync.Map

type inflightQuery struct {
	upstream *upstream
	cancel   context.CancelFunc
}

func (p *SnowflakeProxy) inflightKey(requestID string) string {
	if requestID == "" {
		return ""
	}
	return p.config.SessionID + "/" + requestID
}

func (p *SnowflakeProxy) handleAbort(l zeroLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.authorize(r) {
			writeFailure(w, errCodeAuth, "Authentication token has expired")
			return
		}

		var body struct {
			RequestID string `json:"requestId"`
		}
		if err := decodeRequest(w, r, &body); err == nil {
			if entry, ok := inflightQueries.Load(p.inflightKey(body.RequestID)); ok {
				query := entry.(*inflightQuery)
				abortUpstream(r.Context(), query.upstream, l)
				query.cancel()
			}
		}

		writeEnvelope(w, envelope{Success: true, Data: map[string]any{}})
	}
}

// Detached from the request, which is often already cancelled by the time the abort is worth sending
func abortUpstream(ctx context.Context, client *upstream, l zeroLogger) {
	abortCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loginTimeout)
	defer cancel()

	if err := client.abortQuery(abortCtx); err != nil {
		l.Debug().Err(err).Msg("Snowflake refused a cancellation")
	}
}

func (p *SnowflakeProxy) authorize(r *http.Request) bool {
	presented := strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("Authorization"), `Snowflake Token="`), `"`)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(p.token)) == 1
}

func (p *SnowflakeProxy) blockedBy(statement string) *regexp.Regexp {
	for _, pattern := range p.config.BlockedCommands {
		if pattern.MatchString(statement) {
			return pattern
		}
	}
	return nil
}

func (p *SnowflakeProxy) logStatement(input, output string) {
	if p.config.SessionLogger == nil {
		return
	}
	if err := p.config.SessionLogger.LogEntry(session.SessionLogEntry{
		Timestamp: time.Now(),
		Input:     input,
		Output:    output,
	}); err != nil {
		log.Error().Err(err).Str("sessionId", p.config.SessionID).Msg("Failed to log a Snowflake statement")
	}
}
