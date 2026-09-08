package snowflake

import (
	"compress/gzip"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/youmark/pkcs8"
)

type zeroLogger = zerolog.Logger

const (
	errCodeAuth              = "390114"
	errCodeStatement         = "000904"
	errCodeUnsupported       = "000002"
	sessionExpiredCode       = "390112"
	queryInProgressCode      = "333333"
	queryInProgressAsyncCode = "333334"

	maxRequestBytes = 1 << 20
	// A ceiling on what one statement can pull into gateway memory
	maxRows = 10000
)

type envelope struct {
	Data    any     `json:"data"`
	Message *string `json:"message"`
	Code    *string `json:"code"`
	Success bool    `json:"success"`
}

type column struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Length     int     `json:"length"`
	Precision  *int    `json:"precision"`
	Scale      *int    `json:"scale"`
	Nullable   bool    `json:"nullable"`
	ByteLength int     `json:"byteLength"`
	Database   string  `json:"database"`
	Schema     string  `json:"schema"`
	Table      string  `json:"table"`
	Collation  *string `json:"collation"`
}

func writeEnvelope(w http.ResponseWriter, body envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

// http.MaxBytesReader gives back an opaque read error, which reads like a syntax problem otherwise
func statementReadError(err error) string {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return fmt.Sprintf("The statement is larger than the %d MB a proxied session accepts.", maxRequestBytes>>20)
	}
	return "Could not read the statement"
}

func writeFailure(w http.ResponseWriter, code string, message string) {
	writeEnvelope(w, envelope{Data: map[string]any{}, Message: &message, Code: &code})
}

// The drivers gzip every request body, so the encoding has to be honoured before parsing.
func decodeRequest(w http.ResponseWriter, r *http.Request, out any) error {
	var reader io.Reader = http.MaxBytesReader(w, r.Body, maxRequestBytes)

	if r.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	return json.NewDecoder(reader).Decode(out)
}

// Built from scratch rather than cloned from http.DefaultTransport, which the gateway has replaced.
func snowflakeTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// Every client connection opens its own tunnel and so its own proxy, so this is derived from the
// session rather than random
func sessionToken(config SnowflakeProxyConfig) string {
	mac := hmac.New(sha256.New, []byte(config.PrivateKey+config.Token+config.Password))
	mac.Write([]byte(config.SessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Clients read session parameters such as AUTOCOMMIT off this response and some panic when they are
// missing, so Snowflake's own list is forwarded rather than dropped.
func loginData(token string, config SnowflakeProxyConfig, sessionCtx map[string]string, parameters json.RawMessage) map[string]any {
	if len(parameters) == 0 {
		parameters = json.RawMessage("[]")
	}
	return map[string]any{
		"token":                   token,
		"masterToken":             token,
		"validityInSeconds":       3600,
		"masterValidityInSeconds": 3600,
		"displayUserName":         config.Username,
		"serverVersion":           "8.0.0",
		"firstLogin":              false,
		"healthCheckInterval":     45,
		"newClientForUpgrade":     nil,
		// A client on the official Go driver decodes this as an int64, so the PAM session's own UUID
		// can't be handed over as-is
		"sessionId":   numericSessionID(config.SessionID),
		"parameters":  parameters,
		"sessionInfo": sessionCtx,
	}
}

func numericSessionID(sessionID string) int64 {
	digest := sha256.Sum256([]byte(sessionID))
	return int64(binary.BigEndian.Uint64(digest[:8]) &^ (1 << 63))
}

func renewData(token string) map[string]any {
	return map[string]any{
		"sessionToken":            token,
		"masterToken":             token,
		"validityInSecondsST":     3600,
		"validityInSecondsMT":     3600,
		"masterValidityInSeconds": 3600,
	}
}

type queryResult struct {
	columns   []column
	rows      [][]any
	queryID   string
	truncated bool
	elapsed   time.Duration
}

func (r *queryResult) summary() string {
	summary := fmt.Sprintf("%d row(s), %dms", len(r.rows), r.elapsed.Milliseconds())
	if r.truncated {
		summary = fmt.Sprintf("%s, truncated at %d", summary, maxRows)
	}
	return summary
}

func (r *queryResult) data() map[string]any {
	return map[string]any{
		"rowtype":           r.columns,
		"rowset":            r.rows,
		"total":             len(r.rows),
		"returned":          len(r.rows),
		"queryId":           r.queryID,
		"queryResultFormat": "json",
		"parameters":        []any{},
	}
}

func parsePrivateKey(privateKeyPem string, passphrase string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		return nil, errors.New("the stored private key is not valid PEM")
	}

	// Driven by the key itself, not by whether a passphrase happens to be stored, so a passphrase left
	// over from an earlier credential doesn't break a plain key
	if strings.Contains(block.Type, "ENCRYPTED") {
		key, err := pkcs8.ParsePKCS8PrivateKeyRSA(block.Bytes, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("could not decrypt the private key: %w", err)
		}
		return key, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not read the private key: %w", err)
	}

	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("Snowflake key pair authentication requires an RSA private key")
	}
	return key, nil
}

type singleConnListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	listener := &singleConnListener{conns: make(chan net.Conn, 1), closed: make(chan struct{})}
	// http.Server closes the connection when the client hangs up, which is what ends the session and
	// lets the deferred session-logger close flush the recording
	listener.conns <- &closeNotifyConn{Conn: conn, onClose: listener.Close}
	return listener
}

type closeNotifyConn struct {
	net.Conn
	onClose func() error
	once    sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { _ = c.onClose() })
	return err
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func isListenerDone(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed)
}
