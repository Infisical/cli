package gatewayv2

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/gateway-v2/adcs"
	"github.com/rs/zerolog/log"
)

// adcsRequestEnvelope is the common body for every ADCS/MS-WCCE operation.
// Credentials are supplied per request over the mTLS relay tunnel and are never
// persisted by the gateway.
type adcsRequestEnvelope struct {
	Username string `json:"username"`
	// Password is a string (not []byte we could zero after use, unlike the PKCS#11 PIN)
	// because go-msrpc's cfg.Credential.Password is itself a string, so a zeroable copy
	// would not remove the secret from process memory anyway. It lives only for the
	// request and is never persisted or logged.
	Password string          `json:"password"`
	CAName   string          `json:"caName"`
	Params   json.RawMessage `json:"params"`
}

// adcsCAHostContextKey carries the CA host into the operation handlers. The host comes from the
// signed client-certificate routing extension (GATEWAY_ROUTING_INFO_OID), never the request body,
// so a caller cannot point the gateway at an arbitrary host (SSRF).
type adcsCAHostContextKey struct{}

func adcsCAHostFromContext(ctx context.Context) string {
	host, _ := ctx.Value(adcsCAHostContextKey{}).(string)
	return host
}

type adcsEnrollParams struct {
	Template string `json:"template"`
	CSR      string `json:"csr"` // base64-encoded DER PKCS#10
}

type adcsRevokeParams struct {
	SerialNumber string `json:"serialNumber"` // plain hex digits, no leading 0x
	Reason       uint32 `json:"reason"`       // RFC 5280 CRLReason code
}

type adcsResponse struct {
	Result json.RawMessage `json:"result"`
}

type adcsErrorResponse struct {
	Error adcsErrorBody `json:"error"`
}

type adcsErrorBody struct {
	Message string `json:"message"`
}

const (
	adcsRequestDeadline     = 90 * time.Second
	maxAdcsRequestBodyBytes = 256 * 1024
)

// serveAdcsOverTLS reads a single HTTP request off the TLS connection and
// dispatches it to the ADCS operation mux, mirroring the PKCS#11 handler.
func serveAdcsOverTLS(ctx context.Context, conn *tls.Conn, reader *bufio.Reader, caHost string) error {
	_ = conn.SetDeadline(time.Now().Add(adcsRequestDeadline))

	reqCh := make(chan *http.Request, 1)
	errCh := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(reader)
		if err != nil {
			errCh <- err
			return
		}
		reqCh <- req
	}()

	var req *http.Request
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return fmt.Errorf("failed to read HTTP request: %w", err)
	case req = <-reqCh:
	}

	log.Debug().Str("path", req.URL.Path).Msg("adcs: request received")

	// Tie the operation to the gateway lifecycle and the request budget so an in-flight
	// WCCE call is cancelled on shutdown instead of only when the TLS deadline fires.
	opCtx, cancel := context.WithTimeout(ctx, adcsRequestDeadline)
	defer cancel()
	opCtx = context.WithValue(opCtx, adcsCAHostContextKey{}, caHost)
	req = req.WithContext(opCtx)

	rw := newBufferedResponseWriter()
	serveAdcsMux().ServeHTTP(rw, req)
	if err := rw.writeTo(conn); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	log.Debug().Int("status", rw.status).Msg("adcs: response written")
	return nil
}

var serveAdcsMux = sync.OnceValue(func() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/test", wrapAdcs(handleAdcsTest, true))
	// discover-ca reads the CA name over winreg (SMB) and never touches WCCE, so it must
	// not require a WCCE session. It runs before the CA name is even known.
	mux.HandleFunc("/v1/discover-ca", wrapAdcs(handleAdcsDiscoverCA, false))
	mux.HandleFunc("/v1/templates", wrapAdcs(handleAdcsTemplates, true))
	mux.HandleFunc("/v1/enroll", wrapAdcs(handleAdcsEnroll, true))
	// revoke uses MS-CSRA (ICertAdminD) rather than MS-WCCE, so it manages its own DCOM
	// session inside the handler and must not require the shared WCCE session.
	mux.HandleFunc("/v1/revoke", wrapAdcs(handleAdcsRevoke, false))
	return mux
})

type adcsHandler func(ctx context.Context, client *adcs.Client, env *adcsRequestEnvelope) (any, error)

// wrapAdcs decodes the envelope, optionally opens an authenticated MS-WCCE session,
// runs the operation, and encodes the JSON result or error. It recovers from panics
// so a malformed CA/registry response can never take down the gateway process.
func wrapAdcs(fn adcsHandler, needsWcce bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r.Body != nil {
				_ = r.Body.Close()
			}
			if p := recover(); p != nil {
				log.Error().Interface("panic", p).Str("path", r.URL.Path).Msg("adcs: recovered from panic")
				writeAdcsError(w, http.StatusInternalServerError, "Internal error handling ADCS request")
			}
		}()

		if r.Method != http.MethodPost {
			writeAdcsError(w, http.StatusMethodNotAllowed, "Only POST is supported")
			return
		}
		if r.ContentLength > maxAdcsRequestBodyBytes {
			writeAdcsError(w, http.StatusRequestEntityTooLarge, "Request body too large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAdcsRequestBodyBytes)

		var env adcsRequestEnvelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			writeAdcsError(w, http.StatusBadRequest, "Malformed request body")
			return
		}
		ctx := r.Context()
		caHost := adcsCAHostFromContext(ctx)
		if caHost == "" || env.Username == "" {
			writeAdcsError(w, http.StatusBadRequest, "CA host and username are required")
			return
		}

		var client *adcs.Client
		if needsWcce {
			dialed, err := adcs.Dial(ctx, adcs.Credentials{Host: caHost, Username: env.Username, Password: env.Password})
			if err != nil {
				log.Warn().Err(err).Msg("adcs: dial failed")
				writeAdcsError(w, http.StatusBadGateway, "Failed to connect to the ADCS host")
				return
			}
			defer dialed.Close(ctx)
			client = dialed
		}

		result, err := fn(ctx, client, &env)
		if err != nil {
			log.Warn().Err(err).Str("path", r.URL.Path).Msg("adcs: operation failed")
			writeAdcsError(w, http.StatusBadGateway, err.Error())
			return
		}

		raw, err := json.Marshal(result)
		if err != nil {
			writeAdcsError(w, http.StatusInternalServerError, "Failed to marshal result")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(adcsResponse{Result: raw}); err != nil {
			log.Warn().Err(err).Msg("adcs: failed to encode response")
		}
	}
}

func handleAdcsTest(ctx context.Context, client *adcs.Client, _ *adcsRequestEnvelope) (any, error) {
	if err := client.Ping(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func handleAdcsDiscoverCA(ctx context.Context, _ *adcs.Client, env *adcsRequestEnvelope) (any, error) {
	name, err := adcs.DiscoverCAName(ctx, adcs.Credentials{Host: adcsCAHostFromContext(ctx), Username: env.Username, Password: env.Password})
	if err != nil {
		return nil, err
	}
	return map[string]any{"caName": name}, nil
}

func handleAdcsTemplates(ctx context.Context, client *adcs.Client, env *adcsRequestEnvelope) (any, error) {
	if env.CAName == "" {
		return nil, fmt.Errorf("caName is required")
	}
	templates, err := client.Templates(ctx, env.CAName)
	if err != nil {
		return nil, err
	}
	return map[string]any{"templates": templates}, nil
}

func handleAdcsEnroll(ctx context.Context, client *adcs.Client, env *adcsRequestEnvelope) (any, error) {
	if env.CAName == "" {
		return nil, fmt.Errorf("caName is required")
	}
	var p adcsEnrollParams
	if err := json.Unmarshal(env.Params, &p); err != nil {
		return nil, fmt.Errorf("malformed enroll params")
	}
	if p.Template == "" {
		return nil, fmt.Errorf("template is required")
	}
	csrDER, err := base64.StdEncoding.DecodeString(p.CSR)
	if err != nil {
		return nil, fmt.Errorf("csr is not valid base64 DER")
	}
	if len(csrDER) == 0 {
		return nil, fmt.Errorf("csr is empty")
	}
	return client.Enroll(ctx, env.CAName, p.Template, csrDER)
}

func handleAdcsRevoke(ctx context.Context, _ *adcs.Client, env *adcsRequestEnvelope) (any, error) {
	if env.CAName == "" {
		return nil, fmt.Errorf("caName is required")
	}
	var p adcsRevokeParams
	if err := json.Unmarshal(env.Params, &p); err != nil {
		return nil, fmt.Errorf("malformed revoke params")
	}
	if p.SerialNumber == "" {
		return nil, fmt.Errorf("serialNumber is required")
	}
	creds := adcs.Credentials{Host: adcsCAHostFromContext(ctx), Username: env.Username, Password: env.Password}
	if err := adcs.Revoke(ctx, creds, env.CAName, p.SerialNumber, p.Reason); err != nil {
		if errors.Is(err, adcs.ErrConnect) {
			log.Warn().Err(err).Msg("adcs: revoke connection failed")
			return nil, adcs.ErrConnect
		}
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func writeAdcsError(w http.ResponseWriter, status int, message string) {
	body, _ := json.Marshal(adcsErrorResponse{Error: adcsErrorBody{Message: message}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
