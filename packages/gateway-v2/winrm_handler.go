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

	"github.com/Infisical/infisical-merge/packages/gateway-v2/winrm"
	"github.com/rs/zerolog/log"
)

// winrmRequestEnvelope is the common body for every WinRM operation. Host/port come from the signed
// routing extension, not this body, so a caller cannot point the gateway at an arbitrary host (SSRF).
type winrmRequestEnvelope struct {
	Username string          `json:"username"`
	Password string          `json:"password"`
	Params   json.RawMessage `json:"params"`
}

// winrmTargetContextKey carries the target host/port into the operation handlers.
type winrmTargetContextKey struct{}

type winrmTarget struct {
	Host string
	Port int
}

func winrmTargetFromContext(ctx context.Context) winrmTarget {
	t, _ := ctx.Value(winrmTargetContextKey{}).(winrmTarget)
	return t
}

// winrmTransportParams are the per-request transport settings; host/port are excluded (see envelope).
// useHttps selects HTTPS over the default HTTP-with-NTLM-message-encryption transport; for HTTPS,
// insecure skips certificate verification and caCertificate pins a CA to authenticate a self-signed listener.
type winrmTransportParams struct {
	UseHTTPS      bool   `json:"useHttps"`
	Insecure      bool   `json:"insecure"`
	CACertificate string `json:"caCertificate"`
}

type winrmDeliverFile struct {
	Path          string `json:"path"`
	ContentBase64 string `json:"contentBase64"`
}

type winrmDeliverParams struct {
	winrmTransportParams
	Files []winrmDeliverFile `json:"files"`
}

type winrmRemoveParams struct {
	winrmTransportParams
	Paths []string `json:"paths"`
}

type winrmResponse struct {
	Result json.RawMessage `json:"result"`
}

type winrmErrorResponse struct {
	Error winrmErrorBody `json:"error"`
}

type winrmErrorBody struct {
	Message string `json:"message"`
}

const (
	// winrmConnDeadline is longer than winrmOpDeadline so the gateway can flush a structured
	// error response before the connection deadline trips.
	winrmOpDeadline          = 120 * time.Second
	winrmConnDeadline        = winrmOpDeadline + 15*time.Second
	maxWinrmRequestBodyBytes = 4 * 1024 * 1024
)

// serveWinrmOverTLS reads a single HTTP request off the TLS relay connection and dispatches it to the mux.
func serveWinrmOverTLS(ctx context.Context, conn *tls.Conn, reader *bufio.Reader, targetHost string, targetPort int) error {
	_ = conn.SetDeadline(time.Now().Add(winrmConnDeadline))

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

	log.Debug().Str("path", req.URL.Path).Msg("winrm: request received")

	opCtx, cancel := context.WithTimeout(ctx, winrmOpDeadline)
	defer cancel()
	opCtx = context.WithValue(opCtx, winrmTargetContextKey{}, winrmTarget{Host: targetHost, Port: targetPort})
	req = req.WithContext(opCtx)

	rw := newBufferedResponseWriter()
	serveWinrmMux().ServeHTTP(rw, req)
	if err := rw.writeTo(conn); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	log.Debug().Int("status", rw.status).Msg("winrm: response written")
	return nil
}

var serveWinrmMux = sync.OnceValue(func() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/test", wrapWinrm(handleWinrmTest))
	mux.HandleFunc("/v1/deliver", wrapWinrm(handleWinrmDeliver))
	mux.HandleFunc("/v1/remove", wrapWinrm(handleWinrmRemove))
	return mux
})

type winrmHandlerFn func(ctx context.Context, env *winrmRequestEnvelope) (any, error)

// wrapWinrm decodes the envelope, runs the operation, and encodes the JSON result or error. It
// recovers from panics so a malformed host response can't take down the gateway process.
func wrapWinrm(fn winrmHandlerFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r.Body != nil {
				_ = r.Body.Close()
			}
			if p := recover(); p != nil {
				log.Error().Interface("panic", p).Str("path", r.URL.Path).Msg("winrm: recovered from panic")
				writeWinrmError(w, http.StatusInternalServerError, "Internal error handling WinRM request")
			}
		}()

		if r.Method != http.MethodPost {
			writeWinrmError(w, http.StatusMethodNotAllowed, "Only POST is supported")
			return
		}
		if r.ContentLength > maxWinrmRequestBodyBytes {
			writeWinrmError(w, http.StatusRequestEntityTooLarge, "Request body too large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxWinrmRequestBodyBytes)

		var env winrmRequestEnvelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			writeWinrmError(w, http.StatusBadRequest, "Malformed request body")
			return
		}
		ctx := r.Context()
		target := winrmTargetFromContext(ctx)
		if target.Host == "" || target.Port == 0 || env.Username == "" {
			writeWinrmError(w, http.StatusBadRequest, "Target host, port and username are required")
			return
		}

		result, err := fn(ctx, &env)
		if err != nil {
			log.Warn().Err(err).Str("path", r.URL.Path).Msg("winrm: operation failed")
			// Hide the internal host/port from the control plane on connect/auth failures.
			if errors.Is(err, winrm.ErrConnect) {
				err = winrm.ErrConnect
			}
			writeWinrmError(w, http.StatusBadGateway, err.Error())
			return
		}

		raw, err := json.Marshal(result)
		if err != nil {
			writeWinrmError(w, http.StatusInternalServerError, "Failed to marshal result")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(winrmResponse{Result: raw}); err != nil {
			log.Warn().Err(err).Msg("winrm: failed to encode response")
		}
	}
}

func credsFromEnv(ctx context.Context, env *winrmRequestEnvelope, tp winrmTransportParams) winrm.Credentials {
	target := winrmTargetFromContext(ctx)
	return winrm.Credentials{
		Host:     target.Host,
		Port:     target.Port,
		Username: env.Username,
		Password: env.Password,
		UseHTTPS: tp.UseHTTPS,
		Insecure: tp.Insecure,
		CACert:   []byte(tp.CACertificate),
	}
}

func handleWinrmTest(ctx context.Context, env *winrmRequestEnvelope) (any, error) {
	var tp winrmTransportParams
	if len(env.Params) > 0 {
		if err := json.Unmarshal(env.Params, &tp); err != nil {
			return nil, fmt.Errorf("malformed test params")
		}
	}
	if err := winrm.Ping(ctx, credsFromEnv(ctx, env, tp)); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func handleWinrmDeliver(ctx context.Context, env *winrmRequestEnvelope) (any, error) {
	var p winrmDeliverParams
	if err := json.Unmarshal(env.Params, &p); err != nil {
		return nil, fmt.Errorf("malformed deliver params")
	}
	if len(p.Files) == 0 {
		return nil, fmt.Errorf("no files to deliver")
	}
	files := make([]winrm.FileDelivery, 0, len(p.Files))
	for _, f := range p.Files {
		if f.Path == "" {
			return nil, fmt.Errorf("file path is required")
		}
		content, err := base64.StdEncoding.DecodeString(f.ContentBase64)
		if err != nil {
			return nil, fmt.Errorf("file content is not valid base64")
		}
		files = append(files, winrm.FileDelivery{Path: f.Path, Content: content})
	}
	if err := winrm.DeliverFiles(ctx, credsFromEnv(ctx, env, p.winrmTransportParams), files); err != nil {
		return nil, err
	}
	return map[string]any{"delivered": len(files)}, nil
}

func handleWinrmRemove(ctx context.Context, env *winrmRequestEnvelope) (any, error) {
	var p winrmRemoveParams
	if err := json.Unmarshal(env.Params, &p); err != nil {
		return nil, fmt.Errorf("malformed remove params")
	}
	if len(p.Paths) == 0 {
		return map[string]any{"removed": 0}, nil
	}
	if err := winrm.RemoveFiles(ctx, credsFromEnv(ctx, env, p.winrmTransportParams), p.Paths); err != nil {
		return nil, err
	}
	return map[string]any{"removed": len(p.Paths)}, nil
}

func writeWinrmError(w http.ResponseWriter, status int, message string) {
	body, _ := json.Marshal(winrmErrorResponse{Error: winrmErrorBody{Message: message}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
