package gatewayv2

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type pkcs11RequestEnvelope struct {
	SlotLabel string          `json:"slotLabel"`
	PIN       []byte          `json:"-"`
	Params    json.RawMessage `json:"params"`
}

func (e *pkcs11RequestEnvelope) UnmarshalJSON(data []byte) error {
	var raw struct {
		SlotLabel string          `json:"slotLabel"`
		PIN       string          `json:"pin"`
		Params    json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	e.SlotLabel = raw.SlotLabel
	e.PIN = []byte(raw.PIN)
	e.Params = raw.Params
	return nil
}

type pkcs11Response struct {
	Result json.RawMessage `json:"result"`
}

type pkcs11ErrorResponse struct {
	Error pkcs11ErrorBody `json:"error"`
}

type pkcs11ErrorBody struct {
	Code    Pkcs11ErrorCode `json:"code"`
	Message string          `json:"message"`
}

const pkcs11RequestDeadline = 30 * time.Second

func servePkcs11OverTLS(ctx context.Context, conn *tls.Conn, reader *bufio.Reader, module Pkcs11Module) error {
	_ = conn.SetDeadline(time.Now().Add(pkcs11RequestDeadline))

	if module == nil {
		writeErrorResponse(conn, http.StatusServiceUnavailable, Pkcs11ErrNotSupported, "PKCS#11 module not loaded")
		return errors.New("PKCS#11 module is nil")
	}

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

	log.Debug().Str("path", req.URL.Path).Int64("contentLength", req.ContentLength).Msg("pkcs11: request received")

	rw := newBufferedResponseWriter()
	servePkcs11Mux(module).ServeHTTP(rw, req)
	if err := rw.writeTo(conn); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	log.Debug().Int("status", rw.status).Msg("pkcs11: response written")
	return nil
}

type bufferedResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	status     int
	wroteStart bool
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: http.Header{}, status: http.StatusOK}
}
func (b *bufferedResponseWriter) Header() http.Header { return b.header }
func (b *bufferedResponseWriter) WriteHeader(s int) {
	if b.wroteStart {
		return
	}
	b.status = s
	b.wroteStart = true
}
func (b *bufferedResponseWriter) Write(p []byte) (int, error) {
	if !b.wroteStart {
		b.WriteHeader(http.StatusOK)
	}
	return b.body.Write(p)
}
func (b *bufferedResponseWriter) writeTo(conn *tls.Conn) error {
	body := b.body.Bytes()
	if b.header.Get("Content-Length") == "" {
		b.header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	if b.header.Get("Connection") == "" {
		b.header.Set("Connection", "close")
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", b.status, http.StatusText(b.status))
	for k, vs := range b.header {
		for _, v := range vs {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\r\n")
		}
	}
	sb.WriteString("\r\n")
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return err
	}
	if _, err := conn.Write(body); err != nil {
		return err
	}
	return nil
}

func servePkcs11Mux(module Pkcs11Module) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/test", wrapPkcs11(module, handleTest))
	mux.HandleFunc("/v1/generate-key-pair", wrapPkcs11(module, handleGenerateKeyPair))
	mux.HandleFunc("/v1/sign", wrapPkcs11(module, handleSign))
	mux.HandleFunc("/v1/get-public-key", wrapPkcs11(module, handleGetPublicKey))
	return mux
}

type pkcs11Handler func(module Pkcs11Module, env *pkcs11RequestEnvelope) (any, error)

const maxPkcs11RequestBodyBytes = 256 * 1024

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func safeMessageForCode(code Pkcs11ErrorCode) string {
	switch code {
	case Pkcs11ErrPinIncorrect:
		return "The HSM rejected the PIN"
	case Pkcs11ErrPinLocked:
		return "The HSM has locked the slot"
	case Pkcs11ErrLoginFailed:
		return "The HSM rejected the login"
	case Pkcs11ErrSlotNotFound:
		return "Slot not found on this HSM"
	case Pkcs11ErrKeyNotFound:
		return "Key not found on this HSM"
	case Pkcs11ErrMechanismInvalid:
		return "Mechanism not supported by this HSM"
	case Pkcs11ErrDriverUnavailable:
		return "Driver unavailable"
	case Pkcs11ErrNotSupported:
		return "Operation not supported"
	case Pkcs11ErrBadRequest:
		return "Invalid request"
	}
	return "Operation failed"
}

func wrapPkcs11(module Pkcs11Module, fn pkcs11Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r.Body != nil {
				_ = r.Body.Close()
			}
		}()
		log.Debug().Str("path", r.URL.Path).Str("method", r.Method).Int64("contentLength", r.ContentLength).Msg("pkcs11: handler received request")
		if r.Method != http.MethodPost {
			writeErrorResponse(w, http.StatusMethodNotAllowed, Pkcs11ErrBadRequest, "Only POST is supported")
			return
		}
		if r.ContentLength > maxPkcs11RequestBodyBytes {
			log.Error().Int64("contentLength", r.ContentLength).Msg("pkcs11: request body too large")
			writeErrorResponse(w, http.StatusRequestEntityTooLarge, Pkcs11ErrBadRequest, "Request body too large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxPkcs11RequestBodyBytes)
		var env pkcs11RequestEnvelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			log.Warn().Err(err).Msg("pkcs11: body decode failed")
			writeErrorResponse(w, http.StatusBadRequest, Pkcs11ErrBadRequest, "Malformed request body")
			return
		}
		defer zeroBytes(env.PIN)
		log.Debug().Bool("hasPin", len(env.PIN) > 0).Msg("pkcs11: body decoded, dispatching to op handler")
		result, err := fn(module, &env)
		log.Debug().Bool("ok", err == nil).Msg("pkcs11: op handler returned")
		if err != nil {
			var p11Err *Pkcs11Error
			if errors.As(err, &p11Err) {
				log.Error().Str("code", string(p11Err.Code)).Str("errorMessage", p11Err.Message).Msg("pkcs11: op handler returned typed error")
				writeErrorResponse(w, statusForCode(p11Err.Code), p11Err.Code, safeMessageForCode(p11Err.Code))
				return
			}
			log.Error().Err(err).Msg("pkcs11: op handler returned untyped error")
			writeErrorResponse(w, http.StatusInternalServerError, Pkcs11ErrInternal, safeMessageForCode(Pkcs11ErrInternal))
			return
		}
		raw, err := json.Marshal(result)
		if err != nil {
			log.Error().Err(err).Msg("pkcs11: failed to marshal result")
			writeErrorResponse(w, http.StatusInternalServerError, Pkcs11ErrInternal, "Failed to marshal result")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(pkcs11Response{Result: raw}); err != nil {
			log.Warn().Err(err).Msg("pkcs11: failed to encode response")
		}
	}
}

type generateKeyPairParams struct {
	KeyLabel     string `json:"keyLabel"`
	KeyAlgorithm string `json:"keyAlgorithm"`
}

type signParams struct {
	KeyLabel  string `json:"keyLabel"`
	Mechanism string `json:"mechanism"`
	Data      string `json:"data"`
	IsDigest  bool   `json:"isDigest"`
}

type singleKeyLabelParams struct {
	KeyLabel string `json:"keyLabel"`
}

const (
	maxKeyLabelLen   = 256
	maxSignDataBytes = 64 * 1024
)

func handleTest(module Pkcs11Module, env *pkcs11RequestEnvelope) (any, error) {
	info, err := module.Test(env.SlotLabel, env.PIN)
	if err != nil {
		return nil, err
	}
	return map[string]any{"slotInfo": info}, nil
}

func handleGenerateKeyPair(module Pkcs11Module, env *pkcs11RequestEnvelope) (any, error) {
	var p generateKeyPairParams
	if err := json.Unmarshal(env.Params, &p); err != nil {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "Malformed params for generate-key-pair"}
	}
	if len(p.KeyLabel) > maxKeyLabelLen {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "keyLabel too long"}
	}
	spki, err := module.GenerateKeyPair(env.SlotLabel, env.PIN, p.KeyLabel, p.KeyAlgorithm)
	if err != nil {
		return nil, err
	}
	return map[string]any{"publicKey": base64.StdEncoding.EncodeToString(spki)}, nil
}

func handleSign(module Pkcs11Module, env *pkcs11RequestEnvelope) (any, error) {
	var p signParams
	if err := json.Unmarshal(env.Params, &p); err != nil {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "Malformed params for sign"}
	}
	if len(p.KeyLabel) > maxKeyLabelLen {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "keyLabel too long"}
	}
	data, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "data is not valid base64"}
	}
	if len(data) == 0 {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "data is empty"}
	}
	if len(data) > maxSignDataBytes {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "Data too large for signing"}
	}
	sig, err := module.Sign(env.SlotLabel, env.PIN, p.KeyLabel, p.Mechanism, data, p.IsDigest)
	if err != nil {
		return nil, err
	}
	return map[string]any{"signature": base64.StdEncoding.EncodeToString(sig)}, nil
}

func handleGetPublicKey(module Pkcs11Module, env *pkcs11RequestEnvelope) (any, error) {
	var p singleKeyLabelParams
	if err := json.Unmarshal(env.Params, &p); err != nil {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "Malformed params for get-public-key"}
	}
	if len(p.KeyLabel) > maxKeyLabelLen {
		return nil, &Pkcs11Error{Code: Pkcs11ErrBadRequest, Message: "keyLabel too long"}
	}
	spki, err := module.GetPublicKey(env.SlotLabel, env.PIN, p.KeyLabel)
	if err != nil {
		return nil, err
	}
	return map[string]any{"publicKey": base64.StdEncoding.EncodeToString(spki)}, nil
}

func statusForCode(code Pkcs11ErrorCode) int {
	switch code {
	case Pkcs11ErrPinIncorrect, Pkcs11ErrPinLocked, Pkcs11ErrLoginFailed, Pkcs11ErrSlotNotFound, Pkcs11ErrKeyNotFound, Pkcs11ErrMechanismInvalid, Pkcs11ErrBadRequest:
		return http.StatusBadRequest
	case Pkcs11ErrDriverUnavailable, Pkcs11ErrInternal:
		return http.StatusBadGateway
	case Pkcs11ErrNotSupported:
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}

func writeErrorResponse(w any, status int, code Pkcs11ErrorCode, message string) {
	body, _ := json.Marshal(pkcs11ErrorResponse{Error: pkcs11ErrorBody{Code: code, Message: message}})
	switch sink := w.(type) {
	case http.ResponseWriter:
		sink.Header().Set("Content-Type", "application/json")
		sink.WriteHeader(status)
		_, _ = sink.Write(body)
	case *tls.Conn:
		resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			status, http.StatusText(status), len(body), body)
		_, _ = sink.Write([]byte(resp))
	default:
		log.Warn().Msg("writeErrorResponse called with unsupported sink type")
	}
}
