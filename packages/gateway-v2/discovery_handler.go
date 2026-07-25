package gatewayv2

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	discoveryRequestDeadline = 15 * time.Minute
	maxSweepRequestBytes     = 1 * 1024 * 1024
	maxSweepTargets          = 65536
	sweepConcurrency         = 512
	maxSweepTimeout          = 30 * time.Second
)

type rpcTarget struct {
	host string
	port int
}

type rpcTargetContextKey struct{}

// serveRPCOverTLS reads one HTTP request off the relay connection, dispatches it to mux with the cert-bound
// target in context, and writes the response back. The target host/port come from the signed gateway certificate.
func serveRPCOverTLS(
	ctx context.Context,
	conn *tls.Conn,
	reader *bufio.Reader,
	forwardConfig *ForwardConfig,
	mux *http.ServeMux,
	requestDeadline time.Duration,
	logLabel string,
) error {
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

	opCtx, cancel := context.WithTimeout(ctx, requestDeadline)
	defer cancel()
	opCtx = context.WithValue(opCtx, rpcTargetContextKey{}, rpcTarget{forwardConfig.TargetHost, forwardConfig.TargetPort})
	req = req.WithContext(opCtx)

	rw := newBufferedResponseWriter()
	mux.ServeHTTP(rw, req)
	if err := rw.writeTo(conn); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	log.Debug().Str("path", req.URL.Path).Int("status", rw.status).Msg(logLabel + ": response written")
	return nil
}

func serveDiscoveryOverTLS(ctx context.Context, conn *tls.Conn, reader *bufio.Reader, forwardConfig *ForwardConfig) error {
	return serveRPCOverTLS(ctx, conn, reader, forwardConfig, discoveryMux(), discoveryRequestDeadline, "discovery")
}

var discoveryMux = sync.OnceValue(func() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/exec", handleDiscoveryExec)
	mux.HandleFunc("/v1/sweep", handleDiscoverySweep)
	return mux
})

func handleDiscoveryExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, "Only POST is supported")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSshExecRequestBytes))
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	var env sshExecEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeRPCError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	target, _ := r.Context().Value(rpcTargetContextKey{}).(rpcTarget)
	result, execErr := doSSHExec(target.host, target.port, env)
	if execErr != nil {
		writeRPCError(w, http.StatusBadGateway, execErr.Error())
		return
	}
	writeRPCJSON(w, http.StatusOK, sshExecResponse{Result: result})
}

func handleDiscoverySweep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, "Only POST is supported")
		return
	}
	var req struct {
		Targets   []string `json:"targets"`
		TimeoutMs int      `json:"timeoutMs"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxSweepRequestBytes)).Decode(&req); err != nil {
		writeRPCError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(req.Targets) > maxSweepTargets {
		writeRPCError(w, http.StatusBadRequest, fmt.Sprintf("target count %d exceeds limit %d", len(req.Targets), maxSweepTargets))
		return
	}
	writeRPCJSON(w, http.StatusOK, map[string][]string{"open": sweepReachable(r.Context(), req.Targets, req.TimeoutMs)})
}

// sweepReachable TCP-probes each host:port concurrently in-network and returns the reachable ones
func sweepReachable(ctx context.Context, targets []string, timeoutMs int) []string {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	} else if timeout > maxSweepTimeout {
		timeout = maxSweepTimeout
	}

	sem := make(chan struct{}, sweepConcurrency)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		open []string
	)
	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			dialer := net.Dialer{Timeout: timeout}
			c, dialErr := dialer.DialContext(ctx, "tcp", t)
			if dialErr != nil {
				return
			}
			_ = c.Close()
			mu.Lock()
			open = append(open, t)
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	return open
}

func writeRPCJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeRPCError(w http.ResponseWriter, status int, message string) {
	writeRPCJSON(w, status, sshExecErrorResponse{Error: sshExecErrorBody{Message: message}})
}
