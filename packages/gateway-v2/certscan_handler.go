package gatewayv2

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Infisical/infisical-merge/packages/gateway-v2/certscan"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

const (
	maxCertScanRequestBytes = 4 * 1024 * 1024
	certScanConcurrency     = 16
	certScanQueueWait       = 30 * time.Second
	certScanDefaultTimeout  = 10 * time.Minute
)

var certScanSlots = make(chan struct{}, certScanConcurrency)

type certScanEnvelope struct {
	sshExecEnvelope
	certscan.Request
}

type certScanResponse struct {
	Result certscan.Response `json:"result"`
}

type sshClientRunner struct {
	client *ssh.Client
}

func (r sshClientRunner) Run(ctx context.Context, command string, outputLimit int) (certscan.RunResult, error) {
	return runSSHCommand(ctx, r.client, command, outputLimit)
}

var runCertificateScan = certscan.Scan

func handleDiscoveryScanCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, "Only POST is supported")
		return
	}
	var env certScanEnvelope
	if err := json.NewDecoder(io.LimitReader(r.Body, maxCertScanRequestBytes)).Decode(&env); err != nil {
		writeRPCError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := certscan.Normalize(&env.Request); err != nil {
		writeRPCError(w, http.StatusBadRequest, err.Error())
		return
	}

	waitCtx, cancelWait := context.WithTimeout(r.Context(), certScanQueueWait)
	defer cancelWait()
	select {
	case certScanSlots <- struct{}{}:
		defer func() { <-certScanSlots }()
	case <-waitCtx.Done():
		log.Warn().Int("concurrency", certScanConcurrency).Msg("certscan: no free scan slot, rejecting certificate scan")
		writeRPCError(w, http.StatusServiceUnavailable, "The gateway is busy with other certificate scans. Try again shortly.")
		return
	}

	budget := sshCommandBudget(env.TimeoutMs, certScanDefaultTimeout)
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()

	target, _ := r.Context().Value(rpcTargetContextKey{}).(rpcTarget)
	client, err := dialSSH(ctx, budget, target.host, target.port, env.sshExecEnvelope)
	if err != nil {
		message := redactProbeSecrets(err.Error(), env.Password, env.PrivateKey, env.Passphrase)
		log.Warn().Str("host", target.host).Int("port", target.port).Str("error", message).Msg("certscan: failed to connect to the target host")
		writeRPCErrorWithKind(w, http.StatusBadGateway, message, string(classifyTestConnFailure(err)))
		return
	}
	defer client.Close() //nolint:errcheck

	result, err := runCertificateScan(ctx, sshClientRunner{client: client}, env.Request)
	if err != nil {
		message := redactProbeSecrets(err.Error(), env.Password, env.PrivateKey, env.Passphrase)
		log.Warn().Str("host", target.host).Int("port", target.port).Str("error", message).Msg("certscan: certificate scan failed")
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeRPCError(w, http.StatusGatewayTimeout, "The certificate scan did not finish in time")
			return
		}
		writeRPCError(w, http.StatusBadGateway, message)
		return
	}
	writeRPCJSON(w, http.StatusOK, certScanResponse{Result: result})
}
