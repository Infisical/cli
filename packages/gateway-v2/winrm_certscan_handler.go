package gatewayv2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Infisical/infisical-merge/packages/gateway-v2/certscan"
	"github.com/Infisical/infisical-merge/packages/gateway-v2/winrm"
	"github.com/rs/zerolog/log"
)

const (
	maxWinrmStoreScanStores       = 5
	defaultWinrmStoreScanMaxCerts = 5000
)

var errWinrmGatewayBusy = errors.New("gateway busy with other certificate scans")

type winrmScanCertificatesParams struct {
	winrmTransportParams
	Stores          []string `json:"stores"`
	MaxCertificates int      `json:"maxCertificates"`
}

var scanWinrmCertificateStores = winrm.ScanCertificateStores

func handleWinrmScanCertificates(ctx context.Context, env *winrmRequestEnvelope) (any, error) {
	var p winrmScanCertificatesParams
	if err := json.Unmarshal(env.Params, &p); err != nil {
		return nil, fmt.Errorf("malformed scan-certificates params")
	}
	if len(p.Stores) == 0 || len(p.Stores) > maxWinrmStoreScanStores {
		return nil, fmt.Errorf("between 1 and %d certificate stores are required", maxWinrmStoreScanStores)
	}
	for _, store := range p.Stores {
		if !winrm.IsAllowedCertificateStore(store) {
			return nil, fmt.Errorf("unsupported certificate store %q", store)
		}
	}
	maxCerts := p.MaxCertificates
	if maxCerts <= 0 || maxCerts > defaultWinrmStoreScanMaxCerts {
		maxCerts = defaultWinrmStoreScanMaxCerts
	}

	waitCtx, cancelWait := context.WithTimeout(ctx, certScanQueueWait)
	defer cancelWait()
	select {
	case certScanSlots <- struct{}{}:
		defer func() { <-certScanSlots }()
	case <-waitCtx.Done():
		log.Warn().Int("concurrency", certScanConcurrency).Msg("winrm: no free scan slot, rejecting certificate store scan")
		return nil, errWinrmGatewayBusy
	}

	scan, err := scanWinrmCertificateStores(ctx, credsFromEnv(ctx, env, p.winrmTransportParams), p.Stores, maxCerts)
	if err != nil {
		return nil, err
	}

	response := certscan.BuildStoreResults(scan.Records)
	response.Host = certscan.HostInfo{Hostname: scan.Hostname}
	response.DeniedStores = scan.DeniedStores
	response.UnreadableIssuerStores = scan.UnreadableIssuerStores
	if scan.Truncated && scan.Diagnostic != "" {
		log.Warn().Str("diagnostic", scan.Diagnostic).Msg("winrm: certificate store scan stopped early")
	}
	switch {
	case response.TruncatedReason != "":
	case scan.TimedOut:
		response.TruncatedReason = certscan.TruncatedTimeLimit
	case scan.OverBudget:
		response.TruncatedReason = certscan.TruncatedResponseSize
	case scan.Truncated:
		response.TruncatedReason = certscan.TruncatedIncomplete
	case scan.HitLimit:
		response.TruncatedReason = certscan.TruncatedMaxFiles
	}
	return response, nil
}
