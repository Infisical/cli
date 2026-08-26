package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type certRecord struct {
	latestRenewal string
	renewedBy     string
	status        string
}

func newCertificateServer(t *testing.T, certs map[string]certRecord) (*httptest.Server, func() []string) {
	t.Helper()

	var mu sync.Mutex
	var requested []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var id string
		if _, err := fmt.Sscanf(r.URL.Path, "/v1/cert-manager/certificates/%s", &id); err != nil {
			http.NotFound(w, r)
			return
		}

		record, ok := certs[id]
		if !ok {
			http.NotFound(w, r)
			return
		}

		mu.Lock()
		requested = append(requested, id)
		mu.Unlock()

		status := record.status
		if status == "" {
			status = "active"
		}

		var resp api.RetrieveCertificateResponse
		resp.Certificate.ID = id
		resp.Certificate.Status = status
		resp.Certificate.RenewedByCertificateID = record.renewedBy
		resp.Certificate.LatestRenewalCertificateID = record.latestRenewal

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))

	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), requested...)
	}
}

func newCertificateServerWithRenewedBy(t *testing.T, certs map[string]certRecord) (*httptest.Server, func() []string) {
	t.Helper()
	return newCertificateServer(t, certs)
}

func useLatestConfig(certificateID string) *AgentCertificateConfig {
	cert := &AgentCertificateConfig{CertificateID: certificateID}
	cert.Lifecycle.UseLatest = true
	return cert
}

func TestResolveCertificateToFetch_ResolvesLatestInTwoCallsRegardlessOfChainLength(t *testing.T) {
	server, requests := newCertificateServer(t, map[string]certRecord{
		"cert-03": {latestRenewal: "cert-11"},
		"cert-11": {},
	})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	metadata, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-03"), "cert-03")

	require.NoError(t, err)
	assert.Equal(t, "cert-11", metadata.Certificate.ID)
	assert.Equal(t, []string{"cert-03", "cert-11"}, requests(),
		"resolution must cost exactly two calls no matter how long the chain is")
}

func TestResolveCertificateToFetch_NeverRenewedCostsOneCall(t *testing.T) {
	server, requests := newCertificateServer(t, map[string]certRecord{"cert-01": {}})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	metadata, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-01"), "cert-01")

	require.NoError(t, err)
	assert.Equal(t, "cert-01", metadata.Certificate.ID)
	assert.Equal(t, []string{"cert-01"}, requests(), "a certificate that was never renewed must cost one call")
}

func TestResolveCertificateToFetch_PinnedWhenUseLatestDisabled(t *testing.T) {
	server, requests := newCertificateServer(t, map[string]certRecord{
		"cert-01": {latestRenewal: "cert-09"},
		"cert-09": {},
	})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	metadata, err := resolveCertificateToFetch(resty.New(), &AgentCertificateConfig{CertificateID: "cert-01"}, "cert-01")

	require.NoError(t, err)
	assert.Equal(t, "cert-01", metadata.Certificate.ID, "without use-latest the agent stays pinned")
	assert.Equal(t, []string{"cert-01"}, requests(), "pinned mode must not fetch the renewal")
}

func TestResolveCertificateToFetch_PreservesTerminalStatus(t *testing.T) {
	server, _ := newCertificateServer(t, map[string]certRecord{
		"cert-01": {latestRenewal: "cert-02"},
		"cert-02": {status: "revoked"},
	})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	metadata, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-01"), "cert-01")

	require.NoError(t, err)
	assert.Equal(t, "cert-02", metadata.Certificate.ID)
	assert.Equal(t, "revoked", metadata.Certificate.Status)
}

func TestResolveCertificateToFetch_ReportsMissingConfiguredCertificate(t *testing.T) {
	server, _ := newCertificateServer(t, map[string]certRecord{})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	_, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-gone"), "cert-gone")
	require.Error(t, err)
}

func TestResolveCertificateToFetch_NamesBothCertificatesWhenTheRenewalIsUnreachable(t *testing.T) {
	server, _ := newCertificateServer(t, map[string]certRecord{"cert-01": {latestRenewal: "cert-missing"}})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	_, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-01"), "cert-01")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert-missing")
	assert.Contains(t, err.Error(), "cert-01")
}

func TestValidateCertificateSourceConfig_UseLatestRequiresCertificateID(t *testing.T) {
	for _, version := range []string{AgentConfigVersionV1, AgentConfigVersionV2} {
		t.Run(version, func(t *testing.T) {
			cert := AgentCertificateConfig{ProjectName: "proj", ProfileName: "prof"}
			if version == AgentConfigVersionV2 {
				cert = AgentCertificateConfig{ApplicationName: "app", ProfileName: "prof"}
			}
			cert.Lifecycle.UseLatest = true

			certs := []AgentCertificateConfig{cert}
			err := validateCertificateSourceConfig(version, &certs)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "use-latest")
			assert.Contains(t, err.Error(), "certificate-id")
		})
	}
}

func TestValidateCertificateSourceConfig_UseLatestAllowedWithCertificateID(t *testing.T) {
	cert := AgentCertificateConfig{CertificateID: "00000000-0000-0000-0000-000000000000"}
	cert.Lifecycle.UseLatest = true

	certs := []AgentCertificateConfig{cert}
	require.NoError(t, validateCertificateSourceConfig(AgentConfigVersionV2, &certs))
}

func TestValidateCertificateSourceConfig_AcceptsRenewBeforeExpiryWithCertificateID(t *testing.T) {
	cert := AgentCertificateConfig{CertificateID: "00000000-0000-0000-0000-000000000000"}
	cert.Lifecycle.RenewBeforeExpiry = "30d"

	certs := []AgentCertificateConfig{cert}
	require.NoError(t, validateCertificateSourceConfig(AgentConfigVersionV2, &certs))
}

func TestValidateCertificateSourceConfig_StatusCheckIntervalAllowedWithCertificateID(t *testing.T) {
	cert := AgentCertificateConfig{CertificateID: "00000000-0000-0000-0000-000000000000"}
	cert.Lifecycle.StatusCheckInterval = "6h"
	cert.Lifecycle.UseLatest = true

	certs := []AgentCertificateConfig{cert}
	require.NoError(t, validateCertificateSourceConfig(AgentConfigVersionV2, &certs))
}

func TestResolveCertificateToFetch_KeepsCurrentWhenNoNewerCertificateIsNamed(t *testing.T) {
	server, requests := newCertificateServerWithRenewedBy(t, map[string]certRecord{
		"cert-01": {renewedBy: "cert-02"},
	})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	metadata, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-01"), "cert-01")

	require.NoError(t, err)
	assert.Equal(t, "cert-01", metadata.Certificate.ID, "the current certificate keeps being delivered")
	assert.Equal(t, []string{"cert-01"}, requests(), "it must not chase a certificate it was not given")
}

func TestResolveCertificateToFetch_UnrenewedCertificateOnOlderServerIsFine(t *testing.T) {
	server, requests := newCertificateServerWithRenewedBy(t, map[string]certRecord{"cert-01": {}})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	metadata, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-01"), "cert-01")

	require.NoError(t, err)
	assert.Equal(t, "cert-01", metadata.Certificate.ID)
	assert.Equal(t, []string{"cert-01"}, requests())
}

func TestResolveCertificateToFetch_AnchorsOnTheLastDeliveredCertificate(t *testing.T) {
	server, requests := newCertificateServer(t, map[string]certRecord{
		"cert-0001": {latestRenewal: "cert-5000"},
		"cert-4999": {latestRenewal: "cert-5000"},
		"cert-5000": {},
	})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	metadata, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-0001"), "cert-4999")

	require.NoError(t, err)
	assert.Equal(t, "cert-5000", metadata.Certificate.ID)
	assert.Equal(t, []string{"cert-4999", "cert-5000"}, requests(),
		"must resolve from the last delivered certificate, never touching the configured one")
}

func TestResolveCertificateToFetch_FallsBackToConfiguredIDWhenTheAnchorIsGone(t *testing.T) {
	server, requests := newCertificateServer(t, map[string]certRecord{
		"cert-0001": {latestRenewal: "cert-5000"},
		"cert-5000": {},
	})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	metadata, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-0001"), "cert-deleted")

	require.NoError(t, err)
	assert.Equal(t, "cert-5000", metadata.Certificate.ID)
	assert.Equal(t, []string{"cert-0001", "cert-5000"}, requests(),
		"a deleted anchor must fall back to the configured certificate-id, not fail")
}

func TestResolveCertificateToFetch_AnchorErrorSurfacesWhenItIsTheConfiguredID(t *testing.T) {
	server, _ := newCertificateServer(t, map[string]certRecord{})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	_, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-gone"), "cert-gone")
	require.Error(t, err)
}

func TestResolveCertificateToFetch_SteadyStateIsOneCall(t *testing.T) {
	server, requests := newCertificateServer(t, map[string]certRecord{"cert-5000": {}})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	metadata, err := resolveCertificateToFetch(resty.New(), useLatestConfig("cert-0001"), "cert-5000")

	require.NoError(t, err)
	assert.Equal(t, "cert-5000", metadata.Certificate.ID)
	assert.Equal(t, []string{"cert-5000"}, requests())
}

func distributionConfigWithKeyPath(dir string) *AgentCertificateConfig {
	cert := &AgentCertificateConfig{CertificateID: "cert-01"}
	cert.Lifecycle.UseLatest = true
	cert.FileConfig.Certificate.Path = filepath.Join(dir, "certificate.crt")
	cert.FileConfig.PrivateKey.Path = filepath.Join(dir, "private.key")
	return cert
}

func TestWriteCertificateFiles_KeylessFirstDeliveryWritesCertAndSkipsKey(t *testing.T) {
	dir := t.TempDir()
	cert := distributionConfigWithKeyPath(dir)
	tm := &AgentManager{}

	err := tm.writeCertificateFiles(cert, &api.CertificateResponse{
		Certificate: &api.CertificateData{Certificate: "-----BEGIN CERTIFICATE-----\nfirst\n"},
	}, false)

	require.NoError(t, err)
	require.FileExists(t, cert.FileConfig.Certificate.Path)
	require.NoFileExists(t, cert.FileConfig.PrivateKey.Path)
}

func TestWriteCertificateFiles_KeylessReplacementIsRefused(t *testing.T) {
	dir := t.TempDir()
	cert := distributionConfigWithKeyPath(dir)
	tm := &AgentManager{}

	require.NoError(t, os.WriteFile(cert.FileConfig.Certificate.Path, []byte("old cert"), 0o644))
	require.NoError(t, os.WriteFile(cert.FileConfig.PrivateKey.Path, []byte("old key"), 0o600))

	err := tm.writeCertificateFiles(cert, &api.CertificateResponse{
		Certificate: &api.CertificateData{Certificate: "-----BEGIN CERTIFICATE-----\nrenewed\n"},
	}, true)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "would no longer match")

	onDisk, readErr := os.ReadFile(cert.FileConfig.Certificate.Path)
	require.NoError(t, readErr)
	assert.Equal(t, "old cert", string(onDisk), "the certificate must be left alone when the write is refused")
}

func TestWriteCertificateFiles_KeylessReplacementAllowedWhenNoKeyOnDisk(t *testing.T) {
	dir := t.TempDir()
	cert := distributionConfigWithKeyPath(dir)
	tm := &AgentManager{}

	require.NoError(t, os.WriteFile(cert.FileConfig.Certificate.Path, []byte("old cert"), 0o644))

	err := tm.writeCertificateFiles(cert, &api.CertificateResponse{
		Certificate: &api.CertificateData{Certificate: "-----BEGIN CERTIFICATE-----\nrenewed\n"},
	}, true)

	require.NoError(t, err, "with no key on disk there is nothing to mismatch")
}

func TestWriteCertificateFiles_ReplacementWithKeyRewritesBoth(t *testing.T) {
	dir := t.TempDir()
	cert := distributionConfigWithKeyPath(dir)
	tm := &AgentManager{}

	require.NoError(t, os.WriteFile(cert.FileConfig.Certificate.Path, []byte("old cert"), 0o644))
	require.NoError(t, os.WriteFile(cert.FileConfig.PrivateKey.Path, []byte("old key"), 0o600))

	err := tm.writeCertificateFiles(cert, &api.CertificateResponse{
		Certificate: &api.CertificateData{
			Certificate: "-----BEGIN CERTIFICATE-----\nrenewed\n",
			PrivateKey:  "-----BEGIN PRIVATE KEY-----\nnew\n",
		},
	}, true)

	require.NoError(t, err)
	key, readErr := os.ReadFile(cert.FileConfig.PrivateKey.Path)
	require.NoError(t, readErr)
	assert.Contains(t, string(key), "new", "the key must be rotated with the certificate")
}

func TestWriteCertificateFiles_KeylessReplacementRefusedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	cert := distributionConfigWithKeyPath(dir)
	tm := &AgentManager{}

	require.NoError(t, os.WriteFile(cert.FileConfig.Certificate.Path, []byte("delivered before restart"), 0o644))
	require.NoError(t, os.WriteFile(cert.FileConfig.PrivateKey.Path, []byte("key from before restart"), 0o600))

	assert.True(t, isReplacementOnDisk(cert), "a certificate already on disk is a replacement regardless of memory")

	err := tm.writeCertificateFiles(cert, &api.CertificateResponse{
		Certificate: &api.CertificateData{Certificate: "-----BEGIN CERTIFICATE-----\nkeyless renewal\n"},
	}, isReplacementOnDisk(cert))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "would no longer match")
}

func TestIsReplacementOnDisk_FalseOnFirstRun(t *testing.T) {
	cert := distributionConfigWithKeyPath(t.TempDir())
	assert.False(t, isReplacementOnDisk(cert), "nothing on disk yet means this is a first delivery")
}
