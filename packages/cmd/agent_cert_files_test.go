package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestWriteCertificateFiles_CombineCertificateChain(t *testing.T) {
	const leaf = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----"
	const chain = "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"

	for _, tc := range []struct {
		name          string
		option        string
		certificate   string
		chain         string
		omitChainPath bool
		wantCombined  bool
		wantCert      string
		wantChain     bool
	}{
		{name: "default separate files", certificate: leaf + "\n", chain: chain + "\n", wantCert: leaf + "\n", wantChain: true},
		{name: "explicitly disabled", option: "combine-certificate-chain: false", certificate: leaf, chain: chain, wantCert: leaf, wantChain: true},
		{name: "combined", option: "combine-certificate-chain: true", certificate: leaf, chain: chain, wantCombined: true, wantCert: leaf + "\n" + chain + "\n"},
		{name: "combined trims whitespace", option: "combine-certificate-chain: true", certificate: "\n" + leaf + "\n\n", chain: "\n" + chain + "\n\n", wantCombined: true, wantCert: leaf + "\n" + chain + "\n"},
		{name: "combined without chain path", option: "combine-certificate-chain: true", certificate: leaf, chain: chain, omitChainPath: true, wantCombined: true, wantCert: leaf + "\n" + chain + "\n"},
		{name: "combined without chain content", option: "combine-certificate-chain: true", certificate: leaf + "\n", wantCombined: true, wantCert: leaf + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cert AgentCertificateConfig
			require.NoError(t, yaml.Unmarshal([]byte("file-output:\n  "+tc.option+"\n"), &cert))
			assert.Equal(t, tc.wantCombined, cert.FileConfig.CombineCertificateChain)

			dir := t.TempDir()
			cert.FileConfig.Certificate.Path = filepath.Join(dir, "certs", "fullchain.pem")
			cert.FileConfig.Certificate.Permission = "0644"
			cert.FileConfig.PrivateKey.Path = filepath.Join(dir, "keys", "privkey.pem")
			if !tc.omitChainPath {
				cert.FileConfig.Chain.Path = filepath.Join(dir, "chain", "chain.pem")
			}

			tm := &AgentManager{}
			require.NoError(t, tm.WriteCertificateFiles(&cert, &api.CertificateResponse{
				Certificate: &api.CertificateData{
					Certificate:      tc.certificate,
					CertificateChain: tc.chain,
					PrivateKey:       "private key",
				},
			}))

			content, err := os.ReadFile(cert.FileConfig.Certificate.Path)
			require.NoError(t, err)
			assert.Equal(t, tc.wantCert, string(content))
			info, err := os.Stat(cert.FileConfig.Certificate.Path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0644), info.Mode().Perm())

			key, err := os.ReadFile(cert.FileConfig.PrivateKey.Path)
			require.NoError(t, err)
			assert.Equal(t, "private key", string(key))
			info, err = os.Stat(cert.FileConfig.PrivateKey.Path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

			if tc.wantChain {
				content, err = os.ReadFile(cert.FileConfig.Chain.Path)
				require.NoError(t, err)
				assert.Equal(t, tc.chain, string(content))
			} else {
				require.NoFileExists(t, filepath.Join(dir, "chain", "chain.pem"))
			}
		})
	}
}

func mockCertificateServer(t *testing.T, bundle func() (int, api.CertificateBundleResponse)) *atomic.Int32 {
	t.Helper()
	var bundleCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/cert-manager/certificates/cert-01":
			var response api.RetrieveCertificateResponse
			response.Certificate.ID = "cert-01"
			response.Certificate.Status = "active"
			response.Certificate.SerialNumber = "01"
			_ = json.NewEncoder(w).Encode(response)
		case "/v1/cert-manager/certificates/cert-01/bundle":
			bundleCalls.Add(1)
			status, body := bundle()
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)
	return &bundleCalls
}

func TestFetchCertificate_RestartRewritesOnlyOutdatedFiles(t *testing.T) {
	leaf := selfSignedPEM(t, "leaf")
	intermediate := selfSignedPEM(t, "intermediate")
	rotatedIntermediate := selfSignedPEM(t, "rotated intermediate")
	combined := leaf + intermediate

	for _, tc := range []struct {
		name        string
		combine     bool
		chain       string
		certOnDisk  string
		chainOnDisk string
		wantCert    string
		wantChain   string
		wantRewrite bool
	}{
		{name: "separate files up to date", chain: intermediate, certOnDisk: leaf, chainOnDisk: intermediate, wantCert: leaf, wantChain: intermediate},
		{name: "combined file up to date", combine: true, chain: intermediate, certOnDisk: combined, wantCert: combined},
		{name: "chainless combined file up to date", combine: true, certOnDisk: leaf, wantCert: leaf},
		{name: "leaf-only file converted to combined", combine: true, chain: intermediate, certOnDisk: leaf, chainOnDisk: intermediate, wantCert: combined, wantChain: intermediate, wantRewrite: true},
		{name: "combined file split after opting out", chain: intermediate, certOnDisk: combined, wantCert: leaf, wantChain: intermediate, wantRewrite: true},
		{name: "rotated chain refreshed in combined file", combine: true, chain: rotatedIntermediate, certOnDisk: combined, wantCert: leaf + rotatedIntermediate, wantRewrite: true},
		{name: "rotated chain refreshed in chain file", chain: rotatedIntermediate, certOnDisk: leaf, chainOnDisk: intermediate, wantCert: leaf, wantChain: rotatedIntermediate, wantRewrite: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := distributionConfigWithKeyPath(t.TempDir())
			cert.FileConfig.CombineCertificateChain = tc.combine
			cert.FileConfig.Chain.Path = filepath.Join(filepath.Dir(cert.FileConfig.Certificate.Path), "chain.pem")
			require.NoError(t, os.WriteFile(cert.FileConfig.Certificate.Path, []byte(tc.certOnDisk), 0600))
			require.NoError(t, os.WriteFile(cert.FileConfig.PrivateKey.Path, []byte("private key"), 0600))
			if tc.chainOnDisk != "" {
				require.NoError(t, os.WriteFile(cert.FileConfig.Chain.Path, []byte(tc.chainOnDisk), 0600))
			}
			modifiedAt := time.Unix(1700000000, 0)
			require.NoError(t, os.Chtimes(cert.FileConfig.Certificate.Path, modifiedAt, modifiedAt))

			mockCertificateServer(t, func() (int, api.CertificateBundleResponse) {
				return http.StatusOK, api.CertificateBundleResponse{Certificate: leaf, CertificateChain: tc.chain, PrivateKey: "private key", SerialNumber: "01"}
			})

			tm := &AgentManager{accessToken: "test-token", certificateStates: map[int]*CertificateState{1: {}}}
			require.NoError(t, tm.FetchCertificate(1, cert))

			content, err := os.ReadFile(cert.FileConfig.Certificate.Path)
			require.NoError(t, err)
			assert.Equal(t, pemCertificateBlocks([]byte(tc.wantCert)), pemCertificateBlocks(content))
			if tc.wantChain != "" {
				content, err = os.ReadFile(cert.FileConfig.Chain.Path)
				require.NoError(t, err)
				assert.Equal(t, tc.wantChain, string(content))
			}
			info, err := os.Stat(cert.FileConfig.Certificate.Path)
			require.NoError(t, err)
			assert.Equal(t, tc.wantRewrite, !info.ModTime().Equal(modifiedAt))
			assert.Equal(t, "active", tm.certificateStates[1].Status)
		})
	}
}

func TestFetchCertificate_RestartKeepsMatchingFilesWhenBundleIsUnavailable(t *testing.T) {
	leaf := selfSignedPEM(t, "leaf")
	cert := distributionConfigWithKeyPath(t.TempDir())
	cert.FileConfig.CombineCertificateChain = true
	require.NoError(t, os.WriteFile(cert.FileConfig.Certificate.Path, []byte(leaf), 0600))

	bundleCalls := mockCertificateServer(t, func() (int, api.CertificateBundleResponse) {
		return http.StatusInternalServerError, api.CertificateBundleResponse{}
	})

	tm := &AgentManager{accessToken: "test-token", certificateStates: map[int]*CertificateState{1: {}}}
	require.NoError(t, tm.FetchCertificate(1, cert))
	assert.Equal(t, int32(1), bundleCalls.Load())
	assert.Equal(t, "active", tm.certificateStates[1].Status)
	assert.Zero(t, tm.certificateStates[1].RetryCount)

	require.NoError(t, tm.SyncFetchedCertificate(1, cert))
	assert.Equal(t, int32(1), bundleCalls.Load(), "a delivered certificate is not fetched again")
}

func TestCheckCertificateRequestStatusByID_FillsMissingChain(t *testing.T) {
	leaf := selfSignedPEM(t, "renewed leaf")
	intermediate := selfSignedPEM(t, "intermediate")

	for _, tc := range []struct {
		name       string
		bodyStatus int
		wantErr    bool
	}{
		{name: "chain read from the issued certificate", bodyStatus: http.StatusOK},
		{name: "error when the chain cannot be read", bodyStatus: http.StatusInternalServerError, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/cert-manager/certificates/certificate-requests/req-1":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"status": "issued", "certificate": leaf, "certificateId": "cert-02", "serialNumber": "02",
					})
				case "/v1/cert-manager/certificates/cert-02/certificate":
					w.WriteHeader(tc.bodyStatus)
					_ = json.NewEncoder(w).Encode(api.CertificateBodyResponse{Certificate: leaf, CertificateChain: intermediate, SerialNumber: "02"})
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)
			withMockInfisicalURL(t, server.URL)

			tm := &AgentManager{accessToken: "test-token"}
			status, response, err := tm.checkCertificateRequestStatusByID("req-1")
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, response)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "issued", status)
			assert.Equal(t, intermediate, response.Certificate.CertificateChain)

			cert := distributionConfigWithKeyPath(t.TempDir())
			cert.FileConfig.CombineCertificateChain = true
			require.NoError(t, tm.WriteCertificateFiles(cert, response))
			content, err := os.ReadFile(cert.FileConfig.Certificate.Path)
			require.NoError(t, err)
			assert.Len(t, pemCertificateBlocks(content), 2)
		})
	}
}
