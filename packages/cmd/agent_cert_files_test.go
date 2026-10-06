package cmd

import (
	"encoding/json"
	"fmt"
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
			assert.False(t, allConfiguredOutputsExist(&cert))

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
			assert.True(t, allConfiguredOutputsExist(&cert))
			require.NoError(t, os.Remove(cert.FileConfig.PrivateKey.Path))
			assert.False(t, allConfiguredOutputsExist(&cert))
		})
	}
}

func TestFetchCertificate_CombineCertificateChainAfterRestart(t *testing.T) {
	leaf := selfSignedPEM(t, "leaf")
	chain := selfSignedPEM(t, "intermediate")
	for _, tc := range []struct {
		combine bool
		chain   string
	}{
		{combine: false, chain: chain},
		{combine: true, chain: chain},
		{combine: true},
	} {
		t.Run(fmt.Sprintf("combine=%t/chain=%t", tc.combine, tc.chain != ""), func(t *testing.T) {
			cert := distributionConfigWithKeyPath(t.TempDir())
			cert.FileConfig.CombineCertificateChain = tc.combine
			cert.FileConfig.Chain.Path = filepath.Join(filepath.Dir(cert.FileConfig.Certificate.Path), "chain.pem")
			require.NoError(t, os.WriteFile(cert.FileConfig.Certificate.Path, []byte(leaf), 0600))
			require.NoError(t, os.WriteFile(cert.FileConfig.PrivateKey.Path, []byte("private key"), 0600))
			require.NoError(t, os.WriteFile(cert.FileConfig.Chain.Path, []byte(chain), 0600))
			require.True(t, serialMatchesCertificateOnDisk(cert, "01"))
			require.True(t, allConfiguredOutputsExist(cert))

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
					_ = json.NewEncoder(w).Encode(api.CertificateBundleResponse{
						Certificate: leaf, CertificateChain: tc.chain, PrivateKey: "private key", SerialNumber: "01",
					})
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)
			withMockInfisicalURL(t, server.URL)

			tm := &AgentManager{accessToken: "test-token", certificateStates: map[int]*CertificateState{1: {}}}
			require.NoError(t, tm.FetchCertificate(1, cert))
			content, err := os.ReadFile(cert.FileConfig.Certificate.Path)
			require.NoError(t, err)
			if tc.combine {
				assert.Equal(t, leaf+tc.chain, string(content))
				assert.Equal(t, int32(1), bundleCalls.Load())
			} else {
				assert.Equal(t, leaf, string(content))
				assert.Zero(t, bundleCalls.Load())
			}
			callsAfterRestart := bundleCalls.Load()
			require.NoError(t, tm.SyncFetchedCertificate(1, cert))
			assert.Equal(t, callsAfterRestart, bundleCalls.Load(), "unchanged certificates should not be fetched again")

			if tc.combine {
				require.NoError(t, os.Remove(cert.FileConfig.Chain.Path))
			}
			require.True(t, allConfiguredOutputsExist(cert))
			modifiedAt := time.Unix(1700000000, 0)
			require.NoError(t, os.Chtimes(cert.FileConfig.Certificate.Path, modifiedAt, modifiedAt))
			tm = &AgentManager{accessToken: "test-token", certificateStates: map[int]*CertificateState{1: {}}}
			require.NoError(t, tm.FetchCertificate(1, cert))
			if tc.combine && tc.chain == "" {
				assert.Equal(t, callsAfterRestart+1, bundleCalls.Load(), "leaf-only output needs a bundle check to confirm there is no chain")
			} else {
				assert.Equal(t, callsAfterRestart, bundleCalls.Load(), "already-combined output should not be fetched on restart")
			}
			info, err := os.Stat(cert.FileConfig.Certificate.Path)
			require.NoError(t, err)
			assert.Equal(t, modifiedAt, info.ModTime(), "unchanged output should not be rewritten on restart")
		})
	}
}
