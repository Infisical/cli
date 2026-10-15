package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
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

type testCertificateChain struct {
	leaf, intermediate, root string
}

func newTestCertificateChain(t *testing.T) testCertificateChain {
	t.Helper()
	issue := func(cn string, serial int64, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  isCA,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		}
		if parent == nil {
			parent, parentKey = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
		require.NoError(t, err)
		parsed, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return parsed, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	root, rootKey, rootPEM := issue("root", 100, true, nil, nil)
	intermediate, intermediateKey, intermediatePEM := issue("intermediate", 200, true, root, rootKey)
	_, _, leafPEM := issue("leaf", 1, false, intermediate, intermediateKey)
	return testCertificateChain{leaf: leafPEM, intermediate: intermediatePEM, root: rootPEM}
}

func TestWithoutRootCertificates(t *testing.T) {
	c := newTestCertificateChain(t)
	assert.Equal(t, c.intermediate, withoutRootCertificates(c.intermediate+c.root))
	assert.Equal(t, c.intermediate, withoutRootCertificates(c.intermediate))
	assert.Equal(t, "", withoutRootCertificates(c.root))

	cert := distributionConfigWithKeyPath(t.TempDir())
	assert.Equal(t, c.intermediate, chainToWrite(cert, c.intermediate+c.root))
	keepRoot := false
	cert.FileConfig.Chain.OmitRoot = &keepRoot
	assert.Equal(t, c.intermediate+c.root, chainToWrite(cert, c.intermediate+c.root))
}

func TestFetchCertificate_RestartRewritesOnlyOutdatedFiles(t *testing.T) {
	c := newTestCertificateChain(t)
	rotated := newTestCertificateChain(t)
	combined := c.leaf + c.intermediate

	for _, tc := range []struct {
		name        string
		combine     bool
		chain       string
		certOnDisk  string
		chainOnDisk string
		wantCert    string
		wantChain   string
		wantRewrite bool
		wantBundle  bool
	}{
		{name: "separate files up to date", chain: c.intermediate, certOnDisk: c.leaf, chainOnDisk: c.intermediate, wantCert: c.leaf, wantChain: c.intermediate},
		{name: "combined file up to date", combine: true, chain: c.intermediate, certOnDisk: combined, wantCert: combined, wantBundle: true},
		{name: "chainless combined file up to date", combine: true, certOnDisk: c.leaf, wantCert: c.leaf, wantBundle: true},
		{name: "combined file without root matches a bundle with root", combine: true, chain: c.intermediate + c.root, certOnDisk: combined, wantCert: combined, wantBundle: true},
		{name: "leaf-only file converted to combined", combine: true, chain: c.intermediate, certOnDisk: c.leaf, chainOnDisk: c.intermediate, wantCert: combined, wantChain: c.intermediate, wantRewrite: true, wantBundle: true},
		{name: "combined file split after opting out", chain: c.intermediate, certOnDisk: combined, chainOnDisk: c.intermediate, wantCert: c.leaf, wantChain: c.intermediate, wantRewrite: true, wantBundle: true},
		{name: "rotated chain refreshed in combined file", combine: true, chain: rotated.intermediate, certOnDisk: combined, wantCert: c.leaf + rotated.intermediate, wantRewrite: true, wantBundle: true},
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

			bundleCalls := mockCertificateServer(t, func() (int, api.CertificateBundleResponse) {
				return http.StatusOK, api.CertificateBundleResponse{Certificate: c.leaf, CertificateChain: tc.chain, PrivateKey: "private key", SerialNumber: "01"}
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
			assert.Equal(t, tc.wantBundle, bundleCalls.Load() > 0)
			assert.Equal(t, "active", tm.certificateStates[1].Status)
		})
	}
}

func TestFetchCertificate_RestartKeepsMatchingFilesWhenBundleIsUnavailable(t *testing.T) {
	leaf := newTestCertificateChain(t).leaf
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
	c := newTestCertificateChain(t)
	leaf, intermediate := c.leaf, c.intermediate

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

func TestIssueCertificate_SendsRemoveRootsAtTopLevel(t *testing.T) {
	keepRoot := false
	for _, tc := range []struct {
		name     string
		omitRoot *bool
		want     any
	}{
		{name: "default omits root", want: true},
		{name: "omit-root false keeps root", omitRoot: &keepRoot, want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&body)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			t.Cleanup(server.Close)
			withMockInfisicalURL(t, server.URL)

			cert := distributionConfigWithKeyPath(t.TempDir())
			cert.CertificateID = ""
			cert.ProfileID = "profile-1"
			cert.Attributes = &CertificateAttributes{CommonName: "app.example.com"}
			cert.FileConfig.Chain.OmitRoot = tc.omitRoot
			tm := &AgentManager{accessToken: "test-token", certificateStates: map[int]*CertificateState{1: {}}}
			_ = tm.IssueCertificate(1, cert)

			assert.Equal(t, tc.want, body["removeRootsFromChain"])
			attributes, _ := body["attributes"].(map[string]any)
			assert.NotContains(t, attributes, "removeRootsFromChain")
		})
	}
}
