package cmd

import (
	"os"
	"path/filepath"
	"testing"

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
