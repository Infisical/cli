//go:build !pkcs11

package gatewayv2

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
)

const (
	releaseURLBase            = "https://github.com/Infisical/cli/releases/download"
	envReleaseURLBaseOverride = "INFISICAL_PKCS11_RELEASE_URL_BASE"
)

var pkcs11HTTPClient = &http.Client{Timeout: 90 * time.Second}

func pkcs11TarballName(version, goos, goarch string) string {
	return fmt.Sprintf("infisical-pkcs11_%s_%s_%s.tar.gz", version, goos, goarch)
}

func MaybeExecPkcs11Launcher(pkcs11ModulePath string, originalArgs []string) error {
	if strings.TrimSpace(pkcs11ModulePath) == "" {
		return nil
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("--pkcs11-module is only supported on Linux (detected %s)", runtime.GOOS)
	}
	if util.IsDevelopmentMode() {
		return fmt.Errorf("--pkcs11-module auto-download is not available in development builds")
	}
	binPath, err := ensurePkcs11Binary(util.CLI_VERSION, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("failed to provision infisical-pkcs11: %w", err)
	}
	newArgv := append([]string{binPath}, originalArgs[1:]...)
	return syscall.Exec(binPath, newArgv, os.Environ())
}

func ensurePkcs11Binary(version, goos, goarch string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	binDir := filepath.Join(home, ".infisical", "bin")
	binPath := filepath.Join(binDir, "infisical-pkcs11")
	verPath := binPath + ".version"

	if cached, err := os.ReadFile(verPath); err == nil && strings.TrimSpace(string(cached)) == version {
		if _, err := os.Stat(binPath); err == nil {
			return binPath, nil
		}
	}

	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}

	base := releaseURLBase
	if override := os.Getenv(envReleaseURLBaseOverride); override != "" {
		base = strings.TrimRight(override, "/")
	}
	tarName := pkcs11TarballName(version, goos, goarch)
	sumsURL := fmt.Sprintf("%s/v%s/checksums.txt", base, version)
	tarURL := fmt.Sprintf("%s/v%s/%s", base, version, tarName)

	log.Info().Str("version", version).Msg("installing infisical-pkcs11 (one-time setup)")

	expectedSum, err := fetchChecksum(sumsURL, tarName)
	if err != nil {
		return "", err
	}
	tarBytes, actualSum, err := downloadAndHash(tarURL)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(actualSum, expectedSum) {
		return "", fmt.Errorf("checksum mismatch for %s", tarName)
	}
	if err := extractPkcs11FromTarball(tarBytes, binPath); err != nil {
		return "", err
	}
	if err := os.WriteFile(verPath, []byte(version), 0o644); err != nil {
		return "", err
	}
	log.Info().Str("path", binPath).Msg("infisical-pkcs11 installed")
	return binPath, nil
}

func downloadAndHash(url string) ([]byte, string, error) {
	resp, err := pkcs11HTTPClient.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:]), nil
}

func fetchChecksum(url, filename string) (string, error) {
	resp, err := pkcs11HTTPClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[1] == filename {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("checksum for %s not found in %s", filename, url)
}

func extractPkcs11FromTarball(tarGz []byte, outPath string) error {
	gz, err := gzip.NewReader(bytes.NewReader(tarGz))
	if err != nil {
		return err
	}
	defer gz.Close() //nolint:errcheck
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != "infisical-pkcs11" {
			continue
		}
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close() //nolint:errcheck
			return err
		}
		return out.Close()
	}
	return fmt.Errorf("infisical-pkcs11 binary not found in tarball")
}
