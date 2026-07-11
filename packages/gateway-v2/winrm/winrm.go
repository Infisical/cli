// Package winrm delivers files to, and runs commands on, Windows hosts over WinRM
// on behalf of the Infisical control plane, which cannot reach the host directly.
package winrm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/masterzen/winrm"
)

// ErrConnect marks a failure to reach or authenticate to the Windows host.
var ErrConnect = errors.New("failed to connect to the Windows host over WinRM")

const commandDeadline = 60 * time.Second

type Credentials struct {
	Host     string
	Port     int
	Username string
	Password string
	UseHTTPS bool
	// Insecure skips TLS verification (HTTPS only); ignored for plain HTTP.
	Insecure bool
}

type FileDelivery struct {
	Path    string
	Content []byte
}

// transportDecorator selects the WinRM transport: NTLM message encryption over plain HTTP so the
// payload is never sent in cleartext, or plain NTLM auth over HTTPS where TLS handles confidentiality.
func transportDecorator(useHTTPS bool) (func() winrm.Transporter, error) {
	if useHTTPS {
		return func() winrm.Transporter { return &winrm.ClientNTLM{} }, nil
	}
	enc, err := winrm.NewEncryption("ntlm")
	if err != nil {
		return nil, fmt.Errorf("%w: failed to initialize NTLM message encryption: %v", ErrConnect, err)
	}
	return func() winrm.Transporter { return enc }, nil
}

func newClient(creds Credentials) (*winrm.Client, error) {
	params := *winrm.DefaultParameters

	decorator, err := transportDecorator(creds.UseHTTPS)
	if err != nil {
		return nil, err
	}
	params.TransportDecorator = decorator

	endpoint := winrm.NewEndpoint(
		creds.Host,
		creds.Port,
		creds.UseHTTPS,
		creds.Insecure,
		nil, nil, nil,
		commandDeadline,
	)
	client, err := winrm.NewClientWithParameters(endpoint, creds.Username, creds.Password, &params)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnect, err)
	}
	return client, nil
}

// run executes a PowerShell script and returns its trimmed stdout; a non-zero exit is an error.
func run(ctx context.Context, client *winrm.Client, script string) (string, error) {
	var stdout, stderr bytes.Buffer
	code, err := client.RunWithContext(ctx, winrm.Powershell(script), &stdout, &stderr)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrConnect, err)
	}
	if code != 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return "", fmt.Errorf("command failed (exit %d): %s", code, truncate(msg, 500))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// Ping proves reachability and authentication without touching the filesystem.
func Ping(ctx context.Context, creds Credentials) error {
	client, err := newClient(creds)
	if err != nil {
		return err
	}
	_, err = run(ctx, client, `$ProgressPreference='SilentlyContinue'; Write-Output ('OK='+[System.Environment]::MachineName)`)
	return err
}

// b64ChunkSize keeps each PowerShell command under the Windows command-line limit (~8191 chars),
// so a file's base64 is appended to a staging file in chunks rather than inlined in one command.
const b64ChunkSize = 2000

// DeliverFiles writes each file atomically (temp file + Move-Item), creating the parent dir if missing.
func DeliverFiles(ctx context.Context, creds Credentials, files []FileDelivery) error {
	client, err := newClient(creds)
	if err != nil {
		return err
	}
	// Clear staging files left by a previously interrupted delivery, once per directory.
	swept := map[string]bool{}
	for _, f := range files {
		dir := winParentDir(f.Path)
		if dir != "" && !swept[dir] {
			swept[dir] = true
			sweepStaleStaging(ctx, client, dir)
		}
	}
	for _, f := range files {
		if err := deliverOne(ctx, client, f); err != nil {
			return fmt.Errorf("failed to write %q: %w", f.Path, err)
		}
	}
	return nil
}

// stagingMarker suffixes staging files so a sweep can find leftovers; the random token avoids collisions.
const stagingMarker = ".infisical."

func winParentDir(p string) string {
	i := strings.LastIndexAny(p, "\\/")
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// sweepStaleStaging best-effort removes stagingMarker files older than 60s; failures never block a delivery.
func sweepStaleStaging(ctx context.Context, client *winrm.Client, dir string) {
	script := fmt.Sprintf(
		`$ErrorActionPreference='SilentlyContinue'; $d='%s'; `+
			`if (Test-Path -LiteralPath $d) { $cut=(Get-Date).AddSeconds(-60); `+
			`Get-ChildItem -LiteralPath $d -File -Filter '*%s*' | Where-Object { $_.LastWriteTime -lt $cut } | Remove-Item -Force }`,
		psSingleQuote(dir), stagingMarker,
	)
	_, _ = run(ctx, client, script)
}

func deliverOne(ctx context.Context, client *winrm.Client, f FileDelivery) error {
	pathLit := psSingleQuote(f.Path)
	b64 := base64.StdEncoding.EncodeToString(f.Content)
	token := make([]byte, 6)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("failed to generate staging token: %w", err)
	}
	b64Ext := fmt.Sprintf("%s%s.b64", stagingMarker, hex.EncodeToString(token))
	tmpExt := fmt.Sprintf("%s%s.tmp", stagingMarker, hex.EncodeToString(token))

	init := fmt.Sprintf(
		`$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; `+
			`$p='%s'; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null; `+
			`$b64=$p+'%s'; if (Test-Path -LiteralPath $b64) { Remove-Item -Force -LiteralPath $b64 }; `+
			`New-Item -ItemType File -Force -Path $b64 | Out-Null`,
		pathLit, b64Ext,
	)
	if _, err := run(ctx, client, init); err != nil {
		return err
	}

	for i := 0; i < len(b64); i += b64ChunkSize {
		end := i + b64ChunkSize
		if end > len(b64) {
			end = len(b64)
		}
		// base64 is [A-Za-z0-9+/=] only, so it needs no escaping inside single quotes.
		appendCmd := fmt.Sprintf(
			`$ErrorActionPreference='Stop'; $b64='%s'+'%s'; `+
				`[IO.File]::AppendAllText($b64,'%s')`,
			pathLit, b64Ext, b64[i:end],
		)
		if _, err := run(ctx, client, appendCmd); err != nil {
			return err
		}
	}

	// Verify the file exists after the move so a silently-normalized destination isn't reported as success.
	finalize := fmt.Sprintf(
		`$ErrorActionPreference='Stop'; $p='%s'; $b64=$p+'%s'; $tmp=$p+'%s'; `+
			`[IO.File]::WriteAllBytes($tmp,[Convert]::FromBase64String([IO.File]::ReadAllText($b64))); `+
			`Move-Item -Force -LiteralPath $tmp -Destination $p; Remove-Item -Force -LiteralPath $b64; `+
			`if (-not (Test-Path -LiteralPath $p)) { throw ('file not found after write: '+$p) }; `+
			`Write-Output ('WROTE='+$p)`,
		pathLit, b64Ext, tmpExt,
	)
	if _, err := run(ctx, client, finalize); err != nil {
		return err
	}
	return nil
}

// RemoveFiles deletes each path if it exists. A missing file is not an error.
func RemoveFiles(ctx context.Context, creds Credentials, paths []string) error {
	client, err := newClient(creds)
	if err != nil {
		return err
	}
	for _, p := range paths {
		script := fmt.Sprintf(
			`$ErrorActionPreference='Stop'; $p='%s'; `+
				`if (Test-Path -LiteralPath $p) { Remove-Item -Force -LiteralPath $p }; Write-Output ('REMOVED='+$p)`,
			psSingleQuote(p),
		)
		if _, err := run(ctx, client, script); err != nil {
			return fmt.Errorf("failed to remove %q: %w", p, err)
		}
	}
	return nil
}

// psSingleQuote escapes a value for a PowerShell single-quoted string by doubling the single quote.
func psSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Back up to a rune boundary so we don't split a multibyte character and emit invalid UTF-8.
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
