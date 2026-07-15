// Package winrm delivers files to, and runs commands on, Windows hosts over WinRM
// on behalf of the Infisical control plane, which cannot reach the host directly.
package winrm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/masterzen/winrm"
)

// ErrConnect marks a failure to reach the Windows host.
var ErrConnect = errors.New("failed to connect to the Windows host over WinRM")

// ErrAuth marks the listener rejecting the credentials, as opposed to being unreachable.
var ErrAuth = errors.New("WinRM authentication failed")

// wrapTransportError maps a rejected login (which the library surfaces as an HTTP 401) to ErrAuth and
// any other transport failure to ErrConnect, so an auth problem is not reported as an unreachable host.
func wrapTransportError(err error) error {
	if strings.Contains(err.Error(), "401") {
		return fmt.Errorf(
			"%w: the WinRM listener rejected the credentials (HTTP 401). Verify the username and password, "+
				"and that the listener allows Negotiate/NTLM authentication",
			ErrAuth,
		)
	}
	return fmt.Errorf("%w: %v", ErrConnect, err)
}

const commandDeadline = 60 * time.Second

type Credentials struct {
	Host     string
	Port     int
	Username string
	Password string
	// UseHTTPS selects the transport: false (default) uses HTTP with NTLM message encryption, which
	// needs no server certificate; true uses HTTPS.
	UseHTTPS bool
	// Insecure skips TLS certificate verification (HTTPS only): confidentiality without server authentication.
	Insecure bool
	// CACert, when set (HTTPS only), is a PEM bundle used to verify a self-signed listener's certificate
	// so it can be authenticated without a publicly trusted CA.
	CACert []byte
}

type FileDelivery struct {
	Path    string
	Content []byte
}

// AccessRule grants a Windows principal a level of access on the delivered files, applied additively
// with icacls (inherited permissions are kept). Access is one of "read", "modify", "full-control".
type AccessRule struct {
	Identity string
	Access   string
}

// icaclsRights maps a control-plane access level to the icacls simple-rights code.
func icaclsRights(access string) (string, error) {
	switch access {
	case "read":
		return "R", nil
	case "modify":
		return "M", nil
	case "full-control":
		return "F", nil
	default:
		return "", fmt.Errorf("unsupported access level %q", access)
	}
}

// aclGrantArgs builds the ` /grant '<identity>:(<rights>)'` fragment for each rule, escaping the
// identity for a PowerShell single-quoted literal so it cannot break out of the command.
func aclGrantArgs(rules []AccessRule) (string, error) {
	var sb strings.Builder
	for _, r := range rules {
		if r.Identity == "" {
			return "", fmt.Errorf("access rule identity is required")
		}
		rights, err := icaclsRights(r.Access)
		if err != nil {
			return "", err
		}
		sb.WriteString(fmt.Sprintf(" /grant '%s:(%s)'", escapePowerShellSingleQuotes(r.Identity), rights))
	}
	return sb.String(), nil
}

// maxWinRMReadBytes caps bytes read from a host, bounding one that streams an endless body; command
// responses are tiny, so this never limits real use.
const maxWinRMReadBytes = 32 * 1024 * 1024

// limitedConn fails the read once maxWinRMReadBytes are consumed; the winrm library reads bodies unbounded.
type limitedConn struct {
	net.Conn
	remaining int64
}

func (c *limitedConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, fmt.Errorf("winrm response exceeded %d bytes", maxWinRMReadBytes)
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// boundedDial returns a dialer whose connection carries the operation deadline and read cap, since the
// library issues its HTTP request without a context.
func boundedDial(ctx context.Context) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		return &limitedConn{Conn: conn, remaining: maxWinRMReadBytes}, nil
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// cappedBody fails the read once maxWinRMReadBytes have been consumed.
type cappedBody struct {
	io.ReadCloser
	remaining int64
}

func (c *cappedBody) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, fmt.Errorf("winrm response exceeded %d bytes", maxWinRMReadBytes)
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.ReadCloser.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// winrmSOAPPath is the WS-Management endpoint every WinRM request targets; the response cap keys off it
// so only WinRM traffic is bounded.
const winrmSOAPPath = "/wsman"

var installHTTPResponseCapOnce sync.Once

// InstallHTTPResponseCap bounds response reads on the HTTP (NTLM message-sealing) transport, which uses
// masterzen's Encryption. That transport uses a bare *http.Client with no hook for a custom transport, so
// wrapping http.DefaultTransport is the only way to cap it without forking the library. The wrapper only
// caps requests to the WinRM WS-Management path ("/wsman") and passes every other request through unchanged,
// so it does not affect any other use of the default transport. Call once at startup, before serving.
func InstallHTTPResponseCap() {
	installHTTPResponseCapOnce.Do(func() {
		base := http.DefaultTransport
		http.DefaultTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			resp, err := base.RoundTrip(req)
			if err != nil || resp == nil || resp.Body == nil {
				return resp, err
			}
			if req.URL != nil && req.URL.Path == winrmSOAPPath {
				resp.Body = &cappedBody{ReadCloser: resp.Body, remaining: maxWinRMReadBytes}
			}
			return resp, nil
		})
	})
}

// pinnedServerName returns the name to verify a pinned cert against: its first DNS SAN, else its
// Common Name. Empty when no CA is pinned or the PEM cannot be parsed.
func pinnedServerName(caCert []byte) string {
	if len(caCert) == 0 {
		return ""
	}
	block, _ := pem.Decode(caCert)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return cert.Subject.CommonName
}

// newClient builds a WinRM client. Both modes authenticate with NTLM; they differ in how the SOAP body
// is kept confidential. HTTP (default) uses NTLM message sealing, so the body is confidential without a
// server certificate (default listeners require this). HTTPS relies on TLS, verifying the listener against
// the system trust store, an optional pinned CA (self-signed listener), or skipping verification if Insecure.
func newClient(ctx context.Context, creds Credentials) (*winrm.Client, error) {
	params := *winrm.DefaultParameters
	if creds.UseHTTPS {
		// NTLM authentication over TLS. The bounded dial caps the response read and carries the operation
		// deadline; the library otherwise reads the body unbounded and issues its request without a context.
		params.TransportDecorator = func() winrm.Transporter { return winrm.NewClientNTLMWithDial(boundedDial(ctx)) }
	} else {
		// HTTP transport: NTLM message sealing provides confidentiality without a server certificate.
		// Confidentiality here depends on the encrypted session being established: masterzen's Encryption
		// falls back to unencrypted NTLM if sealing setup fails, and that fallback uses its own transport
		// (not http.DefaultTransport), so it cannot be intercepted without forking the library. An active
		// MITM that forces the setup to fail could therefore read a delivery in cleartext. Use HTTPS when
		// the gateway-to-host segment is not trusted.
		enc, err := winrm.NewEncryption("ntlm")
		if err != nil {
			return nil, fmt.Errorf("%w: failed to initialize NTLM message encryption: %v", ErrConnect, err)
		}
		params.TransportDecorator = func() winrm.Transporter { return enc }
	}

	endpoint := winrm.NewEndpoint(
		creds.Host,
		creds.Port,
		creds.UseHTTPS,
		creds.Insecure,
		creds.CACert,
		nil, nil,
		commandDeadline,
	)

	// When verifying against a pinned CA, verify the presented cert against the pinned cert's own name
	// rather than the connection host: WinRM hosts are often reached by IP while the listener cert is
	// issued for the machine name. Chain validation against the pinned CA still stops a MITM.
	if creds.UseHTTPS && !creds.Insecure {
		if name := pinnedServerName(creds.CACert); name != "" {
			endpoint.TLSServerName = name
		}
	}

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
		return "", wrapTransportError(err)
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

// runSuppressingOutput runs a script whose text carries file content, returning a generic error on
// failure that never echoes the remote stdout/stderr (which could contain that content).
func runSuppressingOutput(ctx context.Context, client *winrm.Client, script string) error {
	var stdout, stderr bytes.Buffer
	code, err := client.RunWithContext(ctx, winrm.Powershell(script), &stdout, &stderr)
	if err != nil {
		return wrapTransportError(err)
	}
	if code != 0 {
		return fmt.Errorf("failed to stage file content (exit %d)", code)
	}
	return nil
}

// Ping proves reachability and authentication without touching the filesystem.
func Ping(ctx context.Context, creds Credentials) error {
	client, err := newClient(ctx, creds)
	if err != nil {
		return err
	}
	_, err = run(ctx, client, `$ProgressPreference='SilentlyContinue'; Write-Output ('OK='+[System.Environment]::MachineName)`)
	return err
}

// base64ChunkSize keeps each PowerShell command under the Windows command-line limit (~8191 chars),
// so a file's base64 is appended to a staging file in chunks rather than inlined in one command.
const base64ChunkSize = 2000

// DeliverFiles writes each file atomically (temp file + Move-Item), creating the parent dir if missing.
// Any accessRules are applied to each delivered file so, for example, only a chosen service account can
// read the private key.
func DeliverFiles(ctx context.Context, creds Credentials, files []FileDelivery, accessRules []AccessRule) error {
	client, err := newClient(ctx, creds)
	if err != nil {
		return err
	}
	grantArgs, err := aclGrantArgs(accessRules)
	if err != nil {
		return err
	}
	// Clear staging files left by a previously interrupted delivery, once per directory.
	swept := map[string]bool{}
	for _, f := range files {
		dir := windowsParentDir(f.Path)
		if dir != "" && !swept[dir] {
			swept[dir] = true
			removeStaleStagingFiles(ctx, client, dir)
		}
	}
	for _, f := range files {
		if err := deliverFile(ctx, client, f, grantArgs); err != nil {
			return fmt.Errorf("failed to write %q: %w", f.Path, err)
		}
	}
	return nil
}

// stagingMarker suffixes staging files so a sweep can find leftovers; the random token avoids collisions.
const stagingMarker = ".infisical."

func windowsParentDir(p string) string {
	i := strings.LastIndexAny(p, "\\/")
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// removeStaleStagingFiles best-effort removes stagingMarker files older than 60s; failures never block a delivery.
func removeStaleStagingFiles(ctx context.Context, client *winrm.Client, dir string) {
	script := fmt.Sprintf(
		`$ErrorActionPreference='SilentlyContinue'; $d='%s'; `+
			`if (Test-Path -LiteralPath $d) { $cut=(Get-Date).AddSeconds(-60); `+
			`Get-ChildItem -LiteralPath $d -File -Filter '*%s*' | Where-Object { $_.LastWriteTime -lt $cut } | Remove-Item -Force }`,
		escapePowerShellSingleQuotes(dir), stagingMarker,
	)
	_, _ = run(ctx, client, script)
}

func deliverFile(ctx context.Context, client *winrm.Client, f FileDelivery, grantArgs string) (err error) {
	pathLit := escapePowerShellSingleQuotes(f.Path)
	b64 := base64.StdEncoding.EncodeToString(f.Content)
	token := make([]byte, 6)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("failed to generate staging token: %w", err)
	}
	b64Ext := fmt.Sprintf("%s%s.b64", stagingMarker, hex.EncodeToString(token))
	tmpExt := fmt.Sprintf("%s%s.tmp", stagingMarker, hex.EncodeToString(token))

	// Best-effort cleanup so a failed delivery leaves no staging files behind (the sweep is the backstop).
	defer func() {
		if err != nil {
			cleanup := fmt.Sprintf(
				`$ErrorActionPreference='SilentlyContinue'; $p='%s'; Remove-Item -Force -LiteralPath ($p+'%s'),($p+'%s')`,
				pathLit, b64Ext, tmpExt,
			)
			_ = runSuppressingOutput(ctx, client, cleanup)
		}
	}()

	init := fmt.Sprintf(
		`$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; `+
			`$p='%s'; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null; `+
			`$b64=$p+'%s'; if (Test-Path -LiteralPath $b64) { Remove-Item -Force -LiteralPath $b64 }; `+
			`New-Item -ItemType File -Force -Path $b64 | Out-Null; `+
			`$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; `+
			`icacls $b64 /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" ('*'+$sid+':(F)') *>$null`,
		pathLit, b64Ext,
	)
	if _, err := run(ctx, client, init); err != nil {
		return err
	}

	for i := 0; i < len(b64); i += base64ChunkSize {
		end := i + base64ChunkSize
		if end > len(b64) {
			end = len(b64)
		}
		// base64 is [A-Za-z0-9+/=] only, so it needs no escaping inside single quotes.
		appendCmd := fmt.Sprintf(
			`$ErrorActionPreference='Stop'; $b64='%s'+'%s'; `+
				`[IO.File]::AppendAllText($b64,'%s')`,
			pathLit, b64Ext, b64[i:end],
		)
		if err := runSuppressingOutput(ctx, client, appendCmd); err != nil {
			return err
		}
	}

	// Lock the decoded staging file to SYSTEM/Administrators/current-user before writing the cleartext
	// bytes, matching the .b64 lockdown, so the plaintext key is never briefly readable via inherited
	// directory permissions. After the move, icacls /reset restores the destination to inherited-only,
	// leaving the delivered file's resting ACL unchanged (additive grants are applied separately below).
	// Verify the file exists after the move so a silently-normalized destination isn't reported as success.
	finalize := fmt.Sprintf(
		`$ErrorActionPreference='Stop'; $p='%s'; $b64=$p+'%s'; $tmp=$p+'%s'; `+
			`if (Test-Path -LiteralPath $tmp) { Remove-Item -Force -LiteralPath $tmp }; `+
			`New-Item -ItemType File -Force -Path $tmp | Out-Null; `+
			`$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; `+
			`icacls $tmp /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" ('*'+$sid+':(F)') *>$null; `+
			`[IO.File]::WriteAllBytes($tmp,[Convert]::FromBase64String([IO.File]::ReadAllText($b64))); `+
			`Move-Item -Force -LiteralPath $tmp -Destination $p; `+
			`icacls $p /reset *>$null; Remove-Item -Force -LiteralPath $b64; `+
			`if (-not (Test-Path -LiteralPath $p)) { throw ('file not found after write: '+$p) }; `+
			`Write-Output ('WROTE='+$p)`,
		pathLit, b64Ext, tmpExt,
	)
	if _, err := run(ctx, client, finalize); err != nil {
		return err
	}

	// Apply the requested ACL grants to the delivered file (additive: inherited permissions are kept).
	if grantArgs != "" {
		acl := fmt.Sprintf(
			`$ErrorActionPreference='Stop'; $p='%s'; icacls $p%s *>$null; `+
				`if ($LASTEXITCODE -ne 0) { throw ('failed to set permissions (icacls exit '+$LASTEXITCODE+')') }`,
			pathLit, grantArgs,
		)
		if _, err := run(ctx, client, acl); err != nil {
			return err
		}
	}
	return nil
}

// RemoveFiles deletes each path if it exists. A missing file is not an error.
func RemoveFiles(ctx context.Context, creds Credentials, paths []string) error {
	client, err := newClient(ctx, creds)
	if err != nil {
		return err
	}
	for _, p := range paths {
		script := fmt.Sprintf(
			`$ErrorActionPreference='Stop'; $p='%s'; `+
				`if (Test-Path -LiteralPath $p) { Remove-Item -Force -LiteralPath $p }; Write-Output ('REMOVED='+$p)`,
			escapePowerShellSingleQuotes(p),
		)
		if _, err := run(ctx, client, script); err != nil {
			return fmt.Errorf("failed to remove %q: %w", p, err)
		}
	}
	return nil
}

// escapePowerShellSingleQuotes escapes a value for a PowerShell single-quoted string by doubling the single quote.
func escapePowerShellSingleQuotes(s string) string {
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
