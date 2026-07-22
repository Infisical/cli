package sandbox

import (
	"sort"
	"strconv"
	"strings"
)

// generateSeatbeltProfile builds the SBPL (Seatbelt profile language) string for a spec. It is a pure
// function (no OS calls) so it can be golden-tested on any platform.
//
// The profile grants the minimal baseline a process needs to run, with two deliberate deltas for our
// credential boundary:
//
//  1. The keychain mach services (com.apple.securityd.xpc, com.apple.SecurityServer) are OMITTED from
//     the allow-list, so (deny default) blocks them and the child cannot read the developer's login
//     token from the keyring. We block by omission, never by an explicit deny against a broad allow.
//  2. trustd.agent is likewise omitted; system-root TLS relies on the injected CA bundle instead.
//     This is what makes the keychain block TLS-safe: keychain and TLS trust are separate services.
//
// Egress is filtered on (remote ip ...), never (local ip ...): a local filter is evaluated against
// the source address, which for an unbound socket is the any-address, so it would silently admit all
// egress.
func generateSeatbeltProfile(spec SandboxSpec) string {
	var b []string
	add := func(lines ...string) { b = append(b, lines...) }

	add(
		"(version 1)",
		"(deny default)",
		"",
		"; Process",
		"(allow process-exec)",
		"(allow process-fork)",
		"(allow process-info* (target same-sandbox))",
		"(allow signal (target same-sandbox))",
		"(allow mach-priv-task-port (target same-sandbox))",
		"",
		"(allow user-preference-read)",
		"",
		"; Baseline mach services a process needs to boot, minus the keychain services so the login",
		"; token is unreadable, and minus trustd so system-root TLS falls back to the injected CA bundle.",
		"(allow mach-lookup",
		`  (global-name "com.apple.audio.systemsoundserver")`,
		`  (global-name "com.apple.distributed_notifications@Uv3")`,
		`  (global-name "com.apple.FontObjectsServer")`,
		`  (global-name "com.apple.fonts")`,
		`  (global-name "com.apple.logd")`,
		`  (global-name "com.apple.lsd.mapdb")`,
		`  (global-name "com.apple.system.logger")`,
		`  (global-name "com.apple.system.notification_center")`,
		`  (global-name "com.apple.system.opendirectoryd.libinfo")`,
		`  (global-name "com.apple.system.opendirectoryd.membership")`,
		`  (global-name "com.apple.bsd.dirhelper")`,
		`  (global-name "com.apple.coreservices.launchservicesd")`,
		")",
		"",
		"; POSIX IPC",
		"(allow ipc-posix-shm)",
		"(allow ipc-posix-sem)",
		"",
		"; IOKit",
		"(allow iokit-open",
		`  (iokit-registry-entry-class "IOSurfaceRootUserClient")`,
		`  (iokit-registry-entry-class "RootDomainUserClient")`,
		`  (iokit-user-client-class "IOSurfaceSendRight")`,
		")",
		"(allow iokit-get-properties)",
		"",
		"; System info",
		"(allow sysctl-read)",
		"(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))",
		"",
		"; Device files",
		`(allow file-ioctl (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/dtracehelper") (literal "/dev/tty"))`,
		"",
		"; Pseudo-terminal (interactive TUIs need a real pty)",
		"(allow pseudo-tty)",
		`(allow file-ioctl (literal "/dev/ptmx") (regex #"^/dev/ttys"))`,
		`(allow file-read* file-write* (literal "/dev/ptmx") (regex #"^/dev/ttys"))`,
		"",
	)

	// Network. (deny default) already blocks external egress; we allow loopback to the proxy port and
	// local binding (so agents can run dev servers). Outbound stays pinned to the proxy port only.
	add("; Network")
	port := strconv.Itoa(spec.LoopbackPort)
	add(
		`(allow network-bind (local ip "*:*"))`,
		`(allow network-inbound (local ip "*:*"))`,
		`(allow network-outbound (remote ip "localhost:`+port+`"))`,
	)
	add("")

	// File read: broad allow, then subtract the credential deny paths (last-match-wins in SBPL).
	add("; File read")
	add("(allow file-read*)")
	for _, p := range dedupeSorted(spec.DenyPaths) {
		add(`(deny file-read* (subpath ` + escapeSBPL(p) + `))`)
	}
	add("")

	// File write: cwd, tmp, tempdir, and any operator-granted write paths.
	add("; File write")
	writePaths := dedupeSorted(append([]string{spec.Cwd, spec.TempDir, "/tmp", "/private/tmp", "/dev/null"}, spec.WritePaths...))
	for _, p := range writePaths {
		if p == "" {
			continue
		}
		if p == "/dev/null" {
			add(`(allow file-write* (literal "/dev/null"))`)
			continue
		}
		add(`(allow file-write* (subpath ` + escapeSBPL(p) + `))`)
	}

	return strings.Join(b, "\n") + "\n"
}

func dedupeSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// escapeSBPL quotes a path as an SBPL string literal. SBPL uses C-style double-quoted strings, so
// backslash and double-quote must be escaped.
func escapeSBPL(p string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range p {
		switch r {
		case '\\':
			sb.WriteString(`\\`)
		case '"':
			sb.WriteString(`\"`)
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}
