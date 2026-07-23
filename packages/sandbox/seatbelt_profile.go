package sandbox

import (
	"sort"
	"strconv"
	"strings"
)

// generateSeatbeltProfile builds the SBPL profile for a spec. Pure (no OS calls), golden-testable.
// The keychain services (securityd.xpc, SecurityServer) and trustd are deliberately omitted from the
// allow-list, so (deny default) blocks keyring reads while injected-CA TLS still works.
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
		"; Baseline mach services (keychain services and trustd deliberately omitted)",
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

	// Egress must be filtered on `remote ip`, not `local ip` (a local filter matches the any-address
	// and would admit all egress). Bind/inbound are wildcarded so agents can run local dev servers.
	add("; Network")
	port := strconv.Itoa(spec.LoopbackPort)
	add(
		`(allow network-bind (local ip "*:*"))`,
		`(allow network-inbound (local ip "*:*"))`,
		`(allow network-outbound (remote ip "localhost:`+port+`"))`,
	)
	add("")

	// Broad read, then subtract the credential deny paths (SBPL is last-match-wins).
	add("; File read")
	add("(allow file-read*)")
	for _, p := range dedupeSorted(spec.DenyPaths) {
		add(`(deny file-read* (subpath ` + escapeSBPL(p) + `))`)
	}
	add("")

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

// escapeSBPL quotes a path as an SBPL (C-style) string literal.
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
