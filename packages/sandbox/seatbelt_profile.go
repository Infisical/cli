package sandbox

import (
	"strconv"
	"strings"
)

// generateSeatbeltProfile builds the SBPL profile for a spec. Pure (no OS calls), golden-testable.
// The keychain services (securityd.xpc, SecurityServer) and trustd are deliberately omitted from the
// allow-list, so (deny default) blocks keyring reads while injected-CA TLS still works.
func generateSeatbeltProfile(spec Spec) string {
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
		// DNS is omitted as deliberately as the keychain: the proxy resolves on the host, so the child
		// needs no resolver. Without one, a proxy-ignoring client fails loudly instead of leaking, and
		// DNS cannot be used to exfiltrate. Do not add mDNSResponder here.
		"; Baseline mach services (keychain + DNS deliberately omitted; trustd gated on AllowTrustd)",
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

	if spec.AllowTrustd {
		// Cert-trust evaluation only.
		add(
			"; trustd: cert-trust evaluation",
			`(allow mach-lookup (global-name "com.apple.trustd") (global-name "com.apple.trustd.agent"))`,
			"",
		)
	}

	// Egress must be filtered on `remote ip`, not `local ip` (a local filter matches the any-address
	// and would admit all egress). Bind/inbound are wildcarded so agents can run local dev servers.
	add("; Network")
	add(
		`(allow network-bind (local ip "*:*"))`,
		`(allow network-inbound (local ip "*:*"))`,
	)
	if spec.NetMode == SharedNet {
		// SharedNet keeps only the credential and filesystem controls. It is for callers that have no
		// proxy to route through, so the child reaches the network itself and needs a resolver to do it.
		// mDNSResponder is allowed in this branch alone: granting it above would hand the hard fence the
		// DNS exfil channel its loopback-only egress rule exists to deny.
		add(
			`(allow network-outbound)`,
			`(allow mach-lookup (global-name "com.apple.mDNSResponder"))`,
		)
	} else {
		add(`(allow network-outbound (remote ip "localhost:` + strconv.Itoa(spec.LoopbackPort) + `"))`)
	}
	add("")

	// Broad read, then subtract the credential deny paths (SBPL is last-match-wins).
	add("; File read")
	add("(allow file-read*)")
	for _, p := range dedupeSorted(spec.DenyPaths) {
		add(`(deny file-read* (subpath ` + escapeSBPL(p) + `))`)
	}
	add("")

	// --allow-read exceptions land after the denies but before the write section, so the trailing write
	// denies still apply: an excepted path becomes readable, not writable, and its siblings stay denied.
	if exceptions := dedupeSorted(spec.ReadPaths); len(exceptions) > 0 {
		add("; Read exceptions (--allow-read): re-open specific paths inside the denied set")
		for _, p := range exceptions {
			add(`(allow file-read* (subpath ` + escapeSBPL(p) + `))`)
		}
		add("")
	}

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
	add("")

	// Re-deny writes after the write allows (last-match-wins), so running the agent from $HOME cannot
	// use its writable cwd to append to ~/.ssh/authorized_keys.
	add("; Credential paths: deny writes too (not just reads)")
	for _, p := range dedupeSorted(spec.DenyPaths) {
		add(`(deny file-write* (subpath ` + escapeSBPL(p) + `))`)
	}

	return strings.Join(b, "\n") + "\n"
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
