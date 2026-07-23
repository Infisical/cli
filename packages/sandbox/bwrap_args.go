package sandbox

// BridgeLoopbackPort is the loopback port the in-namespace bridge listens on. Fixed is safe: each
// hard-fence run has its own empty netns, so it never collides across concurrent runs.
const BridgeLoopbackPort = 17321

// SupervisorSubcommand re-enters this binary as the in-namespace supervisor. Exported so the cmd
// package can register the matching hidden command.
const SupervisorSubcommand = "__sandbox-supervisor"

// buildBwrapArgv builds the bwrap argv for a spec. Pure (its filesystem dependency is injected via
// isFile, which reports whether a deny path is a regular file), so it is golden-testable.
//
// Deny paths are masked by type: /dev/null bind for files, empty tmpfs for directories. This is
// load-bearing, not cosmetic: mounting a tmpfs onto an existing file aborts bwrap at startup (ENOTDIR).
// Omits --new-session (setsid breaks the interactive TTY). On the hard fence the proxy's unix socket
// is bind-mounted and the supervisor bridges to it; shared net reaches host loopback directly.
func buildBwrapArgv(spec SandboxSpec, selfExe string, argv []string, isFile func(string) bool) []string {
	args := []string{
		"bwrap",
		"--unshare-all",
		"--die-with-parent",
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
	}

	if spec.NetMode == SharedNet {
		args = append(args, "--share-net")
	}

	for _, p := range dedupeSorted(spec.DenyPaths) {
		if isFile(p) {
			args = append(args, "--ro-bind", "/dev/null", p)
		} else {
			args = append(args, "--tmpfs", p)
		}
	}

	// Bound after --tmpfs /tmp so a tempdir under /tmp is not shadowed.
	if spec.Cwd != "" {
		args = append(args, "--bind", spec.Cwd, spec.Cwd)
	}
	if spec.TempDir != "" {
		args = append(args, "--bind", spec.TempDir, spec.TempDir)
	}
	for _, p := range dedupeSorted(spec.WritePaths) {
		args = append(args, "--bind", p, p)
	}

	args = append(args, "--")

	if spec.NetMode == HardFence && spec.ProxySocket != "" {
		args = append(args,
			selfExe, SupervisorSubcommand,
			"--port", itoa(spec.LoopbackPort),
			"--socket", spec.ProxySocket,
			"--",
		)
	}

	return append(args, argv...)
}

// itoa keeps this file dependency-free (no strconv).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
