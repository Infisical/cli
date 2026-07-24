package sandbox

// BridgeLoopbackPort is the loopback port the in-namespace bridge listens on. Fixed is safe: each
// hard-fence run has its own empty netns, so it never collides across concurrent runs.
const BridgeLoopbackPort = 17321

// SupervisorSubcommand re-enters this binary as the in-namespace supervisor. Exported so the cmd
// package can register the matching hidden command.
const SupervisorSubcommand = "__sandbox-supervisor"

// buildBwrapArgv builds the bwrap argv for a spec. Pure (its filesystem dependency is injected via
// classify, which reports whether a deny path exists and, if so, whether it is a regular file), so it
// is golden-testable.
//
// Deny paths are masked by type: /dev/null bind for files, empty tmpfs for directories. This is
// load-bearing, not cosmetic: mounting a tmpfs onto an existing file aborts bwrap at startup (ENOTDIR).
// A deny path that does not exist is skipped entirely: there is no credential there to hide, and bwrap
// cannot create the mountpoint under the read-only root bind, so masking a missing path would abort the
// whole sandbox at startup ("Can't mkdir ...: Read-only file system").
// Deny mounts are emitted after the cwd/tempdir/write binds so they always win: otherwise a cwd bind
// that is an ancestor of a deny path (running the agent from $HOME) would re-expose ~/.aws, ~/.ssh, etc.
// Omits --new-session (setsid breaks the interactive TTY). On the hard fence the proxy's unix socket
// is bind-mounted and the supervisor bridges to it; shared net reaches host loopback directly.
func buildBwrapArgv(spec SandboxSpec, selfExe string, argv []string, classify func(string) (exists, isFile bool)) []string {
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

	// Read/write binds first. Bound after --tmpfs /tmp so a tempdir under /tmp is not shadowed.
	if spec.Cwd != "" {
		args = append(args, "--bind", spec.Cwd, spec.Cwd)
	}
	if spec.TempDir != "" {
		args = append(args, "--bind", spec.TempDir, spec.TempDir)
	}
	for _, p := range dedupeSorted(spec.WritePaths) {
		args = append(args, "--bind", p, p)
	}

	// Deny mounts LAST so they always win: a cwd or write bind that is an ancestor of a deny path
	// (e.g. running the agent from $HOME, whose bind would otherwise re-expose ~/.aws, ~/.ssh, ...)
	// must not be able to re-expose a credential path masked earlier.
	for _, p := range dedupeSorted(spec.DenyPaths) {
		exists, isFile := classify(p)
		if !exists {
			continue
		}
		if isFile {
			args = append(args, "--ro-bind", "/dev/null", p)
		} else {
			args = append(args, "--tmpfs", p)
		}
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
