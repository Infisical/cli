package sandbox

// BridgeLoopbackPort is the loopback port the in-namespace bridge listens on (hard-fence path). The
// child's HTTP(S)_PROXY targets 127.0.0.1:this. Because each hard-fence run gets its own empty network
// namespace, this port never collides across concurrent runs, so a fixed value is safe.
const BridgeLoopbackPort = 17321

// SupervisorSubcommand is the hidden argv token that re-enters this binary as the in-namespace
// supervisor (brings up loopback, starts the TCP->unix bridge, then execs the agent). Exported so the
// cmd package registers a matching hidden cobra command.
const SupervisorSubcommand = "__sandbox-supervisor"

// buildBwrapArgv builds the full argv (starting with "bwrap") for a spec. Pure function (its only
// filesystem dependency is injected via isFile), so it is golden-testable on any platform.
//
//   - selfExe is the path to this binary (/proc/self/exe at call time), re-executed as the supervisor
//     on the hard-fence path.
//   - argv is the agent command.
//   - isFile reports whether a deny path currently exists as a regular file, which decides how it is
//     masked (see below). Injected so tests can exercise both branches without touching disk.
//
// Deny paths are masked by their type: a directory (or a path that does not exist) is covered with an
// empty --tmpfs; a regular file is covered by binding /dev/null over it. Using the wrong primitive is
// not cosmetic: bwrap aborts at startup if asked to mount a tmpfs onto a file (ENOTDIR), so a user who
// has e.g. ~/.docker/config.json would otherwise be unable to start the sandbox at all.
//
// Hard fence (NetMode == HardFence): --unshare-all gives an empty network namespace; the proxy's unix
// socket (spec.ProxySocket) is bind-mounted in and the supervisor bridges LoopbackPort -> that socket.
// Shared net (NetMode == SharedNet): --unshare-all --share-net keeps host networking, so the child
// reaches the proxy on host loopback directly and no supervisor/bridge is inserted.
//
// Deliberately omits --new-session (it calls setsid() and breaks the interactive TTY / job control).
func buildBwrapArgv(spec SandboxSpec, selfExe string, argv []string, isFile func(string) bool) []string {
	args := []string{
		"bwrap",
		"--unshare-all",
		"--die-with-parent",
		// A read-only view of the whole filesystem keeps arbitrary toolchains working; credential paths
		// are masked back out below, and the workspace/tempdir are bound writable on top.
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
	}

	if spec.NetMode == SharedNet {
		args = append(args, "--share-net")
	}

	// Mask credential paths (they were visible via --ro-bind / /). A regular file is masked by binding
	// /dev/null over it; a directory (or a path that does not exist) is masked with an empty tmpfs.
	// tmpfs onto an existing file makes bwrap abort at startup, so the file/dir split is load-bearing.
	for _, p := range dedupeSorted(spec.DenyPaths) {
		if isFile(p) {
			args = append(args, "--ro-bind", "/dev/null", p)
		} else {
			args = append(args, "--tmpfs", p)
		}
	}

	// Writable workspace + tempdir, bound AFTER --tmpfs /tmp so a tempdir under /tmp is not shadowed.
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
		// Re-exec ourselves as the in-namespace supervisor: it brings loopback up, bridges the child's
		// loopback proxy port to the bound unix socket, then execs the agent.
		args = append(args,
			selfExe, SupervisorSubcommand,
			"--port", itoa(spec.LoopbackPort),
			"--socket", spec.ProxySocket,
			"--",
		)
	}

	return append(args, argv...)
}

// itoa avoids pulling strconv into the argv builder's tiny surface (keeps it trivially pure).
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
