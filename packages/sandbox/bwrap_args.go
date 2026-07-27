package sandbox

import "strconv"

// BridgeLoopbackPort is the loopback port the in-namespace bridge listens on. Fixed is safe: each
// hard-fence run has its own empty netns, so it never collides across concurrent runs.
const BridgeLoopbackPort = 17321

// SupervisorSubcommand re-enters this binary as the in-namespace supervisor. Exported so the cmd
// package can register the matching hidden command.
const SupervisorSubcommand = "__sandbox-supervisor"

// bwrapBaseArgs are the containment flags every bwrap invocation starts with, shared by the real argv
// and by Preflight's probes so a probe can never certify a configuration the real run doesn't use.
// Omits --new-session (setsid breaks the interactive TTY).
func bwrapBaseArgs() []string {
	return []string{
		"--unshare-all",
		"--die-with-parent",
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
	}
}

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
// On the hard fence the proxy's unix socket lives in the bind-mounted tempdir and the supervisor bridges
// to it; shared net reaches host loopback directly.
func buildBwrapArgv(spec Spec, selfExe string, argv []string, classify func(string) (exists, isFile bool)) []string {
	args := append([]string{"bwrap"}, bwrapBaseArgs()...)

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

	// Deny mounts after the read/write binds so they always win: a cwd or write bind that is an ancestor
	// of a deny path (e.g. running the agent from $HOME, whose bind would otherwise re-expose ~/.aws,
	// ~/.ssh, ...) must not be able to re-expose a credential path masked earlier.
	exceptions := dedupeSorted(spec.ReadPaths)
	var maskedDirs []string
	for _, p := range dedupeSorted(spec.DenyPaths) {
		// A deny path the operator re-opened wholesale (--allow-read ~/.aws) is simply left unmasked,
		// rather than masked and then re-bound: re-binding a path we just covered would depend on how
		// bwrap resolves an already-shadowed source.
		if containsString(exceptions, p) {
			continue
		}
		exists, isFile := classify(p)
		if !exists {
			continue
		}
		if isFile {
			args = append(args, "--ro-bind", "/dev/null", p)
		} else {
			args = append(args, "--tmpfs", p)
			maskedDirs = append(maskedDirs, p)
		}
	}

	// Re-bind only the exceptions a mask we just emitted actually covers. Their parent is an empty
	// tmpfs, which is writable, so bwrap can create the mountpoint. Read-only, and emitted after the
	// masks so nothing re-covers them.
	for _, p := range exceptions {
		if !underAny(p, maskedDirs) {
			continue // nothing masks it: the read-only root bind already exposes it
		}
		if exists, _ := classify(p); !exists {
			continue // --ro-bind fails on a missing source
		}
		args = append(args, "--ro-bind", p, p)
	}

	args = append(args, "--")

	if spec.NetMode == HardFence && spec.ProxySocket != "" {
		args = append(args,
			selfExe, SupervisorSubcommand,
			"--port", strconv.Itoa(spec.LoopbackPort),
			"--socket", spec.ProxySocket,
			"--",
		)
	}

	return append(args, argv...)
}
