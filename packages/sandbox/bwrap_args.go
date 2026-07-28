package sandbox

import "strconv"

// BridgeLoopbackPort is where the in-namespace bridge listens. A fixed port is safe because each
// hard-fence run gets its own empty netns.
const BridgeLoopbackPort = 17321

// SupervisorSubcommand re-enters this binary as the in-namespace supervisor. Exported so cmd can
// register the matching hidden command.
const SupervisorSubcommand = "__sandbox-supervisor"

// bwrapBaseArgs are the containment flags shared by the real argv and by Preflight's probes, so a
// probe can never certify flags the real run does not use.
// Deliberately omits --new-session: setsid would detach the terminal and break interactive TUIs.
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

// buildBwrapArgv builds the bwrap argv for a spec. The filesystem dependency is injected via classify
// (does this deny path exist, and is it a regular file?), which keeps the function pure and testable
// on any platform. Mount order below is load-bearing; each step says why.
func buildBwrapArgv(spec Spec, selfExe string, argv []string, classify func(string) (exists, isFile bool)) []string {
	args := append([]string{"bwrap"}, bwrapBaseArgs()...)

	if spec.NetMode == SharedNet {
		args = append(args, "--share-net")
	}

	// Write binds come after --tmpfs /tmp, or a tempdir under /tmp would be shadowed by it.
	if spec.Cwd != "" {
		args = append(args, "--bind", spec.Cwd, spec.Cwd)
	}
	if spec.TempDir != "" {
		args = append(args, "--bind", spec.TempDir, spec.TempDir)
	}
	for _, p := range dedupeSorted(spec.WritePaths) {
		args = append(args, "--bind", p, p)
	}

	// Deny mounts come after the write binds so they win. Otherwise running the agent from $HOME would
	// bind $HOME writable and re-expose ~/.aws, ~/.ssh and friends underneath it.
	exceptions := dedupeSorted(spec.ReadPaths)
	var maskedDirs []string
	for _, p := range dedupeSorted(spec.DenyPaths) {
		// Left unmasked rather than masked-then-rebound, which would depend on how bwrap resolves an
		// already-shadowed source.
		if containsString(exceptions, p) {
			continue
		}
		exists, isFile := classify(p)
		if !exists {
			continue // bwrap cannot create a mountpoint under the read-only root bind, and would abort
		}
		if isFile {
			args = append(args, "--ro-bind", "/dev/null", p) // tmpfs onto a file aborts with ENOTDIR
		} else {
			args = append(args, "--tmpfs", p)
			maskedDirs = append(maskedDirs, p)
		}
	}

	// Read exceptions land last so no mask re-covers them. Their parent is now an empty tmpfs, which is
	// writable, so bwrap can create the mountpoint.
	for _, p := range exceptions {
		if !underAny(p, maskedDirs) {
			continue // nothing masks it: the root bind already exposes it
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
