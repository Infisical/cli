package sandbox

import (
	"strings"
	"testing"
)

func bwrapSpec(net NetMode) SandboxSpec {
	return SandboxSpec{
		Sandbox:      true,
		Cwd:          "/home/dev/project",
		TempDir:      "/tmp/infisical-run-xyz",
		LoopbackPort: BridgeLoopbackPort,
		ProxySocket:  "/tmp/infisical-run-xyz/proxy.sock",
		DenyPaths:    []string{"/home/dev/.aws", "/home/dev/.ssh", "/home/dev/.infisical"},
		WritePaths:   []string{"/home/dev/.cache"},
		NetMode:      net,
	}
}

// allExistingDirs classifies every deny path as an existing directory (never a file, never missing),
// so the default specs mask with --tmpfs. Tests that care about the file or missing branch pass their
// own classifier.
func allExistingDirs(string) (bool, bool) { return true, false }

// argIndex returns the index of the first occurrence of tok, or -1.
func argIndex(args []string, tok string) int {
	for i, a := range args {
		if a == tok {
			return i
		}
	}
	return -1
}

func TestBwrapArgvHardFence(t *testing.T) {
	args := buildBwrapArgv(bwrapSpec(HardFence), "/proc/self/exe", []string{"claude", "--flag"}, allExistingDirs)
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"--unshare-all", "--die-with-parent",
		"--tmpfs /home/dev/.aws", "--tmpfs /home/dev/.ssh", "--tmpfs /home/dev/.infisical",
		"--bind /home/dev/project /home/dev/project",
		"--bind /tmp/infisical-run-xyz /tmp/infisical-run-xyz",
		"--bind /home/dev/.cache /home/dev/.cache",
		SupervisorSubcommand,
		"--socket /tmp/infisical-run-xyz/proxy.sock",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("hard-fence argv missing %q\n%s", want, joined)
		}
	}

	// Must NOT share host net on the hard fence, and must NOT setsid.
	if strings.Contains(joined, "--share-net") {
		t.Error("hard fence must not pass --share-net")
	}
	if strings.Contains(joined, "--new-session") {
		t.Error("must never pass --new-session (breaks the interactive TTY)")
	}

	// The supervisor + agent must appear after the -- separator, in order.
	sep := argIndex(args, "--")
	sup := argIndex(args, SupervisorSubcommand)
	agent := argIndex(args, "claude")
	if sep == -1 || sup < sep || agent < sup {
		t.Fatalf("expected `-- <supervisor> ... claude`; sep=%d sup=%d agent=%d\n%v", sep, sup, agent, args)
	}
	// tempdir bind must come after the /tmp tmpfs so it is not shadowed.
	tmpfsTmp := lastArgPairIndex(args, "--tmpfs", "/tmp")
	bindTemp := lastArgPairIndex(args, "--bind", "/tmp/infisical-run-xyz")
	if tmpfsTmp == -1 || bindTemp == -1 || bindTemp < tmpfsTmp {
		t.Fatalf("tempdir bind must follow the /tmp tmpfs (tmpfs=%d bind=%d)", tmpfsTmp, bindTemp)
	}
}

func TestBwrapArgvSharedNet(t *testing.T) {
	args := buildBwrapArgv(bwrapSpec(SharedNet), "/proc/self/exe", []string{"claude"}, allExistingDirs)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--share-net") {
		t.Error("shared-net argv must pass --share-net")
	}
	// No bridge/supervisor on the shared-net path: the agent runs directly.
	if strings.Contains(joined, SupervisorSubcommand) {
		t.Error("shared-net path must not insert the supervisor")
	}
	if args[len(args)-1] != "claude" {
		t.Errorf("agent must be the final arg on the shared-net path, got %q", args[len(args)-1])
	}
}

// lastArgPairIndex finds the index of `flag` immediately followed by `val`.
func lastArgPairIndex(args []string, flag, val string) int {
	idx := -1
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			idx = i
		}
	}
	return idx
}

func TestBwrapArgvMasksFilesWithDevNull(t *testing.T) {
	spec := bwrapSpec(HardFence)
	spec.DenyPaths = []string{"/home/dev/.aws", "/home/dev/.docker/config.json", "/home/dev/.netrc"}
	// Classify the two dotfiles as files; the .aws dir stays a directory. All three exist.
	classify := func(p string) (bool, bool) {
		return true, p == "/home/dev/.docker/config.json" || p == "/home/dev/.netrc"
	}
	joined := strings.Join(buildBwrapArgv(spec, "/proc/self/exe", []string{"claude"}, classify), " ")

	// Files masked by binding /dev/null over them (tmpfs onto a file aborts bwrap).
	for _, want := range []string{
		"--ro-bind /dev/null /home/dev/.docker/config.json",
		"--ro-bind /dev/null /home/dev/.netrc",
		"--tmpfs /home/dev/.aws", // directory still uses tmpfs
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected %q\n%s", want, joined)
		}
	}
	// A file deny path must NOT be masked with tmpfs.
	if strings.Contains(joined, "--tmpfs /home/dev/.netrc") || strings.Contains(joined, "--tmpfs /home/dev/.docker/config.json") {
		t.Errorf("file deny paths must not be masked with tmpfs\n%s", joined)
	}
}

func TestBwrapArgvSkipsMissingDenyPaths(t *testing.T) {
	spec := bwrapSpec(HardFence)
	spec.DenyPaths = []string{"/home/dev/.aws", "/home/dev/.ssh", "/home/dev/.netrc"}
	// Only .aws exists (as a dir); .ssh and .netrc are missing on this account.
	classify := func(p string) (bool, bool) {
		return p == "/home/dev/.aws", false
	}
	joined := strings.Join(buildBwrapArgv(spec, "/proc/self/exe", []string{"claude"}, classify), " ")

	// The existing path is masked...
	if !strings.Contains(joined, "--tmpfs /home/dev/.aws") {
		t.Errorf("existing deny dir must be masked with tmpfs\n%s", joined)
	}
	// ...but missing paths must NOT appear at all: bwrap can't create a mountpoint under the
	// read-only root bind, so a --tmpfs/--ro-bind for a missing path aborts the whole sandbox.
	for _, missing := range []string{"/home/dev/.ssh", "/home/dev/.netrc"} {
		if strings.Contains(joined, missing) {
			t.Errorf("missing deny path %q must be skipped, not mounted\n%s", missing, joined)
		}
	}
}

func TestBwrapArgvDenyMountsWinOverCwdBind(t *testing.T) {
	// Agent launched from $HOME: the cwd bind is an ancestor of every deny path.
	spec := bwrapSpec(HardFence)
	spec.Cwd = "/home/dev"
	spec.WritePaths = []string{"/home/dev/.claude"}
	spec.DenyPaths = []string{"/home/dev/.aws", "/home/dev/.ssh"}
	args := buildBwrapArgv(spec, "/proc/self/exe", []string{"claude"}, allExistingDirs)

	// Every deny mount must come AFTER the cwd bind and the write bind, or the bind re-exposes it.
	cwdBind := lastArgPairIndex(args, "--bind", "/home/dev")
	writeBind := lastArgPairIndex(args, "--bind", "/home/dev/.claude")
	for _, deny := range []string{"/home/dev/.aws", "/home/dev/.ssh"} {
		denyIdx := lastArgPairIndex(args, "--tmpfs", deny)
		if denyIdx == -1 {
			t.Fatalf("deny path %q not masked\n%v", deny, args)
		}
		if denyIdx < cwdBind {
			t.Errorf("deny mount %q (idx %d) must come after the cwd bind (idx %d), else the cwd bind re-exposes it", deny, denyIdx, cwdBind)
		}
		if denyIdx < writeBind {
			t.Errorf("deny mount %q (idx %d) must come after the write bind (idx %d)", deny, denyIdx, writeBind)
		}
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 7: "7", 17321: "17321", -42: "-42"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}
