package sandbox

import (
	"strings"
	"testing"
)

func bwrapSpec(net NetMode) Spec {
	return Spec{
		Enabled:      true,
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

func TestBwrapArgvReadExceptionInsideDeniedDir(t *testing.T) {
	spec := bwrapSpec(HardFence)
	spec.DenyPaths = []string{"/home/dev/.aws", "/home/dev/.ssh"}
	spec.ReadPaths = []string{"/home/dev/.aws/config"}
	args := buildBwrapArgv(spec, "/proc/self/exe", []string{"claude"}, allExistingDirs)
	joined := strings.Join(args, " ")

	// The directory is still masked, and the one excepted file is re-bound on top of that tmpfs.
	if !strings.Contains(joined, "--tmpfs /home/dev/.aws") {
		t.Errorf("the denied dir must still be masked\n%s", joined)
	}
	if !strings.Contains(joined, "--ro-bind /home/dev/.aws/config /home/dev/.aws/config") {
		t.Errorf("the read exception must be re-bound read-only\n%s", joined)
	}
	// Ordering is what makes it work: the re-bind must land after the tmpfs that masks its parent.
	mask := lastArgPairIndex(args, "--tmpfs", "/home/dev/.aws")
	rebind := lastArgPairIndex(args, "--ro-bind", "/home/dev/.aws/config")
	if mask == -1 || rebind == -1 || rebind < mask {
		t.Fatalf("read exception must be emitted after the mask (mask=%d rebind=%d)\n%v", mask, rebind, args)
	}
	// It must be read-only: never bound writable.
	if strings.Contains(joined, "--bind /home/dev/.aws/config") {
		t.Errorf("a read exception must never be bound writable\n%s", joined)
	}
	// The unrelated deny is untouched.
	if !strings.Contains(joined, "--tmpfs /home/dev/.ssh") {
		t.Errorf("unrelated deny paths must stay masked\n%s", joined)
	}
}

func TestBwrapArgvReadExceptionOfWholeDenyPathSkipsMask(t *testing.T) {
	spec := bwrapSpec(HardFence)
	spec.DenyPaths = []string{"/home/dev/.aws", "/home/dev/.ssh"}
	spec.ReadPaths = []string{"/home/dev/.aws"}
	joined := strings.Join(buildBwrapArgv(spec, "/proc/self/exe", []string{"claude"}, allExistingDirs), " ")

	// Re-opening a deny path wholesale leaves it unmasked rather than masking then re-binding it.
	if strings.Contains(joined, "--tmpfs /home/dev/.aws") {
		t.Errorf("a wholly re-opened deny path must not be masked\n%s", joined)
	}
	if strings.Contains(joined, "--ro-bind /home/dev/.aws /home/dev/.aws") {
		t.Errorf("a wholly re-opened deny path needs no re-bind (root bind already exposes it)\n%s", joined)
	}
	if !strings.Contains(joined, "--tmpfs /home/dev/.ssh") {
		t.Errorf("other deny paths must stay masked\n%s", joined)
	}
}

// Nested denies: ~/.aws is masked and ~/.aws/config is itself a deny path that was re-opened. The
// exception still needs a re-bind, because the parent's tmpfs covers it.
func TestBwrapArgvReadExceptionUnderMaskedParent(t *testing.T) {
	spec := bwrapSpec(HardFence)
	spec.DenyPaths = []string{"/home/dev/.aws", "/home/dev/.aws/config"}
	spec.ReadPaths = []string{"/home/dev/.aws/config"}
	args := buildBwrapArgv(spec, "/proc/self/exe", []string{"claude"}, allExistingDirs)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--tmpfs /home/dev/.aws ") && !strings.HasSuffix(joined, "--tmpfs /home/dev/.aws") {
		t.Errorf("the masked parent must still be masked\n%s", joined)
	}
	rebind := lastArgPairIndex(args, "--ro-bind", "/home/dev/.aws/config")
	mask := lastArgPairIndex(args, "--tmpfs", "/home/dev/.aws")
	if rebind == -1 {
		t.Fatalf("an exception under a masked parent must be re-bound\n%s", joined)
	}
	if rebind < mask {
		t.Fatalf("the re-bind must follow the parent mask (mask=%d rebind=%d)", mask, rebind)
	}
}

func TestBwrapArgvSkipsUselessAndMissingReadExceptions(t *testing.T) {
	spec := bwrapSpec(HardFence)
	spec.DenyPaths = []string{"/home/dev/.aws"}
	// One outside any deny (nothing to re-open), one inside a deny but missing on disk.
	spec.ReadPaths = []string{"/home/dev/project/notes.md", "/home/dev/.aws/absent"}
	classify := func(p string) (bool, bool) {
		return p != "/home/dev/.aws/absent", false
	}
	joined := strings.Join(buildBwrapArgv(spec, "/proc/self/exe", []string{"claude"}, classify), " ")

	if strings.Contains(joined, "notes.md") {
		t.Errorf("a path outside every deny needs no re-bind\n%s", joined)
	}
	// A missing source would abort bwrap at startup.
	if strings.Contains(joined, "/home/dev/.aws/absent") {
		t.Errorf("a missing read exception must be skipped\n%s", joined)
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
