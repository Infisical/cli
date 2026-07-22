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
	args := buildBwrapArgv(bwrapSpec(HardFence), "/proc/self/exe", []string{"claude", "--flag"})
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
	args := buildBwrapArgv(bwrapSpec(SharedNet), "/proc/self/exe", []string{"claude"})
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

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 7: "7", 17321: "17321", -42: "-42"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}
