package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// smTree lists every command that must exist both at the top level and under `sm`.
var smTree = [][]string{
	{"run"},
	{"export"},
	{"secrets"},
	{"secrets", "get"},
	{"secrets", "set"},
	{"secrets", "delete"},
	{"secrets", "generate-example-env"},
	{"secrets", "folders"},
	{"secrets", "folders", "get"},
	{"secrets", "folders", "create"},
	{"secrets", "folders", "delete"},
	{"secrets", "agent-proxy"},
	{"secrets", "agent-proxy", "connect"},
	{"secrets", "agent-proxy", "start"},
	{"secrets", "agent-proxy", "run"},
	{"dynamic-secrets"},
	{"dynamic-secrets", "lease"},
	{"dynamic-secrets", "lease", "create"},
	{"dynamic-secrets", "lease", "list"},
	{"dynamic-secrets", "lease", "renew"},
	{"dynamic-secrets", "lease", "delete"},
}

// findCommand walks the tree by name, without parsing flags or running anything.
func findCommand(t *testing.T, path []string) *cobra.Command {
	t.Helper()
	current := RootCmd
	for _, name := range path {
		var next *cobra.Command
		for _, child := range current.Commands() {
			if child.Name() == name {
				next = child
				break
			}
		}
		if next == nil {
			t.Fatalf("command %q is not registered", strings.Join(path, " "))
		}
		current = next
	}
	return current
}

func smPath(path []string) []string {
	return append([]string{smCommandName}, path...)
}

// flagSignature describes a flag the way a user sees it, so two independently built
// commands can be compared.
func flagSignature(flags *pflag.FlagSet) map[string]string {
	signature := map[string]string{}
	flags.VisitAll(func(flag *pflag.Flag) {
		signature[flag.Name] = strings.Join([]string{flag.Shorthand, flag.Value.Type(), flag.DefValue, flag.Usage}, "|")
	})
	return signature
}

func TestSmRegistersEveryCommandAtBothLevels(t *testing.T) {
	for _, path := range smTree {
		name := strings.Join(path, " ")
		top := findCommand(t, path)
		sm := findCommand(t, smPath(path))

		if top == sm {
			t.Errorf("%s: top-level and sm share one command instance", name)
		}
		if got, want := top.CommandPath(), "infisical "+name; got != want {
			t.Errorf("%s: top-level command path is %q, want %q (re-parented?)", name, got, want)
		}
		if got, want := sm.CommandPath(), "infisical sm "+name; got != want {
			t.Errorf("%s: sm command path is %q, want %q", name, got, want)
		}
	}
}

func TestSmFlagsMatchTopLevel(t *testing.T) {
	for _, path := range smTree {
		name := strings.Join(path, " ")
		top := findCommand(t, path)
		sm := findCommand(t, smPath(path))

		for kind, pair := range map[string][2]*pflag.FlagSet{
			"local":     {top.LocalFlags(), sm.LocalFlags()},
			"inherited": {top.InheritedFlags(), sm.InheritedFlags()},
		} {
			topFlags, smFlags := flagSignature(pair[0]), flagSignature(pair[1])
			for flag, signature := range topFlags {
				if smFlags[flag] != signature {
					t.Errorf("%s: %s flag --%s differs under sm: top=%q sm=%q", name, kind, flag, signature, smFlags[flag])
				}
			}
			for flag := range smFlags {
				if _, ok := topFlags[flag]; !ok {
					t.Errorf("%s: %s flag --%s exists only under sm", name, kind, flag)
				}
			}
		}
	}
}

func TestSmFlagStateIsSeparate(t *testing.T) {
	for _, path := range smTree {
		name := strings.Join(path, " ")
		top := findCommand(t, path)
		sm := findCommand(t, smPath(path))
		top.LocalFlags().VisitAll(func(flag *pflag.Flag) {
			if flag == sm.LocalFlags().Lookup(flag.Name) {
				t.Errorf("%s: --%s is the same flag instance at both levels", name, flag.Name)
			}
		})
	}

	// Setting a value on one tree must not leak into the other.
	topRun := findCommand(t, []string{"run"})
	smRun := findCommand(t, smPath([]string{"run"}))
	envFlag := topRun.Flags().Lookup("env")
	original, originalChanged := envFlag.Value.String(), envFlag.Changed
	t.Cleanup(func() {
		_ = envFlag.Value.Set(original)
		envFlag.Changed = originalChanged
	})
	if err := topRun.Flags().Set("env", "leak-check"); err != nil {
		t.Fatalf("setting --env: %v", err)
	}
	if got := smRun.Flags().Lookup("env"); got.Value.String() == "leak-check" || got.Changed {
		t.Errorf("setting --env on `run` changed `sm run` (value=%q changed=%v)", got.Value.String(), got.Changed)
	}
}

func TestSmRejectsUnknownSubcommand(t *testing.T) {
	sm := findCommand(t, []string{smCommandName})
	err := sm.ValidateArgs([]string{"rnu"})
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("`sm rnu` should fail as an unknown command, got %v", err)
	}
	if err := sm.ValidateArgs(nil); err != nil {
		t.Errorf("bare `sm` should be accepted (prints help), got %v", err)
	}
}

// `sm agent-proxy` is a shorter path to `secrets agent-proxy`: same subcommands and flags, its own
// instances. It has no `secrets` parent, so the --env/--tags that `secrets` passes down (which
// agent-proxy ignores) are not inherited there.
func TestSmAgentProxyShortcut(t *testing.T) {
	for _, sub := range [][]string{{}, {"connect"}, {"start"}, {"run"}} {
		viaSecrets := findCommand(t, append([]string{"secrets", "agent-proxy"}, sub...))
		shortcut := findCommand(t, append([]string{smCommandName, "agent-proxy"}, sub...))
		name := strings.TrimSpace("agent-proxy " + strings.Join(sub, " "))

		if viaSecrets == shortcut {
			t.Errorf("%s: shortcut shares its instance with `secrets agent-proxy`", name)
		}
		if got, want := shortcut.CommandPath(), "infisical sm "+name; got != want {
			t.Errorf("%s: shortcut path is %q, want %q", name, got, want)
		}

		want, got := flagSignature(viaSecrets.LocalFlags()), flagSignature(shortcut.LocalFlags())
		for flag, signature := range want {
			if got[flag] != signature {
				t.Errorf("%s: --%s differs on the shortcut: secrets=%q sm=%q", name, flag, signature, got[flag])
			}
		}
		for flag := range got {
			if _, ok := want[flag]; !ok {
				t.Errorf("%s: --%s exists only on the shortcut", name, flag)
			}
		}
		for _, inherited := range []string{"env", "tags"} {
			if len(sub) == 0 && shortcut.InheritedFlags().Lookup(inherited) != nil {
				t.Errorf("%s: shortcut should not inherit --%s from `secrets`", name, inherited)
			}
		}
	}

	for _, child := range RootCmd.Commands() {
		if child.Name() == "agent-proxy" {
			t.Errorf("agent-proxy must not be added at the top level; only `sm agent-proxy` is new")
		}
	}
}

func TestTopLevelCommandNameSeesThroughSm(t *testing.T) {
	cases := map[string]string{
		"secrets get":                     "secrets",
		"sm secrets get":                  "secrets",
		"sm secrets folders get":          "secrets",
		"sm run":                          "run",
		"sm":                              "sm",
		"secrets agent-proxy run":         "secrets",
		"sm secrets agent-proxy run":      "secrets",
		"sm dynamic-secrets lease create": "dynamic-secrets",
		"sm agent-proxy run":              "agent-proxy",
		"sm projects list":                "projects",
	}
	for path, want := range cases {
		if got := topLevelCommandName(findCommand(t, strings.Fields(path))); got != want {
			t.Errorf("topLevelCommandName(%q) = %q, want %q", path, got, want)
		}
	}
}

// Projects are typed per product, so `projects` lives only under `sm`, not at the top level.
func TestProjectsIsRegisteredOnlyUnderSm(t *testing.T) {
	for _, path := range [][]string{{"projects", "list"}, {"projects", "get"}, {"projects", "create"}} {
		findCommand(t, smPath(path))
	}
	for _, child := range RootCmd.Commands() {
		if child.Name() == "projects" {
			t.Fatal("projects is registered at the top level; it should only be under sm")
		}
	}
}
