package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var updateCommandSurface = flag.Bool("update-command-surface", false, "record new command paths and flags in "+commandSurfaceFile)

const commandSurfaceFile = "testdata/command_surface.json"

// commandSurface maps each command path to its flags, written as "shorthand|type|default".
// Root persistent flags are recorded once, on the root, instead of on every command.
type commandSurface map[string]map[string]string

func flagSurface(cmd *cobra.Command) map[string]string {
	flags := map[string]string{}
	record := func(set *pflag.FlagSet) {
		set.VisitAll(func(f *pflag.Flag) {
			if f.Name == "help" || (cmd != RootCmd && RootCmd.PersistentFlags().Lookup(f.Name) == f) {
				return
			}
			flags[f.Name] = strings.Join([]string{f.Shorthand, f.Value.Type(), f.DefValue}, "|")
		})
	}
	record(cmd.LocalFlags())
	record(cmd.InheritedFlags())
	return flags
}

// currentCommandSurface records every spelling of every path, aliases included at each level
// (`infisical sm project list`), so removing an alias fails like removing a command. It skips:
//   - hidden commands: they are not public, and some are platform-specific (the Linux sandbox
//     supervisor). A command hidden after it was recorded stays in the snapshot and is still checked;
//   - cobra's default `help` command, which RootCmd.Execute adds to the shared root, so whether it
//     exists depends on which tests ran first.
func currentCommandSurface() commandSurface {
	surface := commandSurface{}
	var walk func(cmd *cobra.Command, paths []string)
	walk = func(cmd *cobra.Command, paths []string) {
		if cmd.Hidden || (cmd.Name() == "help" && cmd.Parent() == RootCmd) {
			return
		}
		flags := flagSurface(cmd)
		for _, path := range paths {
			surface[path] = flags
		}
		for _, child := range cmd.Commands() {
			var childPaths []string
			for _, path := range paths {
				for _, name := range append([]string{child.Name()}, child.Aliases...) {
					childPaths = append(childPaths, path+" "+name)
				}
			}
			walk(child, childPaths)
		}
	}
	walk(RootCmd, []string{RootCmd.Name()})
	return surface
}

// resolveCommandPath finds a recorded path the way a user's command line would, so a path keeps
// resolving through an alias after its command is renamed.
func resolveCommandPath(path string) *cobra.Command {
	cmd, rest, err := RootCmd.Find(strings.Fields(path)[1:])
	if err != nil || len(rest) > 0 {
		return nil
	}
	return cmd
}

func readCommandSurface(t *testing.T) commandSurface {
	t.Helper()
	recorded := commandSurface{}
	data, err := os.ReadFile(commandSurfaceFile)
	if err != nil && !(os.IsNotExist(err) && *updateCommandSurface) {
		t.Fatalf("reading %s: %v", commandSurfaceFile, err)
	}
	if err == nil {
		if err := json.Unmarshal(data, &recorded); err != nil {
			t.Fatalf("parsing %s: %v", commandSurfaceFile, err)
		}
	}
	return recorded
}

// incompatibilities lists every recorded command line that no longer works as it did.
func incompatibilities(recorded commandSurface) []string {
	var problems []string
	for path, flags := range recorded {
		cmd := resolveCommandPath(path)
		if cmd == nil {
			problems = append(problems, fmt.Sprintf("`%s` no longer resolves. Commands and aliases are never removed or renamed; hide them instead (see CLI.md)", path))
			continue
		}
		current := flagSurface(cmd)
		for name, want := range flags {
			if got, ok := current[name]; !ok {
				problems = append(problems, fmt.Sprintf("`%s --%s` was removed. Flags are never removed or renamed; hide them instead (see CLI.md)", path, name))
			} else if got != want {
				problems = append(problems, fmt.Sprintf("`%s --%s` changed from %q to %q (shorthand|type|default)", path, name, want, got))
			}
		}
	}
	sort.Strings(problems)
	return problems
}

// The snapshot only grows: -update-command-surface adds new paths and flags but never removes or
// changes a recorded one, so a command line that worked once keeps working.
func TestCommandSurfaceIsBackwardsCompatible(t *testing.T) {
	recorded := readCommandSurface(t)
	for _, problem := range incompatibilities(recorded) {
		t.Error(problem)
	}
	if t.Failed() {
		return
	}

	// Anything new must be recorded too, so it is protected from then on.
	added := 0
	for path, flags := range currentCommandSurface() {
		recordedFlags, pathRecorded := recorded[path]
		if !pathRecorded {
			recordedFlags = map[string]string{}
			recorded[path] = recordedFlags
			added++
			if !*updateCommandSurface {
				t.Errorf("`%s` is not in %s yet", path, commandSurfaceFile)
			}
		}
		for name, signature := range flags {
			if _, ok := recordedFlags[name]; ok {
				continue
			}
			recordedFlags[name] = signature
			added++
			if pathRecorded && !*updateCommandSurface {
				t.Errorf("`%s --%s` is not in %s yet", path, name, commandSurfaceFile)
			}
		}
	}
	if t.Failed() {
		t.Logf("record new commands and flags with: go test ./packages/cmd -run TestCommandSurfaceIsBackwardsCompatible -update-command-surface")
		return
	}

	if *updateCommandSurface {
		out, err := json.MarshalIndent(recorded, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(commandSurfaceFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(commandSurfaceFile, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("recorded %d new commands and flags in %s", added, commandSurfaceFile)
	}
}

func TestCommandSurfaceRecordsAliases(t *testing.T) {
	surface := currentCommandSurface()
	for _, path := range []string{"infisical av", "infisical av proxy", "infisical sm projects list", "infisical sm project list", "infisical secrets-manager project list"} {
		if _, ok := surface[path]; !ok {
			t.Errorf("alias path %q is not part of the surface", path)
		}
	}

	agentVault, _, err := RootCmd.Find([]string{"agent-vault"})
	if err != nil {
		t.Fatal(err)
	}
	aliases := agentVault.Aliases
	agentVault.Aliases = nil
	t.Cleanup(func() { agentVault.Aliases = aliases })
	if problems := strings.Join(incompatibilities(readCommandSurface(t)), "\n"); !strings.Contains(problems, "`infisical av` no longer resolves") {
		t.Errorf("removing the av alias should be reported, got:\n%s", problems)
	}
}

// RootCmd.Execute (run by other tests in this package) adds cobra's default help command to the
// shared root. The surface must not depend on whether that happened first.
func TestCommandSurfaceIgnoresCobraHelp(t *testing.T) {
	RootCmd.InitDefaultHelpCmd()
	if _, ok := currentCommandSurface()["infisical help"]; ok {
		t.Error("cobra's default help command is part of the surface")
	}
}
