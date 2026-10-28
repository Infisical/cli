package cmd

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
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

// currentCommandSurface skips hidden commands: they are not public, and some are platform-specific
// (the Linux sandbox supervisor), so recording them would make the snapshot differ per OS. A command
// hidden after it was recorded stays in the snapshot and is still checked.
func currentCommandSurface() commandSurface {
	surface := commandSurface{}
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		if cmd.Hidden {
			return
		}
		surface[cmd.CommandPath()] = flagSurface(cmd)
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(RootCmd)
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

// The snapshot only grows: -update-command-surface adds new paths and flags but never removes or
// changes a recorded one, so a command line that worked once keeps working.
func TestCommandSurfaceIsBackwardsCompatible(t *testing.T) {
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

	for path, flags := range recorded {
		cmd := resolveCommandPath(path)
		if cmd == nil {
			t.Errorf("`%s` no longer resolves. Commands are never removed or renamed; hide them instead (see CLI.md)", path)
			continue
		}
		current := flagSurface(cmd)
		for name, want := range flags {
			if got, ok := current[name]; !ok {
				t.Errorf("`%s --%s` was removed. Flags are never removed or renamed; hide them instead (see CLI.md)", path, name)
			} else if got != want {
				t.Errorf("`%s --%s` changed from %q to %q (shorthand|type|default)", path, name, want, got)
			}
		}
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
