package cmd

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// These are the rules from CLI.md that can be checked mechanically. They apply to every visible
// command under `secrets-manager`; hidden commands are kept only for backwards compatibility.

var (
	crudActions      = map[string]bool{"get": true, "create": true, "update": true, "delete": true}
	lifecycleActions = map[string]bool{"start": true, "stop": true, "install": true, "uninstall": true}
	workflowCommands = map[string]bool{"run": true, "export": true}
)

type conventionRule struct {
	id    string
	check func(cmd *cobra.Command) string
}

var conventionRules = []conventionRule{
	{"action", func(cmd *cobra.Command) string {
		if !cmd.Runnable() || cmd.HasAvailableSubCommands() {
			return ""
		}
		name := cmd.Name()
		if crudActions[name] || lifecycleActions[name] || workflowCommands[name] {
			return ""
		}
		return fmt.Sprintf("%q is not an action from CLI.md (get, create, update, delete, or a lifecycle or workflow command)", name)
	}},
	{"plural-resource", func(cmd *cobra.Command) string {
		if !cmd.HasAvailableSubCommands() || cmd.Parent() == RootCmd || strings.HasSuffix(cmd.Name(), "s") {
			return ""
		}
		return fmt.Sprintf("resource %q should be a plural noun", cmd.Name())
	}},
	{"args", func(cmd *cobra.Command) string {
		if cmd.Runnable() && cmd.Args == nil {
			return "runnable command has no Args check, so stray arguments are silently ignored"
		}
		return ""
	}},
	{"short", func(cmd *cobra.Command) string {
		if cmd.Short == "" {
			return "missing Short"
		}
		if strings.HasPrefix(cmd.Short, "Used ") {
			return fmt.Sprintf("Short %q should start with an imperative verb", cmd.Short)
		}
		return ""
	}},
	{"examples", func(cmd *cobra.Command) string {
		if !cmd.Runnable() {
			return ""
		}
		if strings.TrimSpace(cmd.Example) == "" {
			return "missing Example"
		}
		for _, line := range strings.Split(cmd.Example, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "infisical ") {
				return fmt.Sprintf("example %q should start with `infisical `", line)
			}
		}
		return ""
	}},
	{"long-product-name", func(cmd *cobra.Command) string {
		if strings.Contains(cmd.Example, "infisical "+secretsManagerAlias+" ") {
			return "examples should use `infisical secrets-manager`, not the `sm` shorthand"
		}
		return ""
	}},
	{"output", func(cmd *cobra.Command) string {
		if !crudActions[cmd.Name()] || !cmd.Runnable() {
			return ""
		}
		if f := cmd.Flags().Lookup("output"); f == nil || f.Shorthand != "o" {
			return "missing -o/--output"
		}
		return ""
	}},
	{"confirm", func(cmd *cobra.Command) string {
		if cmd.Name() != "delete" || !cmd.Runnable() {
			return ""
		}
		if f := cmd.Flags().Lookup("yes"); f == nil || f.Shorthand != "y" {
			return "destructive command has no -y/--yes"
		}
		return ""
	}},
}

// conventionExceptions lists commands that predate CLI.md, with the rules each one breaks. It is
// the remaining cleanup: remove an entry once the command is fixed. New commands must not be added.
var conventionExceptions = map[string][]string{
	"infisical secrets-manager dynamic-secrets":              {"short"},
	"infisical secrets-manager dynamic-secrets lease":        {"plural-resource"},
	"infisical secrets-manager dynamic-secrets lease create": {"examples", "short"},
	"infisical secrets-manager dynamic-secrets lease delete": {"confirm", "examples", "short"},
	"infisical secrets-manager dynamic-secrets lease list":   {"action", "examples", "short"},
	"infisical secrets-manager dynamic-secrets lease renew":  {"action", "examples", "short"},
	"infisical secrets-manager export":                       {"short"},
	"infisical secrets-manager projects list":                {"action"}, // stays: projects get without a slug already means the linked project
	"infisical secrets-manager run":                          {"short"},
	"infisical secrets-manager secrets":                      {"short"},
	"infisical secrets-manager secrets delete":               {"confirm", "examples", "short"},
	"infisical secrets-manager secrets folders":              {"args", "examples"},
	"infisical secrets-manager secrets folders create":       {"args", "examples"},
	"infisical secrets-manager secrets folders delete":       {"args", "confirm", "examples"},
	"infisical secrets-manager secrets folders get":          {"args", "examples"},
	"infisical secrets-manager secrets get":                  {"examples", "short"},
	"infisical secrets-manager secrets set":                  {"action", "examples", "short"},
}

func visibleCommands(cmd *cobra.Command) []*cobra.Command {
	if cmd.Hidden {
		return nil
	}
	commands := []*cobra.Command{cmd}
	for _, child := range cmd.Commands() {
		commands = append(commands, visibleCommands(child)...)
	}
	return commands
}

func TestCommandConventions(t *testing.T) {
	root := findCommand(t, []string{secretsManagerCommandName})
	violations := map[string][]string{}
	for _, cmd := range visibleCommands(root) {
		for _, rule := range conventionRules {
			if problem := rule.check(cmd); problem != "" {
				path := cmd.CommandPath()
				violations[path] = append(violations[path], rule.id)
				if !contains(conventionExceptions[path], rule.id) {
					t.Errorf("%s [%s]: %s (see CLI.md)", path, rule.id, problem)
				}
			}
		}
	}

	paths := make([]string, 0, len(conventionExceptions))
	for path := range conventionExceptions {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		for _, id := range conventionExceptions[path] {
			if !contains(violations[path], id) {
				t.Errorf("%s no longer breaks [%s]; remove it from conventionExceptions", path, id)
			}
		}
	}
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
