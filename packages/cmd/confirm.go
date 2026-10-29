package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/manifoldco/promptui"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Swapped out in tests, which have no terminal to type into.
var (
	stdinIsTerminal = func() bool {
		return isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd())
	}
	promptForConfirmation = func(label string) (string, error) {
		prompt := promptui.Prompt{Label: label}
		return prompt.Run()
	}
)

// Flags left out of a suggested rerun entirely: the user supplies them again (or through the
// environment), and repeating even a placeholder would invite pasting a credential.
var credentialFlags = map[string]bool{"token": true, "client-secret": true, "client-id": true, "password": true, "passphrase": true}

// Flags whose values a suggested rerun repeats, because they only ever hold identifiers. Any other
// flag's value becomes a placeholder, so a secret in a flag nobody anticipated can't reach the
// suggestion even when it looks like a slug.
var rerunIdentifierFlags = map[string]bool{
	"projectId": true, "project-slug": true, "env": true, "path": true, "type": true, "tag": true, "tags": true,
	"name": true, "slug": true, "position": true, "output": true,
}

// destructiveAction is what a command is about to delete.
type destructiveAction struct {
	Target      string // named in messages: `environment "qa"`, `3 secrets`
	Expected    string // what the user types to confirm: "qa", "3"
	Label       string // how the prompt names Expected: "the environment slug", "the number of secrets"
	Description string // "environment qa and all of its secrets"
}

// addConfirmFlags gives a destructive command -y/--yes. Pair it with confirmDestructive.
func addConfirmFlags(cmd *cobra.Command) {
	cmd.Flags().BoolP("yes", "y", false, "Delete without asking for confirmation (for scripts and agents)")
}

// confirmDestructive asks the user to type the name of what's being deleted. --yes skips the
// question. Without a terminal and without --yes, it returns a confirmation_required error that
// suggests the same command with --yes, so a script or agent never deletes by accident.
func confirmDestructive(cmd *cobra.Command, args []string, action destructiveAction) error {
	if yes, _ := cmd.Flags().GetBool("yes"); yes {
		return nil
	}
	if !stdinIsTerminal() {
		return errConfirmationRequired(action, rerunWithYes(cmd, args))
	}

	util.PrintlnStderr(fmt.Sprintf("This deletes %s.", util.SanitizeDisplay(action.Description)))
	typed, err := promptForConfirmation(fmt.Sprintf("Type %s to confirm", action.Label))
	if err != nil || strings.TrimSpace(typed) != action.Expected {
		return errConfirmationDeclined(action)
	}
	return nil
}

// rerunWithYes rebuilds the command the user ran, with --yes added. It uses the full command path, so
// a command run as `sm` is suggested as `secrets-manager`. Positional arguments and identifier flags
// keep their values when they are safe identifiers; every other value becomes a placeholder, and
// credential flags are left out.
func rerunWithYes(cmd *cobra.Command, args []string) string {
	parts := []string{cmd.CommandPath()}
	for _, arg := range args {
		if name, _, isAssignment := strings.Cut(arg, "="); isAssignment {
			parts = append(parts, util.SuggestedValue(name, "name")+"=<value>")
			continue
		}
		parts = append(parts, util.SuggestedValue(arg, "value"))
	}

	cmd.Flags().Visit(func(f *pflag.Flag) {
		if f.Name == "yes" || credentialFlags[f.Name] {
			return
		}
		switch {
		case f.Value.Type() == "bool":
			if f.Value.String() == "true" {
				parts = append(parts, "--"+f.Name)
			} else {
				parts = append(parts, "--"+f.Name+"=false")
			}
		case f.Name == "domain":
			parts = append(parts, "--domain "+util.SuggestedDomain(f.Value.String()))
		default:
			values := []string{f.Value.String()}
			if slice, ok := f.Value.(pflag.SliceValue); ok {
				values = slice.GetSlice()
			}
			for _, value := range values {
				if !rerunIdentifierFlags[f.Name] {
					value = "<" + f.Name + ">"
				}
				parts = append(parts, "--"+f.Name+" "+util.SuggestedValue(value, f.Name))
			}
		}
	})

	return strings.Join(append(parts, "--yes"), " ")
}

// requireConfirmation gives cmd -y/--yes and makes it confirm before its Run deletes anything.
// describe says what the arguments would delete; when it returns false (missing input), Run reports
// the problem itself, as before.
func requireConfirmation(cmd *cobra.Command, describe func(cmd *cobra.Command, args []string) (destructiveAction, bool)) {
	addConfirmFlags(cmd)
	run := cmd.Run
	cmd.Run = func(cmd *cobra.Command, args []string) {
		if action, ok := describe(cmd, args); ok {
			if err := confirmDestructive(cmd, args, action); err != nil {
				exitWithError(cmd, err)
			}
		}
		run(cmd, args)
	}
}
