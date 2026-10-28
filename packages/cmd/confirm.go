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

// Flags whose values never go into a suggested command, whatever they contain.
var credentialFlags = map[string]bool{"token": true, "client-secret": true, "client-id": true, "password": true, "passphrase": true}

// destructiveAction is what a command is about to delete.
type destructiveAction struct {
	Kind        string // "project", "environment"
	Slug        string // what the user has to type to confirm
	Description string // "project payments-api and all of its environments and secrets"
}

// addConfirmFlags gives a destructive command -y/--yes. Pair it with confirmDestructive.
func addConfirmFlags(cmd *cobra.Command) {
	cmd.Flags().BoolP("yes", "y", false, "Delete without asking for confirmation (for scripts and agents)")
}

// confirmDestructive asks the user to type the slug of what's being deleted. --yes skips the
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
	typed, err := promptForConfirmation(fmt.Sprintf("Type the %s slug to confirm", action.Kind))
	if err != nil || strings.TrimSpace(typed) != action.Slug {
		return errConfirmationDeclined(action)
	}
	return nil
}

// rerunWithYes rebuilds the command the user ran, with --yes added. It uses the full command path, so
// a command run as `sm` is suggested as `secrets-manager`. Values that aren't safe identifiers become
// placeholders, and credential flags are left out.
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
				parts = append(parts, "--"+f.Name+" "+util.SuggestedValue(value, f.Name))
			}
		}
	})

	return strings.Join(append(parts, "--yes"), " ")
}
