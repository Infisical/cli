package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const zshShellInit = `# Infisical automatic command wrapper
if [[ -o interactive ]]; then
  _infisical_auto_run_prefixes=(npm pnpm bun node)

  _infisical_auto_run_accept_line() {
    local command="${BUFFER%%[[:space:]]*}"
    local prefix

    for prefix in "${_infisical_auto_run_prefixes[@]}"; do
      if [[ "$command" == "$prefix" ]]; then
        BUFFER="infisical run -- $BUFFER"
        break
      fi
    done

    zle .accept-line
  }

  zle -N accept-line _infisical_auto_run_accept_line
fi
`

var shellInitCmd = &cobra.Command{
	Use:                   "shell-init [zsh]",
	Short:                 "prints shell integration for automatically injecting secrets",
	Args:                  cobra.ExactArgs(1),
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] != "zsh" {
			return fmt.Errorf("unsupported shell %q, supported shells: zsh", args[0])
		}

		_, err := fmt.Fprint(cmd.OutOrStdout(), zshShellInit)
		return err
	},
}

func init() {
	RootCmd.AddCommand(shellInitCmd)
}
