/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/Infisical/infisical-merge/packages/itui"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the Infisical Terminal UI (ITUI)",
	Long:  `ITUI is an AI-powered terminal user interface for Infisical. Use natural language to manage secrets, switch environments, and explore your projects.`,
	Example: `  infisical tui
  GEMINI_API_KEY=your-key infisical tui`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if err := itui.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error running ITUI: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(tuiCmd)
}
