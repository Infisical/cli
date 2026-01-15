/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"

	mcobra "github.com/muesli/mango-cobra"
	"github.com/muesli/roff"
	"github.com/spf13/cobra"

	"github.com/Infisical/infisical-merge/packages/util"
)

var manCmd = &cobra.Command{
	Use:                   "man",
	Short:                 "generates the manpages",
	SilenceUsage:          true,
	DisableFlagsInUseLine: true,
	Hidden:                true,
	Args:                  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		manPage, err := mcobra.NewManPage(1, RootCmd)
		if err != nil {
			return err
		}

		_, err = fmt.Fprint(util.GetStdoutWriter(), manPage.Build(roff.NewDocument()))
		return err
	},
}

func init() {
	RootCmd.AddCommand(manCmd)
}
