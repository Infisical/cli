/*
Copyright (c) 2023 Infisical Inc.
*/
package main

import (
	"os"

	"github.com/Infisical/infisical-merge/packages/cmd"
	"github.com/rs/zerolog/log"
)

func main() {
	// Trigger scan
	log.Logger = log.Output(cmd.GetLoggerConfig(os.Stderr))
	cmd.Execute()
}
