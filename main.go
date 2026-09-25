/*
Copyright (c) 2023 Infisical Inc.
*/
package main

import (
	"os"

	"github.com/Infisical/infisical-merge/packages/cmd"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog/log"
)

func main() {
	// Initialize logger with sensible defaults before flag parsing.
	// This will be reconfigured by initLogOutput() after flags are parsed.
	noColor := !isatty.IsTerminal(os.Stderr.Fd()) || isNoColorEnvSet()
	log.Logger = log.Output(cmd.GetLoggerConfig(os.Stderr, noColor))
	cmd.Execute()
}

// isNoColorEnvSet returns true if NO_COLOR env var is set to a non-empty value.
// Per https://no-color.org/, an empty string does not disable colors.
func isNoColorEnvSet() bool {
	val, ok := os.LookupEnv("NO_COLOR")
	return ok && val != ""
}
