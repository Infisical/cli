/*
Copyright (c) 2023 Infisical Inc.
*/
package main

import (
	"github.com/Infisical/infisical-merge/packages/cmd"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(cmd.GetLoggerConfig())
	cmd.Execute()
}
