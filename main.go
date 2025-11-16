/*
Copyright (c) 2023 Infisical Inc.
*/
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/cmd"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {

	// very annoying but zerolog doesn't allow us to change one color without changing all of them
	// these are the default colors for each level, except for warn
	levelColors := map[string]string{
		"trace": "\033[35m", // magenta
		"debug": "\033[33m", // yellow
		"info":  "\033[32m", // green
		"warn":  "\033[33m", // yellow (this one is custom, the default is red \033[31m)
		"error": "\033[31m", // red
		"fatal": "\033[31m", // red
		"panic": "\033[31m", // red
	}

	// map full level names to abbreviated forms (default zerolog behavior)
	// see consoleDefaultFormatLevel, in zerolog for example
	levelAbbrev := map[string]string{
		"trace": "TRC",
		"debug": "DBG",
		"info":  "INF",
		"warn":  "WRN",
		"error": "ERR",
		"fatal": "FTL",
		"panic": "PNC",
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		FormatLevel: func(i interface{}) string {
			level := fmt.Sprintf("%s", i)
			color := levelColors[level]
			if color == "" {
				color = "\033[0m" // no color for unknown levels
			}
			abbrev := levelAbbrev[level]
			if abbrev == "" {
				abbrev = strings.ToUpper(level) // fallback to uppercase if unknown
			}
			return color + abbrev + "\033[0m"
		},
	})
	cmd.Execute()
}
