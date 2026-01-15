/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
)

var Telemetry *telemetry.Telemetry

var RootCmd = &cobra.Command{
	Use:               "infisical",
	Short:             "Infisical CLI is used to inject environment variables into any process",
	Long:              `Infisical is a simple, end-to-end encrypted service that enables teams to sync and manage their environment variables across their development life cycle.`,
	CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
	Version:           util.CLI_VERSION,
}

// rootCmdStderrWriter is a writer wrapper that dynamically reads from RootCmd.ErrOrStderr()
// on each write. This allows the logger to automatically use RootCmd's stderr even if it's
// changed after logger initialization (e.g., in tests).
type rootCmdStderrWriter struct{}

func (w *rootCmdStderrWriter) Write(p []byte) (n int, err error) {
	return RootCmd.ErrOrStderr().Write(p)
}

// RootCmdStderrWriter returns a writer that proxies all writes to RootCmd.ErrOrStderr().
// This writer dynamically reads from RootCmd on each write, so it will automatically
// use whatever stderr is set on RootCmd, even if changed after initialization.
func RootCmdStderrWriter() io.Writer {
	return &rootCmdStderrWriter{}
}

// rootCmdStdoutWriter is a writer wrapper that dynamically reads from RootCmd.OutOrStdout()
// on each write. This allows the logger to automatically use RootCmd's stdout even if it's
// changed after logger initialization (e.g., in tests).
type rootCmdStdoutWriter struct{}

func (w *rootCmdStdoutWriter) Write(p []byte) (n int, err error) {
	return RootCmd.OutOrStdout().Write(p)
}

// RootCmdStdoutWriter returns a writer that proxies all writes to RootCmd.OutOrStdout().
// This writer dynamically reads from RootCmd on each write, so it will automatically
// use whatever stdout is set on RootCmd, even if changed after initialization.
func RootCmdStdoutWriter() io.Writer {
	return &rootCmdStdoutWriter{}
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	util.GetStderrWriter = RootCmdStderrWriter
	util.GetStdoutWriter = RootCmdStdoutWriter
	cobra.OnInitialize(initLog)
	RootCmd.PersistentFlags().StringP("log-level", "l", "", "log level (trace, debug, info, warn, error, fatal)")
	RootCmd.PersistentFlags().Bool("telemetry", true, "Infisical collects non-sensitive telemetry data to enhance features and improve user experience. Participation is voluntary")
	RootCmd.PersistentFlags().StringVar(&config.INFISICAL_URL, "domain", fmt.Sprintf("%s/api", util.INFISICAL_DEFAULT_US_URL), "Point the CLI to your Infisical instance (e.g., https://eu.infisical.com for EU Cloud, or https://your-instance.com for self-hosted). Can also set via INFISICAL_API_URL environment variable. Required for non-US Cloud users.")
	RootCmd.PersistentFlags().Bool("silent", false, "Disable output of tip/info messages. Useful when running in scripts or CI/CD pipelines.")
	RootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		silent, err := cmd.Flags().GetBool("silent")
		if err != nil {
			util.HandleError(err)
		}

		config.INFISICAL_URL = util.AppendAPIEndpoint(config.INFISICAL_URL)

		// util.DisplayAptInstallationChangeBannerWithWriter(silent, cmd.ErrOrStderr())
		if !util.IsRunningInDocker() && !silent {
			util.CheckForUpdateWithWriter(cmd.ErrOrStderr())
		}

		loggedInDetails, err := util.GetCurrentLoggedInUserDetails(false)

		if !silent && err == nil && loggedInDetails.IsUserLoggedIn && !loggedInDetails.LoginExpired {
			token, err := util.GetInfisicalToken(cmd)

			if err == nil && token != nil {
				util.PrintWarningWithWriter(fmt.Sprintf("Your logged-in session is being overwritten by the token provided from the %s.", token.Source), cmd.ErrOrStderr())
			}
		}

	}

	// if config.INFISICAL_URL is set to the default value, check if INFISICAL_URL is set in the environment
	// this is used to allow overrides of the default value
	if !RootCmd.Flag("domain").Changed {
		if envInfisicalBackendUrl, ok := os.LookupEnv("INFISICAL_API_URL"); ok {
			config.INFISICAL_URL = util.AppendAPIEndpoint(envInfisicalBackendUrl)
		}
	}

	isTelemetryOn, _ := RootCmd.PersistentFlags().GetBool("telemetry")
	Telemetry = telemetry.NewTelemetry(isTelemetryOn)
}

func initLog() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	ll, err := RootCmd.Flags().GetString("log-level")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	if ll == "" {
		ll = os.Getenv("LOG_LEVEL")

		if ll == "" {
			ll = "info"
		}
	}

	switch strings.ToLower(ll) {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "err", "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

// GetLoggerConfig returns the logger configuration with the provided writer.
func GetLoggerConfig(w io.Writer) zerolog.ConsoleWriter {
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

	return zerolog.ConsoleWriter{
		Out:        w,
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
	}
}
