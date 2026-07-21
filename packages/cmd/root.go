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

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/telemetry"
	"github.com/Infisical/infisical-merge/packages/util"
)

var Telemetry *telemetry.Telemetry

// Log configuration variables set via flags
var (
	logFormat      string
	logDestination string
)

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

// isStructuredOutputRequested checks whether the command has a --format or --output
// flag explicitly set to a machine-readable format (json, csv, yaml). When true,
// human-oriented messages like update notifications should be suppressed to avoid
// breaking parsers that consume the CLI output.
func isStructuredOutputRequested(cmd *cobra.Command) bool {
	structuredFormats := map[string]bool{"json": true, "csv": true, "yaml": true}

	for _, flagName := range []string{"format", "output", "report-format"} {
		if f := cmd.Flags().Lookup(flagName); f != nil && f.Changed {
			if structuredFormats[strings.ToLower(f.Value.String())] {
				return true
			}
		}
	}
	return false
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute() {
	defer util.WaitForUpdateCheck()
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// resolveDomain picks the domain by precedence: --domain flag > env > .infisical.json > default (flagValue).
// Must run after flag parsing (PersistentPreRun, not init) so cmd.Flags().Changed is reliable.
func resolveDomain(cmd *cobra.Command, flagValue string) string {
	if cmd.Flags().Changed("domain") {
		return flagValue
	}

	if envDomain, ok := util.GetEnvDomain(); ok {
		return envDomain
	}

	workspaceConfig, err := util.GetWorkSpaceFromFile()
	if err != nil || workspaceConfig.Domain == "" {
		return flagValue
	}

	domain := workspaceConfig.Domain
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		util.PrintWarningWithWriter("The 'domain' field in .infisical.json is not a valid URL (must start with http:// or https://). It will be ignored.", cmd.ErrOrStderr())
		return flagValue
	}

	// A .infisical.json is usually committed to the repo, so a malicious one could redirect requests
	// and credentials. Always surface where traffic is going (even under --silent); it goes to stderr.
	util.PrintWarningWithWriter(fmt.Sprintf("Using domain '%s' from .infisical.json; all requests and credentials will be sent there.", domain), cmd.ErrOrStderr())
	return domain
}

func init() {
	util.GetStderrWriter = RootCmdStderrWriter
	util.GetStdoutWriter = RootCmdStdoutWriter
	cobra.OnInitialize(initLog, initLogOutput)
	RootCmd.PersistentFlags().StringP("log-level", "l", "", "log level (trace, debug, info, warn, error, fatal)")
	RootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "", "log output format: console (default), plain, json. Console mode auto-disables colors in non-TTY environments or when NO_COLOR is set. Can also set via LOG_FORMAT env var.")
	RootCmd.PersistentFlags().StringVar(&logDestination, "log-destination", "", "log output destination: stderr (default), stdout. Can also set via LOG_DESTINATION env var.")
	RootCmd.PersistentFlags().Bool("telemetry", true, "Infisical collects non-sensitive telemetry data to enhance features and improve user experience. Participation is voluntary")
	RootCmd.PersistentFlags().StringVar(&config.INFISICAL_URL, "domain", fmt.Sprintf("%s/api", util.INFISICAL_DEFAULT_US_URL), "Point the CLI to your Infisical instance (e.g., https://eu.infisical.com for EU Cloud, or https://your-instance.com for self-hosted). Can also set via INFISICAL_DOMAIN environment variable or the 'domain' field in .infisical.json. Required for non-US Cloud users.")
	RootCmd.PersistentFlags().Bool("silent", false, "Disable output of tip/info messages. Useful when running in scripts or CI/CD pipelines.")
	RootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		silent, err := cmd.Flags().GetBool("silent")
		if err != nil {
			util.HandleError(err)
		}

		config.INFISICAL_URL = util.AppendAPIEndpoint(resolveDomain(cmd, config.INFISICAL_URL))

		if !util.IsRunningInDocker() && !silent && !isStructuredOutputRequested(cmd) {
			util.CheckForUpdateWithWriter(cmd.ErrOrStderr())
			util.DisplayPackageRepoMigrationNoticeWithWriter(silent, cmd.ErrOrStderr())
		}

		loggedInDetails, err := util.GetCurrentLoggedInUserDetails(false)

		if !silent && err == nil && loggedInDetails.IsUserLoggedIn && !loggedInDetails.LoginExpired {
			token, err := util.GetInfisicalToken(cmd)

			if err == nil && token != nil {
				util.PrintWarningWithWriter(fmt.Sprintf("Your logged-in session is being overwritten by the token provided from the %s.", token.Source), cmd.ErrOrStderr())
			}
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

// initLogOutput configures the logger output format and destination based on
// flags and environment variables. Called via cobra.OnInitialize after flags
// are parsed.
func initLogOutput() {
	// Determine format: flag > env > default
	format := logFormat
	if format == "" {
		format = os.Getenv("LOG_FORMAT")
	}
	if format == "" {
		format = "console"
	}

	// Determine destination: flag > env > default
	dest := logDestination
	if dest == "" {
		dest = os.Getenv("LOG_DESTINATION")
	}
	if dest == "" {
		dest = "stderr"
	}

	// Select output writer based on destination
	var w io.Writer
	switch strings.ToLower(dest) {
	case "stdout":
		w = os.Stdout
	default:
		w = os.Stderr
	}

	// Configure logger based on format
	switch strings.ToLower(format) {
	case "json":
		// Raw JSON output - zerolog default without ConsoleWriter
		log.Logger = zerolog.New(w).With().Timestamp().Logger()
	case "plain":
		// Plain text without colors
		log.Logger = log.Output(GetLoggerConfig(w, true))
	default: // "console"
		// Colored console output, disable only if explicitly requested
		noColor := shouldDisableColor()
		log.Logger = log.Output(GetLoggerConfig(w, noColor))
	}
}

// shouldDisableColor returns true if ANSI color codes should be disabled.
// Colors are only disabled when explicitly requested via:
// - NO_COLOR env var set to a non-empty value (https://no-color.org/)
// - TERM=dumb
func shouldDisableColor() bool {
	// NO_COLOR env var (https://no-color.org/) - disables color when present and non-empty
	if val, ok := os.LookupEnv("NO_COLOR"); ok && val != "" {
		return true
	}

	// TERM=dumb indicates a dumb terminal without color support
	if os.Getenv("TERM") == "dumb" {
		return true
	}

	return false
}

func BuildAgentProxyLogWriter(format, filePath string) (io.Writer, error) {
	var stream io.Writer = os.Stderr
	if format != "json" {
		stream = GetLoggerConfig(os.Stderr, !isatty.IsTerminal(os.Stderr.Fd()))
	}

	if filePath == "" {
		return stream, nil
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %q: %w", filePath, err)
	}
	return zerolog.MultiLevelWriter(stream, f), nil
}

// GetLoggerConfig returns the logger configuration with the provided writer. noColor drops ANSI codes.
func GetLoggerConfig(w io.Writer, noColor bool) zerolog.ConsoleWriter {
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
		NoColor:    noColor,
		TimeFormat: time.RFC3339,
		// zerolog >= 1.35 bolds info/warn/error messages by default. Keep the message
		// rendered as-is so CLI output stays consistent with prior releases.
		FormatMessage: func(i interface{}) string {
			if i == nil {
				return ""
			}
			return fmt.Sprintf("%s", i)
		},
		FormatLevel: func(i interface{}) string {
			level := fmt.Sprintf("%s", i)
			abbrev := levelAbbrev[level]
			if abbrev == "" {
				abbrev = strings.ToUpper(level) // fallback to uppercase if unknown
			}
			if noColor {
				return abbrev
			}
			color := levelColors[level]
			if color == "" {
				color = "\033[0m" // no color for unknown levels
			}
			return color + abbrev + "\033[0m"
		},
	}
}
