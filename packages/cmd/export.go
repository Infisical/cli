/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

const (
	FormatDotenv       string = "dotenv"
	FormatJson         string = "json"
	FormatCSV          string = "csv"
	FormatYaml         string = "yaml"
	FormatDotEnvExport string = "dotenv-export"
	FormatDotEnvEval   string = "dotenv-eval"
)

const (
	QuoteCharSingle string = "'"
	QuoteCharDouble string = `"`
)

// POSIX portable variable name, the only shape a shell can bind a value to.
var shellVariableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:                   "export",
	Short:                 "Used to export environment variables to a file",
	DisableFlagsInUseLine: true,
	Example:               "infisical export --env=prod --format=json > secrets.json\ninfisical export --env=prod --format=json --output-file=secrets.json\ninfisical export --env=prod --dotenv-quote-char='\"' > .env",
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		environmentName, _ := cmd.Flags().GetString("env")
		if !cmd.Flags().Changed("env") {
			environmentFromWorkspace := util.GetEnvFromWorkspaceFile()
			if environmentFromWorkspace != "" {
				environmentName = environmentFromWorkspace
			}
		}

		shouldExpandSecrets, err := cmd.Flags().GetBool("expand")
		if err != nil {
			util.HandleError(err)
		}

		includeImports, err := cmd.Flags().GetBool("include-imports")
		if err != nil {
			util.HandleError(err)
		}

		projectId, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "projectId", []string{util.INFISICAL_PROJECT_ID_NAME}, "")
		if err != nil {
			util.HandleError(err)
		}

		token, err := util.GetInfisicalToken(cmd)
		if err != nil {
			util.HandleError(err, "Unable to parse flag")
		}

		format, err := cmd.Flags().GetString("format")
		if err != nil {
			util.HandleError(err)
		}

		templatePath, err := cmd.Flags().GetString("template")
		if err != nil {
			util.HandleError(err)
		}

		secretOverriding, err := cmd.Flags().GetBool("secret-overriding")
		if err != nil {
			util.HandleError(err, "Unable to parse flag")
		}

		tagSlugs, err := cmd.Flags().GetString("tags")
		if err != nil {
			util.HandleError(err, "Unable to parse flag")
		}

		secretsPath, err := cmd.Flags().GetString("path")
		if err != nil {
			util.HandleError(err, "Unable to parse flag")
		}

		outputFile, err := cmd.Flags().GetString("output-file")
		if err != nil {
			util.HandleError(err, "Unable to parse flag")
		}

		dotEnvQuoteChar, err := cmd.Flags().GetString("dotenv-quote-char")
		if err != nil {
			util.HandleError(err, "Unable to parse flag")
		}

		// Validated up front, before any secrets are fetched, so that a typo is
		// reported immediately instead of after a network round trip. This runs
		// regardless of the chosen format, so that an unusable value is never
		// silently accepted just because the format happens to ignore it.
		if err := validateDotEnvQuoteChar(dotEnvQuoteChar); err != nil {
			util.HandleError(err)
		}

		request := models.GetAllSecretsParameters{
			Environment:              environmentName,
			TagSlugs:                 tagSlugs,
			WorkspaceId:              projectId,
			SecretsPath:              secretsPath,
			IncludeImport:            includeImports,
			ExpandSecretReferences:   shouldExpandSecrets,
			IncludePersonalOverrides: secretOverriding,
		}

		if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER {
			request.InfisicalToken = token.Token
		} else if token != nil && token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER {
			request.UniversalAuthAccessToken = token.Token
		}

		if templatePath != "" {
			dynamicSecretLeases := NewDynamicSecretLeaseManager(nil, nil)

			accessToken := ""
			if token != nil {
				accessToken = token.Token
			} else {
				log.Debug().Msg("GetAllEnvironmentVariables: Trying to fetch secrets using logged in details")
				loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
				if err != nil {
					util.HandleError(err)
				}
				accessToken = loggedInUserDetails.UserCredentials.JTWToken
			}

			currentEtag := ""
			processedTemplate, err := ProcessTemplate(1, templatePath, nil, accessToken, &currentEtag, dynamicSecretLeases, nil)
			if err != nil {
				util.HandleError(err)
			}
			util.PrintStdout(processedTemplate.String())
			return
		}

		secrets, err := util.GetAllEnvironmentVariables(request, "")
		if err != nil {
			util.HandleError(err, "Unable to fetch secrets")
		}

		var output string
		secrets = util.FilterSecretsByTag(secrets, tagSlugs)
		secrets = util.SortSecretsByKeys(secrets)

		output, err = formatEnvs(secrets, format, dotEnvQuoteChar)
		if err != nil {
			util.HandleError(err)
		}

		// Handle output file logic - only save to file if --output-file is specified
		if outputFile != "" {
			finalPath, err := resolveOutputPath(outputFile, format)
			if err != nil {
				util.HandleError(err, "Unable to resolve output path")
			}

			err = writeToFile(finalPath, output, 0644)
			if err != nil {
				util.HandleError(err, "Failed to write output to file")
			}

			util.PrintfStderr("Successfully exported secrets to: %s\n", finalPath)
		} else {
			// Original behavior - print to stdout when no output file specified
			util.PrintStdout(output)
		}

		// Telemetry.CaptureEvent("cli-command:export", posthog.NewProperties().Set("secretsCount", len(secrets)).Set("version", util.CLI_VERSION))
	},
}

// resolveOutputPath determines the final output path based on the provided path and format
func resolveOutputPath(outputFile, format string) (string, error) {
	// Expand ~ to home directory if present
	if strings.HasPrefix(outputFile, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to resolve home directory: %w", err)
		}
		outputFile = strings.Replace(outputFile, "~", homeDir, 1)
	}

	// Get absolute path to handle relative paths consistently
	absPath, err := filepath.Abs(outputFile)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// Check if the path is a directory
	if info, err := os.Stat(absPath); err == nil && info.IsDir() {
		// If it's a directory, append the default filename
		defaultFilename := getDefaultFilename(format)
		return filepath.Join(absPath, defaultFilename), nil
	} else if os.IsNotExist(err) {
		// Path doesn't exist, check if it looks like a directory (ends with /)
		if strings.HasSuffix(absPath, string(filepath.Separator)) {
			// Treat as directory, create it and add default filename
			err := os.MkdirAll(absPath, 0755)
			if err != nil {
				return "", fmt.Errorf("failed to create directory %s: %w", absPath, err)
			}
			defaultFilename := getDefaultFilename(format)
			return filepath.Join(absPath, defaultFilename), nil
		}

		// Ensure the parent directory exists
		parentDir := filepath.Dir(absPath)
		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			err := os.MkdirAll(parentDir, 0755)
			if err != nil {
				return "", fmt.Errorf("failed to create parent directory %s: %w", parentDir, err)
			}
		}

		// If no extension provided, add default extension based on format
		if filepath.Ext(absPath) == "" {
			ext := getDefaultExtension(format)
			absPath += ext
		}
	}

	return absPath, nil
}

// getDefaultFilename returns the default filename based on the format
func getDefaultFilename(format string) string {
	switch strings.ToLower(format) {
	case FormatJson:
		return "secrets.json"
	case FormatCSV:
		return "secrets.csv"
	case FormatYaml:
		return "secrets.yaml"
	case FormatDotEnvExport:
		return ".env"
	case FormatDotEnvEval:
		return ".env"
	case FormatDotenv:
		return ".env"
	default:
		return ".env"
	}
}

// getDefaultExtension returns the default file extension based on the format
func getDefaultExtension(format string) string {
	switch strings.ToLower(format) {
	case FormatJson:
		return ".json"
	case FormatCSV:
		return ".csv"
	case FormatYaml:
		return ".yaml"
	case FormatDotEnvExport:
		return ".env"
	case FormatDotEnvEval:
		return ".env"
	case FormatDotenv:
		return ".env"
	default:
		return ".env"
	}
}

func init() {
	RootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringP("env", "e", "dev", "Set the environment (dev, prod, etc.) from which your secrets should be pulled from")
	exportCmd.Flags().Bool("expand", true, "Parse shell parameter expansions in your secrets")
	exportCmd.Flags().StringP("format", "f", "dotenv", "Set the format of the output file (dotenv, dotenv-export, dotenv-eval, json, csv, yaml)")
	exportCmd.Flags().Bool("secret-overriding", true, "Prioritizes personal secrets, if any, with the same name over shared secrets")
	exportCmd.Flags().Bool("include-imports", true, "Imported linked secrets")
	exportCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	exportCmd.Flags().StringP("tags", "t", "", "filter secrets by tag slugs")
	exportCmd.Flags().String("projectId", "", "manually set the projectId to export secrets from")
	exportCmd.Flags().String("path", "/", "get secrets within a folder path")
	exportCmd.Flags().String("template", "", "The path to the template file used to render secrets")
	exportCmd.Flags().StringP("output-file", "o", "", "The path to write the output file to. Can be a full file path, directory, or filename. If not specified, output will be printed to stdout")
	exportCmd.Flags().String("dotenv-quote-char", QuoteCharSingle, `Set the character used to wrap values in the dotenv format (' or "). Double quotes let dotenv parsers interpret escape sequences such as \n. Ignored by every other format, including dotenv-export, whose values are always wrapped so they are safe to source in a shell`)
}

// Format according to the format flag. quoteChar is the character used to wrap
// values in the dotenv format, and is ignored by every other format, including
// dotenv-export. It is validated by the caller before any secrets are fetched.
func formatEnvs(envs []models.SingleEnvironmentVariable, format string, quoteChar string) (string, error) {
	switch strings.ToLower(format) {
	case FormatDotenv:
		return formatAsDotEnv(envs, quoteChar), nil
	case FormatDotEnvExport:
		return formatAsDotEnvExport(envs)
	case FormatDotEnvEval:
		return formatAsDotEnvEval(envs)
	case FormatJson:
		return formatAsJson(envs), nil
	case FormatCSV:
		return formatAsCSV(envs), nil
	case FormatYaml:
		return formatAsYaml(envs)
	default:
		return "", fmt.Errorf("invalid format type: %s. Available format types are [%s]", format, []string{FormatDotenv, FormatJson, FormatCSV, FormatYaml, FormatDotEnvExport, FormatDotEnvEval})
	}
}

// Format environment variables as a CSV file
func formatAsCSV(envs []models.SingleEnvironmentVariable) string {
	csvString := &strings.Builder{}
	writer := csv.NewWriter(csvString)
	writer.Write([]string{"Key", "Value"})
	for _, env := range envs {
		writer.Write([]string{env.Key, escapeNewLinesIfRequired(env)})
	}
	writer.Flush()
	return csvString.String()
}

// Format environment variables as a dotenv file
func formatAsDotEnv(envs []models.SingleEnvironmentVariable, quoteChar string) string {
	var dotenv string
	for _, env := range envs {
		dotenv += fmt.Sprintf("%s=%s\n", env.Key, quoteDotEnvValue(env, quoteChar))
	}
	return dotenv
}

// Format environment variables as a dotenv file with export at the beginning.
// Every line is meant to be sourced by a shell, so values are always quoted the
// way dotenv-eval quotes them and never with the dotenv quote character: a
// value containing that character would otherwise close the wrapping early and
// let the rest of the value run as shell code.
func formatAsDotEnvExport(envs []models.SingleEnvironmentVariable) (string, error) {
	return formatAsDotEnvEval(envs)
}

// validateDotEnvQuoteChar checks that the quote character used by the dotenv
// format is one that dotenv parsers actually understand.
func validateDotEnvQuoteChar(quoteChar string) error {
	if quoteChar != QuoteCharSingle && quoteChar != QuoteCharDouble {
		return fmt.Errorf("invalid quote character: %q. Available quote characters are [%s]", quoteChar, strings.Join([]string{QuoteCharSingle, QuoteCharDouble}, ", "))
	}

	return nil
}

// quoteDotEnvValue wraps a secret value in quoteChar. The value itself is
// written verbatim, so the quote character is the only difference between the
// two styles.
//
// No backslash or quote escaping is applied, deliberately. Dotenv parsers
// extract a value by finding the quotes that delimit it and then treat what is
// between them as opaque; they do not generally undo escape sequences on read.
// Escaping on write would therefore never be unescaped again, and would only
// leave stray backslashes in the parsed value without protecting anything.
//
// The double quote style exists purely so that the "\n" produced by
// escapeNewLinesIfRequired is decoded back into a real newline, which is
// something parsers only do for double quoted values. That is the whole reason
// to pick it over the single quote default.
func quoteDotEnvValue(env models.SingleEnvironmentVariable, quoteChar string) string {
	return quoteChar + escapeNewLinesIfRequired(env) + quoteChar
}

// Format environment variables for shell eval/source. Values are wrapped in
// single quotes with POSIX escaping so the output is safe to evaluate via
// `eval "$(infisical export --format=dotenv-eval)"` regardless of value
// contents (newlines, single quotes, $, ", \, etc.).
//
// Secret names are not restricted to shell variable names, so they are checked
// against the portable syntax rather than escaped. Escaping cannot help there:
// the name is re-parsed by `export` after quote removal, and several shapes are
// assignments to a different variable rather than errors. `PATH=x` assigns to
// PATH because the split is on the first `=`, and `PATH+` appends to PATH
// because bash reads the result as `PATH+=`. A name outside the portable syntax
// cannot be bound by a shell at all, so the whole batch is rejected instead.
//
// The `--` is redundant with that check and kept as a second layer, so that a
// name starting with `-` can never be read as a flag.
func formatAsDotEnvEval(envs []models.SingleEnvironmentVariable) (string, error) {
	var dotenv string
	for _, env := range envs {
		if !shellVariableName.MatchString(env.Key) {
			return "", fmt.Errorf("cannot export secret %q to a shell format: a shell variable name may only contain ASCII letters, digits and underscores, and may not start with a digit. Other names are either rejected by the shell or silently applied to a different variable, the way names like PATH= and PATH+ are. Rename the secret, or export it with a format other than %s and %s", env.Key, FormatDotEnvExport, FormatDotEnvEval)
		}

		dotenv += fmt.Sprintf("export -- %s=%s\n", env.Key, posixShellQuote(env.Value))
	}
	return dotenv, nil
}

// posixShellQuote wraps a value in single quotes and escapes any embedded
// single quotes using the standard `'\''` sequence. Single-quoted POSIX
// strings preserve every other character verbatim (including newlines,
// backslashes, $, and "), so this is sufficient for eval/source.
func posixShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func formatAsYaml(envs []models.SingleEnvironmentVariable) (string, error) {
	m := make(map[string]string)
	for _, env := range envs {
		m[env.Key] = escapeNewLinesIfRequired(env)
	}

	yamlBytes, err := yaml.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to format environment variables as YAML: %w", err)
	}

	return string(yamlBytes), nil
}

// Format environment variables as a JSON file
func formatAsJson(envs []models.SingleEnvironmentVariable) string {
	// Dump as a json array
	json, err := json.Marshal(envs)
	if err != nil {
		log.Err(err).Msgf("Unable to marshal environment variables to JSON")
		return ""
	}
	return string(json)
}

func escapeNewLinesIfRequired(env models.SingleEnvironmentVariable) string {
	if env.IsMultilineEncodingEnabled() && strings.ContainsRune(env.Value, '\n') {
		return strings.ReplaceAll(env.Value, "\n", "\\n")
	}

	return env.Value
}
