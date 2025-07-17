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
)

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:                   "export",
	Short:                 "Used to export environment variables to a file",
	DisableFlagsInUseLine: true,
	Example:               "infisical export --env=prod --format=json > secrets.json\ninfisical export --env=prod --format=json --output-file=secrets.json",
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

		projectId, err := cmd.Flags().GetString("projectId")
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

		request := models.GetAllSecretsParameters{
			Environment:            environmentName,
			TagSlugs:               tagSlugs,
			WorkspaceId:            projectId,
			SecretsPath:            secretsPath,
			IncludeImport:          includeImports,
			ExpandSecretReferences: shouldExpandSecrets,
		}

		if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER {
			request.InfisicalToken = token.Token
		} else if token != nil && token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER {
			request.UniversalAuthAccessToken = token.Token
		}

		if templatePath != "" {
			sigChan := make(chan os.Signal, 1)
			dynamicSecretLeases := NewDynamicSecretLeaseManager(sigChan)
			newEtag := ""

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

			processedTemplate, err := ProcessTemplate(1, templatePath, nil, accessToken, "", &newEtag, dynamicSecretLeases)
			if err != nil {
				util.HandleError(err)
			}
			fmt.Print(processedTemplate.String())
			return
		}

		secrets, err := util.GetAllEnvironmentVariables(request, "")
		if err != nil {
			util.HandleError(err, "Unable to fetch secrets")
		}

		if secretOverriding {
			secrets = util.OverrideSecrets(secrets, util.SECRET_TYPE_PERSONAL)
		} else {
			secrets = util.OverrideSecrets(secrets, util.SECRET_TYPE_SHARED)
		}

		var output string
		secrets = util.FilterSecretsByTag(secrets, tagSlugs)
		secrets = util.SortSecretsByKeys(secrets)

		output, err = formatEnvs(secrets, format)
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

			fmt.Printf("Successfully exported secrets to: %s\n", finalPath)
		} else {
			// Original behavior - print to stdout when no output file specified
			fmt.Print(output)
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
	case FormatDotenv:
		return ".env"
	default:
		return ".env"
	}
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringP("env", "e", "dev", "Set the environment (dev, prod, etc.) from which your secrets should be pulled from")
	exportCmd.Flags().Bool("expand", true, "Parse shell parameter expansions in your secrets")
	exportCmd.Flags().StringP("format", "f", "dotenv", "Set the format of the output file (dotenv, json, csv)")
	exportCmd.Flags().Bool("secret-overriding", true, "Prioritizes personal secrets, if any, with the same name over shared secrets")
	exportCmd.Flags().Bool("include-imports", true, "Imported linked secrets")
	exportCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	exportCmd.Flags().StringP("tags", "t", "", "filter secrets by tag slugs")
	exportCmd.Flags().String("projectId", "", "manually set the projectId to export secrets from")
	exportCmd.Flags().String("path", "/", "get secrets within a folder path")
	exportCmd.Flags().String("template", "", "The path to the template file used to render secrets")
	exportCmd.Flags().StringP("output-file", "o", "", "The path to write the output file to. Can be a full file path, directory, or filename. If not specified, output will be printed to stdout")
}

// Format according to the format flag
func formatEnvs(envs []models.SingleEnvironmentVariable, format string) (string, error) {
	switch strings.ToLower(format) {
	case FormatDotenv:
		return formatAsDotEnv(envs), nil
	case FormatDotEnvExport:
		return formatAsDotEnvExport(envs), nil
	case FormatJson:
		return formatAsJson(envs), nil
	case FormatCSV:
		return formatAsCSV(envs), nil
	case FormatYaml:
		return formatAsYaml(envs)
	default:
		return "", fmt.Errorf("invalid format type: %s. Available format types are [%s]", format, []string{FormatDotenv, FormatJson, FormatCSV, FormatYaml, FormatDotEnvExport})
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
func formatAsDotEnv(envs []models.SingleEnvironmentVariable) string {
	var dotenv string
	for _, env := range envs {
		dotenv += fmt.Sprintf("%s='%s'\n", env.Key, escapeNewLinesIfRequired(env))
	}
	return dotenv
}

// Format environment variables as a dotenv file with export at the beginning
func formatAsDotEnvExport(envs []models.SingleEnvironmentVariable) string {
	var dotenv string
	for _, env := range envs {
		dotenv += fmt.Sprintf("export %s='%s'\n", env.Key, escapeNewLinesIfRequired(env))
	}
	return dotenv
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