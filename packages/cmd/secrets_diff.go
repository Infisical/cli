/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"sort"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/Infisical/infisical-merge/packages/visualize"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

const (
	secretDiffStatusAdded   = "added"
	secretDiffStatusRemoved = "removed"
	secretDiffStatusChanged = "changed"
)

// secretDiffEntry represents a single key's comparison result between two environments/paths.
type secretDiffEntry struct {
	Key       string
	Status    string
	LeftValue string
	// RightValue is unused when Status is secretDiffStatusRemoved, but kept for
	// completeness/output-formatting purposes.
	RightValue string
}

var secretsDiffCmd = &cobra.Command{
	Example:               `secrets diff --env=staging --env2=production`,
	Short:                 "Used to compare secrets between two environments and/or paths",
	Use:                   "diff",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run:                   diffSecrets,
}

func diffSecrets(cmd *cobra.Command, args []string) {
	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	projectId, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "projectId", []string{util.INFISICAL_PROJECT_ID_NAME}, "")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	env1, err := cmd.Flags().GetString("env")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}
	if !cmd.Flags().Changed("env") {
		if environmentFromWorkspace := util.GetEnvFromWorkspaceFile(); environmentFromWorkspace != "" {
			env1 = environmentFromWorkspace
		}
	}

	env2, err := cmd.Flags().GetString("env2")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}
	if env2 == "" {
		util.PrintErrorMessageAndExit("The --env2 flag is required to specify the environment to compare against")
	}

	path1, err := cmd.Flags().GetString("path")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	path2, err := cmd.Flags().GetString("path2")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}
	path2 = resolveDiffPath2(path1, path2)

	// Same environment is allowed when comparing different paths
	// (e.g. --env=staging --env2=staging --path=/app --path2=/db).
	if err := validateDiffTargets(env1, env2, path1, path2); err != nil {
		util.PrintErrorMessageAndExit(err.Error())
	}

	includeImports, err := cmd.Flags().GetBool("include-imports")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	recursive, err := cmd.Flags().GetBool("recursive")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	shouldExpandSecrets, err := cmd.Flags().GetBool("expand")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	showValues, err := cmd.Flags().GetBool("show-values")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	baseRequest := models.GetAllSecretsParameters{
		WorkspaceId:              projectId,
		SecretsPath:              path1,
		IncludeImport:            includeImports,
		Recursive:                recursive,
		ExpandSecretReferences:   shouldExpandSecrets,
		IncludePersonalOverrides: true,
	}

	if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER {
		baseRequest.InfisicalToken = token.Token
	} else if token != nil && token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER {
		baseRequest.UniversalAuthAccessToken = token.Token
	}

	leftRequest := baseRequest
	leftRequest.Environment = env1
	leftRequest.SecretsPath = path1

	rightRequest := baseRequest
	rightRequest.Environment = env2
	rightRequest.SecretsPath = path2

	leftSecrets, err := util.GetAllEnvironmentVariables(leftRequest, "")
	if err != nil {
		util.HandleError(err, fmt.Sprintf("Unable to fetch secrets for environment %q", env1))
	}

	rightSecrets, err := util.GetAllEnvironmentVariables(rightRequest, "")
	if err != nil {
		util.HandleError(err, fmt.Sprintf("Unable to fetch secrets for environment %q", env2))
	}

	diff := computeSecretDiff(leftSecrets, rightSecrets)

	outputFormat, err := cmd.Flags().GetString("output")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	if outputFormat != "" {
		var outputStructure []map[string]any
		for _, entry := range diff {
			row := map[string]any{
				"secretKey": entry.Key,
				"status":    entry.Status,
			}
			if showValues {
				row["leftValue"] = entry.LeftValue
				row["rightValue"] = entry.RightValue
			}
			outputStructure = append(outputStructure, row)
		}

		output, err := util.FormatOutput(outputFormat, outputStructure, &util.FormatOutputOptions{
			DotEnvArrayKeyAttribute:   "secretKey",
			DotEnvArrayValueAttribute: "status",
		})
		if err != nil {
			util.HandleError(err, "Unable to format output")
		}
		util.PrintStdout(output)
	} else {
		printSecretDiffTable(diff, env1, env2, showValues)
	}

	Telemetry.CaptureEvent("cli-command:secrets diff", posthog.NewProperties().Set("changedCount", len(diff)).Set("version", util.CLI_VERSION))
}

// computeSecretDiff compares two sets of secrets by key and returns entries for
// every key that was added, removed, or has a different value. Keys present in
// both sets with identical values are omitted. Results are sorted by key.
func computeSecretDiff(left, right []models.SingleEnvironmentVariable) []secretDiffEntry {
	leftByKey := make(map[string]models.SingleEnvironmentVariable, len(left))
	for _, secret := range left {
		leftByKey[secret.Key] = secret
	}

	rightByKey := make(map[string]models.SingleEnvironmentVariable, len(right))
	for _, secret := range right {
		rightByKey[secret.Key] = secret
	}

	var diff []secretDiffEntry

	for key, leftSecret := range leftByKey {
		rightSecret, existsInRight := rightByKey[key]
		if !existsInRight {
			diff = append(diff, secretDiffEntry{Key: key, Status: secretDiffStatusRemoved, LeftValue: leftSecret.Value})
			continue
		}
		if leftSecret.Value != rightSecret.Value {
			diff = append(diff, secretDiffEntry{Key: key, Status: secretDiffStatusChanged, LeftValue: leftSecret.Value, RightValue: rightSecret.Value})
		}
	}

	for key, rightSecret := range rightByKey {
		if _, existsInLeft := leftByKey[key]; !existsInLeft {
			diff = append(diff, secretDiffEntry{Key: key, Status: secretDiffStatusAdded, RightValue: rightSecret.Value})
		}
	}

	sort.Slice(diff, func(i, j int) bool {
		return diff[i].Key < diff[j].Key
	})

	return diff
}

func printSecretDiffTable(diff []secretDiffEntry, env1, env2 string, showValues bool) {
	if len(diff) == 0 {
		util.PrintlnStdout(fmt.Sprintf("No differences found between %q and %q.", env1, env2))
		return
	}

	headers := []string{"SECRET NAME", "STATUS", env1, env2}
	rows := [][]string{}
	for _, entry := range diff {
		leftValue := entry.LeftValue
		rightValue := entry.RightValue
		if !showValues {
			leftValue, rightValue = maskDiffColumns(entry.Status, leftValue, rightValue)
		}
		rows = append(rows, []string{entry.Key, entry.Status, leftValue, rightValue})
	}

	visualize.GenericTable(headers, rows)
}

// resolveDiffPath2 defaults --path2 to --path when --path2 is omitted.
func resolveDiffPath2(path1, path2 string) string {
	if path2 == "" {
		return path1
	}
	return path2
}

// validateDiffTargets rejects comparisons where both environment and path are
// identical (there would be nothing meaningful to compare).
func validateDiffTargets(env1, env2, path1, path2 string) error {
	if env1 == env2 && path1 == path2 {
		return fmt.Errorf("--env/--env2 and --path/--path2 must not both be identical; use different environments or different paths")
	}
	return nil
}

// maskDiffColumns returns masked left/right display values for a table row.
//
// Semantics when masking:
//   - removed: key exists only on the left → left masked, right empty
//   - added:   key exists only on the right → left empty, right masked
//   - changed: both sides exist → both masked
func maskDiffColumns(status, leftValue, rightValue string) (string, string) {
	// Left is empty when the key was added on the right (absent on the left).
	// Right is empty when the key was removed from the left (absent on the right).
	return maskDiffValue(status, secretDiffStatusAdded, leftValue),
		maskDiffValue(status, secretDiffStatusRemoved, rightValue)
}

// maskDiffValue masks a value unless it's meant to be empty (i.e. the key
// doesn't exist on that side of the diff).
func maskDiffValue(status, emptyWhenStatus, value string) string {
	if status == emptyWhenStatus {
		return ""
	}
	return maskSecretValue(value)
}

func init() {
	secretsDiffCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	secretsDiffCmd.Flags().String("projectId", "", "manually set the projectId when using machine identity based auth")
	secretsDiffCmd.Flags().String("env2", "", "the second environment to compare against (required)")
	secretsDiffCmd.Flags().String("path", "/", "path to fetch secrets from for --env")
	secretsDiffCmd.Flags().String("path2", "", "path to fetch secrets from for --env2 (defaults to --path)")
	secretsDiffCmd.Flags().Bool("include-imports", true, "Include imported linked secrets")
	secretsDiffCmd.Flags().Bool("recursive", false, "Fetch secrets from all sub-folders")
	secretsDiffCmd.Flags().Bool("expand", true, "Parse shell parameter expansions in your secrets, and process your referenced secrets")
	secretsDiffCmd.Flags().Bool("show-values", false, "reveal secret values in the diff output instead of masking them")
	util.AddOutputFlagsToCmd(secretsDiffCmd, "The output to format the diff in.")

	secretsCmd.AddCommand(secretsDiffCmd)
}
