/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/Infisical/infisical-merge/packages/visualize"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

var secretsCmd = &cobra.Command{
	Example:               `infisical secrets`,
	Short:                 "Used to create, read update and delete secrets",
	Use:                   "secrets",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		token, projectConfig := util.GetTokenAndProjectConfigFromCommand(cmd)

		shouldExpandSecrets := util.GetBooleanArgument(cmd, "expand", "Unable to parse argument --expand")

		includeImports := util.GetBooleanArgument(cmd, "include-imports", "Unable to parse argument --include-imports")

		recursive := util.GetBooleanArgument(cmd, "recursive", "Unable to parse argument --recursive")

		secretOverriding := util.GetBooleanArgument(cmd, "secret-overriding", "Unable to parse argument --secret-overriding")

		plainOutput := util.GetBooleanArgument(cmd, "plain", "Unable to parse argument --plain")

		outputFormat := util.GetStringArgument(cmd, "output", "Unable to parse argument --output")

		request := models.GetAllSecretsParameters{
			Environment:            projectConfig.Environment,
			WorkspaceId:            projectConfig.WorkspaceId,
			TagSlugs:               projectConfig.TagSlugs,
			SecretsPath:            projectConfig.SecretsPath,
			IncludeImport:          includeImports,
			Recursive:              recursive,
			ExpandSecretReferences: shouldExpandSecrets,
		}

		if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER {
			request.InfisicalToken = token.Token
		} else if token != nil && token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER {
			request.UniversalAuthAccessToken = token.Token
		}

		secrets, err := util.GetAllEnvironmentVariables(request)
		if err != nil {
			util.HandleError(err)
		}

		if secretOverriding {
			secrets = util.OverrideSecrets(secrets, util.SECRET_TYPE_PERSONAL)
		} else {
			secrets = util.OverrideSecrets(secrets, util.SECRET_TYPE_SHARED)
		}

		// Sort the secrets by key so we can create a consistent output
		secrets = util.SortSecretsByKeys(secrets)

		if outputFormat != "" {

			var outputStructure []map[string]any
			for _, secret := range secrets {
				outputStructure = append(outputStructure, map[string]any{
					"secretKey":   secret.Key,
					"secretValue": secret.Value,
				})
			}

			output, err := util.FormatOutput(outputFormat, outputStructure, &util.FormatOutputOptions{
				DotEnvArrayKeyAttribute:   "secretKey",
				DotEnvArrayValueAttribute: "secretValue",
			})
			if err != nil {
				util.HandleError(err, "Unable to format output")
			}
			fmt.Print(output)
		} else {
			if plainOutput {
				for _, secret := range secrets {
					fmt.Printf("%s=%s\n", secret.Key, secret.Value)
				}
			} else {
				visualize.PrintAllSecretDetails(secrets)
			}
		}

		Telemetry.CaptureEvent("cli-command:secrets", posthog.NewProperties().Set("secretCount", len(secrets)).Set("version", util.CLI_VERSION))
	},
}

var secretsGetCmd = &cobra.Command{
	Example:               `secrets get <secret name A> <secret name B>..."`,
	Short:                 "Used to retrieve secrets by name",
	Use:                   "get [secrets]",
	DisableFlagsInUseLine: true,
	Args:                  cobra.MinimumNArgs(1),
	Run:                   getSecretsByNames,
}

var secretsGenerateExampleEnvCmd = &cobra.Command{
	Example:               `secrets generate-example-env > .example-env`,
	Short:                 "Used to generate a example .env file",
	Use:                   "generate-example-env",
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run:                   generateExampleEnv,
}

var secretsSetCmd = &cobra.Command{
	Example:               `secrets set <secretName=secretValue> <secretName=secretValue> <secretName=@/path/to/file>..."`,
	Short:                 "Used set secrets",
	Use:                   "set [secrets]",
	DisableFlagsInUseLine: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("file") {
			if len(args) > 0 {
				return fmt.Errorf("secrets cannot be provided as command-line arguments when the --file option is used. Please choose either file-based or argument-based secret input")
			}
			return nil
		}
		return cobra.MinimumNArgs(1)(cmd, args)
	},
	Run: func(cmd *cobra.Command, args []string) {
		token, projectConfig := util.GetTokenAndProjectConfigFromCommand(cmd)
		secretType := util.GetStringArgument(cmd, "type", "Unable to parse argument --type")
		if secretType != util.SECRET_TYPE_SHARED && secretType != util.SECRET_TYPE_PERSONAL {
			util.PrintErrorMessageAndExit("Invalid secret type. Valid values are 'shared' and 'personal'")
		}

		outputFormat := util.GetStringArgument(cmd, "output", "Unable to parse argument --output")

		var processedArgs []string
		for _, arg := range args {
			splitKeyValue := strings.SplitN(arg, "=", 2)
			if len(splitKeyValue) != 2 {
				util.HandleError(fmt.Errorf("invalid argument format: %s. Expected format: key=value or key=@filepath", arg), "")
			}

			key := splitKeyValue[0]
			value := splitKeyValue[1]

			if strings.HasPrefix(value, "\\@") {
				value = "@" + value[2:]
			} else if strings.HasPrefix(value, "@") {
				filePath := strings.TrimPrefix(value, "@")
				content, err := os.ReadFile(filePath)
				if err != nil {
					util.HandleError(err, fmt.Sprintf("Unable to read file %s", filePath))
				}
				value = string(content)
			}

			processedArgs = append(processedArgs, fmt.Sprintf("%s=%s", key, value))
		}

		file := util.GetStringArgument(cmd, "file", "Unable to parse argument --file")

		var secretOperations []models.SecretSetOperation
		if token != nil && (token.Type == util.SERVICE_TOKEN_IDENTIFIER || token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER) {
			var err error
			secretOperations, err = util.SetRawSecrets(args, secretType, projectConfig.Environment, projectConfig.SecretsPath, projectConfig.WorkspaceId, token, file)

			if err != nil {
				util.HandleError(err, "Unable to set secrets")
			}
		} else {
			loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
			if err != nil {
				util.HandleError(err, "unable to authenticate [err=%v]")
			}

			if loggedInUserDetails.LoginExpired {
				loggedInUserDetails = util.EstablishUserLoginSession()
			}

			secretOperations, err = util.SetRawSecrets(processedArgs, secretType, projectConfig.Environment, projectConfig.SecretsPath, projectConfig.WorkspaceId, &models.TokenDetails{
				Type:  "",
				Token: loggedInUserDetails.UserCredentials.JTWToken,
			}, file)

			if err != nil {
				util.HandleError(err, "Unable to set secrets")
			}
		}

		// Print secret operations
		headers := [...]string{"SECRET NAME", "SECRET VALUE", "STATUS"}
		var rows [][3]string
		for _, secretOperation := range secretOperations {
			rows = append(rows, [...]string{secretOperation.SecretKey, secretOperation.SecretValue, secretOperation.SecretOperation})
		}

		if outputFormat != "" {

			var outputStructure []map[string]any
			for _, secretOperation := range secretOperations {
				outputStructure = append(outputStructure, map[string]any{
					"secretKey":   secretOperation.SecretKey,
					"secretValue": secretOperation.SecretValue,
					"operation":   secretOperation.SecretOperation,
				})
			}

			output, err := util.FormatOutput(outputFormat, outputStructure, &util.FormatOutputOptions{
				DotEnvArrayKeyAttribute:   "secretKey",
				DotEnvArrayValueAttribute: "secretValue",
			})

			if err != nil {
				util.HandleError(err, "Unable to format output")
			}
			fmt.Print(output)
		} else {
			visualize.Table(headers, rows)
		}
		Telemetry.CaptureEvent("cli-command:secrets set", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

var secretsDeleteCmd = &cobra.Command{
	Example:               `secrets delete <secret name A> <secret name B>..."`,
	Short:                 "Used to delete secrets by name",
	Use:                   "delete [secrets]",
	DisableFlagsInUseLine: true,
	Args:                  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		token, projectConfig := util.GetTokenAndProjectConfigFromCommand(cmd)

		secretType := util.GetStringArgument(cmd, "type", "Unable to parse argument --type")

		outputFormat := util.GetStringArgument(cmd, "output", "Unable to parse argument --output")

		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			util.HandleError(err, "Unable to get resty client with custom headers")
		}

		httpClient.SetHeader("Accept", "application/json")

		if token != nil && (token.Type == util.SERVICE_TOKEN_IDENTIFIER || token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER) {
			httpClient.SetAuthToken(token.Token)
		} else {
			util.RequireLogin()

			loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
			if err != nil {
				util.HandleError(err, "Unable to authenticate")
			}

			if loggedInUserDetails.LoginExpired {
				loggedInUserDetails = util.EstablishUserLoginSession()
			}

			httpClient.SetAuthToken(loggedInUserDetails.UserCredentials.JTWToken)
		}

		for _, secretName := range args {
			request := api.DeleteSecretV3Request{
				WorkspaceId: projectConfig.WorkspaceId,
				Environment: projectConfig.Environment,
				SecretName:  secretName,
				Type:        secretType,
				SecretPath:  projectConfig.SecretsPath,
			}

			err = api.CallDeleteSecretsRawV3(httpClient, request)
			if err != nil {
				util.HandleError(err, "Unable to complete your delete request")
			}
		}

		if outputFormat != "" {
			var outputStructure []map[string]any
			for _, secretName := range args {
				outputStructure = append(outputStructure, map[string]any{
					"secretKey": secretName,
				})
			}
			output, err := util.FormatOutput(outputFormat, outputStructure, &util.FormatOutputOptions{
				DotEnvArrayKeyAttribute: "secretKey",
			})
			if err != nil {
				util.HandleError(err, "Unable to format output")
			}
			fmt.Print(output)
		} else {
			fmt.Printf("secret name(s) [%v] have been deleted from your project \n", strings.Join(args, ", "))
		}

		Telemetry.CaptureEvent("cli-command:secrets delete", posthog.NewProperties().Set("secretCount", len(args)).Set("version", util.CLI_VERSION))
	},
}

func getSecretsByNames(cmd *cobra.Command, args []string) {
	token, projectConfig := util.GetTokenAndProjectConfigFromCommand(cmd)

	shouldExpand := util.GetBooleanArgument(cmd, "expand", "Unable to parse argument --expand")

	recursive := util.GetBooleanArgument(cmd, "recursive", "Unable to parse argument --recursive")

	outputFormat := util.GetStringArgument(cmd, "output", "Unable to parse argument --output")

	// deprecated, in favor of --plain
	showOnlyValue := util.GetBooleanArgument(cmd, "raw-value", "Unable to parse argument --raw-value")

	plainOutput := util.GetBooleanArgument(cmd, "plain", "Unable to parse argument --plain")

	if showOnlyValue {
		plainOutput = true
	}

	includeImports := util.GetBooleanArgument(cmd, "include-imports", "Unable to parse argument --include-imports")

	secretOverriding := util.GetBooleanArgument(cmd, "secret-overriding", "Unable to parse argument --secret-overriding")

	request := models.GetAllSecretsParameters{
		Environment:            projectConfig.Environment,
		WorkspaceId:            projectConfig.WorkspaceId,
		TagSlugs:               projectConfig.TagSlugs,
		SecretsPath:            projectConfig.SecretsPath,
		IncludeImport:          includeImports,
		Recursive:              recursive,
		ExpandSecretReferences: shouldExpand,
	}

	if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER {
		request.InfisicalToken = token.Token
	} else if token != nil && token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER {
		request.UniversalAuthAccessToken = token.Token
	}

	secrets, err := util.GetAllEnvironmentVariables(request)
	if err != nil {
		util.HandleError(err, "To fetch all secrets")
	}

	if secretOverriding {
		secrets = util.OverrideSecrets(secrets, util.SECRET_TYPE_PERSONAL)
	} else {
		secrets = util.OverrideSecrets(secrets, util.SECRET_TYPE_SHARED)
	}

	var requestedSecrets []models.SingleEnvironmentVariable

	secretsMap := getSecretsByKeys(secrets)

	for _, secretKeyFromArg := range args {
		if value, ok := secretsMap[secretKeyFromArg]; ok {
			requestedSecrets = append(requestedSecrets, value)
		} else {
			if !plainOutput {
				requestedSecrets = append(requestedSecrets, models.SingleEnvironmentVariable{
					Key:   secretKeyFromArg,
					Type:  "*not found*",
					Value: "*not found*",
				})
			}
		}
	}

	if outputFormat != "" && !plainOutput {

		var outputStructure []map[string]any
		for _, secret := range requestedSecrets {
			outputStructure = append(outputStructure, map[string]any{
				"secretKey":   secret.Key,
				"secretValue": secret.Value,
			})
		}

		output, err := util.FormatOutput(outputFormat, outputStructure, &util.FormatOutputOptions{
			DotEnvArrayKeyAttribute:   "secretKey",
			DotEnvArrayValueAttribute: "secretValue",
		})
		if err != nil {
			util.HandleError(err, "Unable to format output")
		}

		fmt.Print(output)
	} else {

		// showOnlyValue deprecated in favor of --plain, below only for backward compatibility
		if plainOutput {
			for _, secret := range requestedSecrets {
				fmt.Println(secret.Value)
			}
		} else {
			visualize.PrintAllSecretDetails(requestedSecrets)
		}
	}

	Telemetry.CaptureEvent("cli-command:secrets get", posthog.NewProperties().Set("secretCount", len(secrets)).Set("version", util.CLI_VERSION))
}

func generateExampleEnv(cmd *cobra.Command, args []string) {
	token, projectConfig := util.GetTokenAndProjectConfigFromCommand(cmd)

	request := models.GetAllSecretsParameters{
		Environment:   projectConfig.Environment,
		WorkspaceId:   projectConfig.WorkspaceId,
		TagSlugs:      projectConfig.TagSlugs,
		SecretsPath:   projectConfig.SecretsPath,
		IncludeImport: true,
	}

	if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER {
		request.InfisicalToken = token.Token
	} else if token != nil && token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER {
		request.UniversalAuthAccessToken = token.Token
	}

	secrets, err := util.GetAllEnvironmentVariables(request)
	if err != nil {
		util.HandleError(err, "To fetch all secrets")
	}

	tagsHashToSecretKey := make(map[string]int)
	slugsToFilerBy := make(map[string]int)

	for _, slug := range strings.Split(projectConfig.TagSlugs, ",") {
		slugsToFilerBy[slug] = 1
	}

	type TagsAndSecrets struct {
		Secrets []models.SingleEnvironmentVariable
		Tags    []models.Tag
	}

	// sort secrets by associated tags (most number of tags to least tags)
	sort.Slice(secrets, func(i, j int) bool {
		return len(secrets[i].Tags) > len(secrets[j].Tags)
	})

	for i, secret := range secrets {
		var filteredTag []models.Tag

		for _, secretTag := range secret.Tags {
			_, exists := slugsToFilerBy[secretTag.Slug]
			if !exists {
				filteredTag = append(filteredTag, secretTag)
			}
		}

		secret.Tags = filteredTag
		secrets[i] = secret
	}

	for _, secret := range secrets {
		var listOfTagSlugs []string

		for _, tag := range secret.Tags {
			listOfTagSlugs = append(listOfTagSlugs, tag.Slug)
		}
		sort.Strings(listOfTagSlugs)

		tagsHash := util.GetHashFromStringList(listOfTagSlugs)

		tagsHashToSecretKey[tagsHash] += 1
	}

	finalTagHashToSecretKey := make(map[string]TagsAndSecrets)

	for _, secret := range secrets {
		var listOfTagSlugs []string
		for _, tag := range secret.Tags {
			listOfTagSlugs = append(listOfTagSlugs, tag.Slug)
		}

		// sort the slug so we get the same hash each time
		sort.Strings(listOfTagSlugs)

		tagsHash := util.GetHashFromStringList(listOfTagSlugs)
		occurrence, exists := tagsHashToSecretKey[tagsHash]
		if exists && occurrence > 0 {

			value, exists2 := finalTagHashToSecretKey[tagsHash]
			allSecretsForTags := append(value.Secrets, secret)

			// sort the the secrets by keys so that they can later be sorted by the first item in the secrets array
			sort.Slice(allSecretsForTags, func(i, j int) bool {
				return allSecretsForTags[i].Key < allSecretsForTags[j].Key
			})

			if exists2 {
				finalTagHashToSecretKey[tagsHash] = TagsAndSecrets{
					Tags:    secret.Tags,
					Secrets: allSecretsForTags,
				}
			} else {
				finalTagHashToSecretKey[tagsHash] = TagsAndSecrets{
					Tags:    secret.Tags,
					Secrets: []models.SingleEnvironmentVariable{secret},
				}
			}

			tagsHashToSecretKey[tagsHash] -= 1
		}
	}

	// sort the final result by secret key for consistent print order
	listOfsecretDetails := make([]TagsAndSecrets, 0, len(finalTagHashToSecretKey))
	for _, secretDetails := range finalTagHashToSecretKey {
		listOfsecretDetails = append(listOfsecretDetails, secretDetails)
	}

	// sort the order of the headings by the order of the secrets
	sort.Slice(listOfsecretDetails, func(i, j int) bool {
		return len(listOfsecretDetails[i].Tags) < len(listOfsecretDetails[j].Tags)
	})

	var tableOfContents []string
	var fullyGeneratedDocuments []string
	for _, secretDetails := range listOfsecretDetails {
		var listOfKeyValue []string

		for _, secret := range secretDetails.Secrets {
			re := regexp.MustCompile(`(?s)(.*)DEFAULT:(.*)`)
			match := re.FindStringSubmatch(secret.Comment)
			defaultValue := ""
			comment := secret.Comment

			// Case: Only has default value
			if len(match) == 2 {
				defaultValue = strings.TrimSpace(match[1])
			}

			// Case: has a comment and a default value
			if len(match) == 3 {
				comment = match[1]
				defaultValue = match[2]
			}

			row := ""
			if comment != "" {
				comment = addHash(comment)
				row = fmt.Sprintf("%s \n%s=%s", strings.TrimSpace(comment), strings.TrimSpace(secret.Key), strings.TrimSpace(defaultValue))
			} else {
				row = fmt.Sprintf("%s=%s", strings.TrimSpace(secret.Key), strings.TrimSpace(defaultValue))
			}

			// each secret row to be added to the file
			listOfKeyValue = append(listOfKeyValue, row)
		}

		var listOfTagNames []string
		for _, tag := range secretDetails.Tags {
			listOfTagNames = append(listOfTagNames, tag.Name)
		}

		heading := CenterString(strings.Join(listOfTagNames, " & "), 80)

		if len(listOfTagNames) == 0 {
			fullyGeneratedDocuments = append(fullyGeneratedDocuments, fmt.Sprintf("\n%s \n", strings.Join(listOfKeyValue, "\n")))
		} else {
			fullyGeneratedDocuments = append(fullyGeneratedDocuments, fmt.Sprintf("\n\n\n%s \n%s \n", heading, strings.Join(listOfKeyValue, "\n")))
			tableOfContents = append(tableOfContents, strings.ToUpper(strings.Join(listOfTagNames, " & ")))
		}
	}

	var dashedList []string
	for _, item := range tableOfContents {
		dashedList = append(dashedList, fmt.Sprintf("# - %s \n", item))
	}
	if len(dashedList) > 0 {
		fmt.Println(CenterString("TABLE OF CONTENTS", 80))
		fmt.Println(strings.Join(dashedList, ""))
	}
	fmt.Println(strings.Join(fullyGeneratedDocuments, ""))

	Telemetry.CaptureEvent("cli-command:generate-example-env", posthog.NewProperties().Set("secretCount", len(secrets)).Set("version", util.CLI_VERSION))
}

func CenterString(s string, numStars int) string {
	stars := strings.Repeat("*", numStars)
	padding := (numStars - len(s)) / 2
	cenetredTextWithStar := stars[:padding] + " " + s + " " + stars[padding:]

	hashes := strings.Repeat("#", len(cenetredTextWithStar)+2)
	return fmt.Sprintf("%s \n# %s \n%s", hashes, cenetredTextWithStar, hashes)
}

func addHash(input string) string {
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		lines[i] = "# " + line
	}
	return strings.Join(lines, "\n")
}

func getSecretsByKeys(secrets []models.SingleEnvironmentVariable) map[string]models.SingleEnvironmentVariable {
	secretMapByName := make(map[string]models.SingleEnvironmentVariable, len(secrets))

	for _, secret := range secrets {
		secretMapByName[secret.Key] = secret
	}

	return secretMapByName
}

func init() {
	// not doing this one
	secretsGenerateExampleEnvCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	secretsGenerateExampleEnvCmd.Flags().String("projectId", "", "manually set the projectId when using machine identity based auth")
	secretsGenerateExampleEnvCmd.Flags().String("path", "/", "Fetch secrets from within a folder path")
	secretsCmd.AddCommand(secretsGenerateExampleEnvCmd)

	secretsGetCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	secretsGetCmd.Flags().String("projectId", "", "manually set the project ID to fetch secrets from when using machine identity based auth")
	secretsGetCmd.Flags().String("path", "/", "get secrets within a folder path")
	secretsGetCmd.Flags().Bool("plain", false, "print values without formatting, one per line")
	secretsGetCmd.Flags().Bool("raw-value", false, "deprecated. Returns only the value of secret, only works with one secret. Use --plain instead")
	_ = secretsGetCmd.Flags().MarkHidden("raw-value") // hide-from --help output
	secretsGetCmd.Flags().Bool("include-imports", true, "Imported linked secrets ")
	secretsGetCmd.Flags().Bool("expand", true, "Parse shell parameter expansions in your secrets, and process your referenced secrets")
	secretsGetCmd.Flags().Bool("recursive", false, "Fetch secrets from all sub-folders")
	secretsGetCmd.Flags().Bool("secret-overriding", true, "Prioritizes personal secrets, if any, with the same name over shared secrets")
	util.AddOutputFlagsToCmd(secretsGetCmd, "The output to format the secrets in.")
	secretsCmd.AddCommand(secretsGetCmd)

	secretsCmd.AddCommand(secretsSetCmd)
	secretsSetCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	secretsSetCmd.Flags().String("projectId", "", "manually set the project ID to for setting secrets when using machine identity based auth")
	secretsSetCmd.Flags().String("path", "/", "set secrets within a folder path")
	secretsSetCmd.Flags().String("type", util.SECRET_TYPE_SHARED, "the type of secret to create: personal or shared")
	secretsSetCmd.Flags().String("file", "", "Load secrets from the specified file. File format: .env or YAML (comments: # or //). This option is mutually exclusive with command-line secrets arguments.")
	util.AddOutputFlagsToCmd(secretsSetCmd, "The output to format the secrets in.")

	secretsDeleteCmd.Flags().String("type", "personal", "the type of secret to delete: personal or shared  (default: personal)")
	secretsDeleteCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	secretsDeleteCmd.Flags().String("projectId", "", "manually set the projectId to delete secrets from when using machine identity based auth")
	secretsDeleteCmd.Flags().String("path", "/", "get secrets within a folder path")
	util.AddOutputFlagsToCmd(secretsDeleteCmd, "The output to format the secrets in.")
	secretsCmd.AddCommand(secretsDeleteCmd)

	// *** Folders sub command ***
	folderCmd.PersistentFlags().String("env", "dev", "Used to select the environment name on which actions should be taken on")

	// Add getCmd, createCmd and deleteCmd flags here
	getCmd.Flags().StringP("path", "p", "/", "The path from where folders should be fetched from")
	getCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	getCmd.Flags().String("projectId", "", "manually set the projectId to fetch folders from when using machine identity based auth")
	util.AddOutputFlagsToCmd(getCmd, "The output to format the folders in.")
	folderCmd.AddCommand(getCmd)

	// Add createCmd flags here
	createCmd.Flags().StringP("path", "p", "/", "Path to where the folder should be created")
	createCmd.Flags().StringP("name", "n", "", "Name of the folder to be created in selected `--path`")
	createCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	createCmd.Flags().String("projectId", "", "manually set the project ID for creating folders in when using machine identity based auth")
	util.AddOutputFlagsToCmd(createCmd, "The output to format the folders in.")
	folderCmd.AddCommand(createCmd)

	// Add deleteCmd flags here
	deleteCmd.Flags().StringP("path", "p", "/", "Path to the folder to be deleted")
	deleteCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	deleteCmd.Flags().String("projectId", "", "manually set the projectId to delete folders when using machine identity based auth")
	deleteCmd.Flags().StringP("name", "n", "", "Name of the folder to be deleted within selected `--path`")
	util.AddOutputFlagsToCmd(deleteCmd, "The output to format the folders in.")
	folderCmd.AddCommand(deleteCmd)

	secretsCmd.AddCommand(folderCmd)

	// ** End of folders sub command

	secretsCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	secretsCmd.Flags().String("projectId", "", "manually set the projectId to fetch secrets when using machine identity based auth")
	secretsCmd.PersistentFlags().String("env", "dev", "Used to select the environment name on which actions should be taken on")
	secretsCmd.Flags().Bool("expand", true, "Parse shell parameter expansions in your secrets, and process your referenced secrets")
	secretsCmd.Flags().Bool("include-imports", true, "Imported linked secrets ")
	secretsCmd.Flags().Bool("recursive", false, "Fetch secrets from all sub-folders")
	secretsCmd.PersistentFlags().StringP("tags", "t", "", "filter secrets by tag slugs")
	secretsCmd.Flags().String("path", "/", "get secrets within a folder path")
	secretsCmd.Flags().Bool("plain", false, "print values without formatting, one per line (deprecated, use --output instead)")
	secretsCmd.Flags().Bool("secret-overriding", true, "Prioritizes personal secrets, if any, with the same name over shared secrets")
	util.AddOutputFlagsToCmd(secretsCmd, "The output to format the secrets in.")
	rootCmd.AddCommand(secretsCmd)
}
