package cmd

import (
	"errors"
	"fmt"

	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/Infisical/infisical-merge/packages/visualize"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

func buildFolderCmd() *cobra.Command {
	folderCmd := &cobra.Command{
		Use:                   "folders",
		Short:                 "Create, delete, and list folders",
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	folderCmd.PersistentFlags().String("env", "dev", "Used to select the environment name on which actions should be taken on")

	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Get folders in a directory",
		Run:   runFoldersGet,
	}
	getCmd.Flags().StringP("path", "p", "/", "The path from where folders should be fetched from")
	getCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	getCmd.Flags().String("projectId", "", "manually set the projectId to fetch folders from when using machine identity based auth")
	util.AddOutputFlagsToCmd(getCmd, "The output to format the folders in.")
	folderCmd.AddCommand(getCmd)

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a folder",
		Run:   runFoldersCreate,
	}
	createCmd.Flags().StringP("path", "p", "/", "Path to where the folder should be created")
	createCmd.Flags().StringP("name", "n", "", "Name of the folder to be created in selected `--path`")
	createCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	createCmd.Flags().String("projectId", "", "manually set the project ID for creating folders in when using machine identity based auth")
	util.AddOutputFlagsToCmd(createCmd, "The output to format the folders in.")
	folderCmd.AddCommand(createCmd)

	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a folder",
		Run:   runFoldersDelete,
	}
	deleteCmd.Flags().StringP("path", "p", "/", "Path to the folder to be deleted")
	deleteCmd.Flags().String("token", "", "Fetch secrets using service token or machine identity access token")
	deleteCmd.Flags().String("projectId", "", "manually set the projectId to delete folders when using machine identity based auth")
	deleteCmd.Flags().StringP("name", "n", "", "Name of the folder to be deleted within selected `--path`")
	util.AddOutputFlagsToCmd(deleteCmd, "The output to format the folders in.")
	folderCmd.AddCommand(deleteCmd)

	return folderCmd
}

func runFoldersGet(cmd *cobra.Command, args []string) {
	environmentName := util.ResolveEnvironmentName(cmd)

	projectId, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "projectId", []string{util.INFISICAL_PROJECT_ID_NAME}, "")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}
	foldersPath, err := cmd.Flags().GetString("path")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}
	outputFormat, err := cmd.Flags().GetString("output")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	request := models.GetAllFoldersParameters{
		Environment: environmentName,
		WorkspaceId: projectId,
		FoldersPath: foldersPath,
	}

	if token != nil && token.Type == util.SERVICE_TOKEN_IDENTIFIER {
		request.InfisicalToken = token.Token
	} else if token != nil && token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER {
		request.UniversalAuthAccessToken = token.Token
	}

	folders, err := util.GetAllFolders(request)
	if err != nil {
		util.HandleError(err, "Unable to get folders")
	}

	if outputFormat != "" {

		var outputStructure []map[string]any
		for _, folder := range folders {
			outputStructure = append(outputStructure, map[string]any{
				"folderName": folder.Name,
				"folderPath": foldersPath,
				"folderId":   folder.ID,
			})
		}

		output, err := util.FormatOutput(outputFormat, outputStructure, nil)

		if err != nil {
			util.HandleError(err, "Unable to format output")
		}

		util.PrintStdout(output)
	} else {
		visualize.PrintAllFoldersDetails(folders, foldersPath)
	}
	Telemetry.CaptureEvent("cli-command:folders get", posthog.NewProperties().Set("folderCount", len(folders)).Set("version", util.CLI_VERSION))
}

func runFoldersCreate(cmd *cobra.Command, args []string) {
	environmentName := util.ResolveEnvironmentName(cmd)

	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	projectId, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "projectId", []string{util.INFISICAL_PROJECT_ID_NAME}, "")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	folderPath, err := cmd.Flags().GetString("path")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	folderName, err := cmd.Flags().GetString("name")
	if err != nil {
		util.HandleError(err, "Unable to parse name flag")
	}

	outputFormat, err := cmd.Flags().GetString("output")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	if folderName == "" {
		util.HandleError(errors.New("invalid folder name, folder name cannot be empty"))
	}

	if err != nil {
		util.HandleError(err, "Unable to get workspace file")
	}

	if projectId == "" {
		workspaceFile, err := util.GetWorkSpaceFromFile()
		if err != nil {
			util.PrintErrorMessageAndExit("Please either run infisical init to connect to a project or pass in project id with --projectId flag")
		}

		projectId = workspaceFile.WorkspaceId
	}

	params := models.CreateFolderParameters{
		FolderName:  folderName,
		Environment: environmentName,
		FolderPath:  folderPath,
		WorkspaceId: projectId,
	}

	if token != nil && (token.Type == util.SERVICE_TOKEN_IDENTIFIER || token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER) {
		params.InfisicalToken = token.Token
	}

	folder, err := util.CreateFolder(params)
	if err != nil {
		util.HandleError(err, "Unable to create folder")
	}

	if outputFormat != "" {

		outputStructure := map[string]any{
			"folderName": folder.Name,
			"folderPath": folderPath,
			"folderId":   folder.ID,
		}

		output, err := util.FormatOutput(outputFormat, outputStructure, nil)
		if err != nil {
			util.HandleError(err, "Unable to format output")
		}
		util.PrintStdout(output)
	} else {
		util.PrintSuccessMessage(fmt.Sprintf("folder named `%s` created in path %s", folderName, folderPath))
	}

	Telemetry.CaptureEvent("cli-command:folders create", posthog.NewProperties().Set("version", util.CLI_VERSION))
}

func runFoldersDelete(cmd *cobra.Command, args []string) {
	environmentName := util.ResolveEnvironmentName(cmd)

	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	projectId, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "projectId", []string{util.INFISICAL_PROJECT_ID_NAME}, "")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	folderPath, err := cmd.Flags().GetString("path")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	folderName, err := cmd.Flags().GetString("name")
	if err != nil {
		util.HandleError(err, "Unable to parse name flag")
	}

	outputFormat, err := cmd.Flags().GetString("output")
	if err != nil {
		util.HandleError(err, "Unable to parse flag")
	}

	if folderName == "" {
		util.HandleError(errors.New("invalid folder name, folder name cannot be empty"))
	}

	if projectId == "" {
		workspaceFile, err := util.GetWorkSpaceFromFile()
		if err != nil {
			util.PrintErrorMessageAndExit("Please either run infisical init to connect to a project or pass in project id with --projectId flag")
		}

		projectId = workspaceFile.WorkspaceId
	}

	params := models.DeleteFolderParameters{
		FolderName:  folderName,
		WorkspaceId: projectId,
		Environment: environmentName,
		FolderPath:  folderPath,
	}

	if token != nil && (token.Type == util.SERVICE_TOKEN_IDENTIFIER || token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER) {
		params.InfisicalToken = token.Token
	}

	_, err = util.DeleteFolder(params)
	if err != nil {
		util.HandleError(err, "Unable to delete folder")
	}

	if outputFormat != "" {
		outputStructure := map[string]any{
			"folderName": folderName,
			"folderPath": folderPath,
		}

		output, err := util.FormatOutput(outputFormat, outputStructure, nil)
		if err != nil {
			util.HandleError(err, "Unable to format output")
		}
		util.PrintStdout(output)
	} else {

		util.PrintSuccessMessage(fmt.Sprintf("folder named `%s` deleted in path %s", folderName, folderPath))
	}

	Telemetry.CaptureEvent("cli-command:folders delete", posthog.NewProperties().Set("version", util.CLI_VERSION))
}
