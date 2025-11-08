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

var folderCmd = &cobra.Command{
	Use:                   "folders",
	Short:                 "Create, delete, and list folders",
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get folders in a directory",
	Run: func(cmd *cobra.Command, args []string) {
		token, projectConfig := util.GetTokenAndProjectConfigFromCommand(cmd)

		foldersPath := util.GetStringArgument(cmd, "path", "Unable to parse flag --path")

		outputFormat := util.GetStringArgument(cmd, "output", "Unable to parse flag --output")

		request := models.GetAllFoldersParameters{
			Environment: projectConfig.Environment,
			WorkspaceId: projectConfig.WorkspaceId,
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

			fmt.Print(output)
		} else {
			visualize.PrintAllFoldersDetails(folders, foldersPath)
		}
		Telemetry.CaptureEvent("cli-command:folders get", posthog.NewProperties().Set("folderCount", len(folders)).Set("version", util.CLI_VERSION))
	},
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a folder",
	Run: func(cmd *cobra.Command, args []string) {
		token, projectConfig := util.GetTokenAndProjectConfigFromCommand(cmd)

		folderPath := util.GetStringArgument(cmd, "path", "Unable to parse flag --path")

		folderName := util.GetStringArgument(cmd, "name", "Unable to parse flag --name")

		outputFormat := util.GetStringArgument(cmd, "output", "Unable to parse flag --output")

		if folderName == "" {
			util.HandleError(errors.New("invalid folder name, folder name cannot be empty"))
		}

		params := models.CreateFolderParameters{
			FolderName:  folderName,
			Environment: projectConfig.Environment,
			FolderPath:  folderPath,
			WorkspaceId: projectConfig.WorkspaceId,
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
			fmt.Print(output)
		} else {
			util.PrintSuccessMessage(fmt.Sprintf("folder named `%s` created in path %s", folderName, folderPath))
		}

		Telemetry.CaptureEvent("cli-command:folders create", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a folder",
	Run: func(cmd *cobra.Command, args []string) {
		token, projectConfig := util.GetTokenAndProjectConfigFromCommand(cmd)

		folderPath := util.GetStringArgument(cmd, "path", "Unable to parse flag --path")

		folderName := util.GetStringArgument(cmd, "name", "Unable to parse flag --name")

		outputFormat := util.GetStringArgument(cmd, "output", "Unable to parse flag --output")

		if folderName == "" {
			util.HandleError(errors.New("invalid folder name, folder name cannot be empty"))
		}

		params := models.DeleteFolderParameters{
			FolderName:  folderName,
			WorkspaceId: projectConfig.WorkspaceId,
			Environment: projectConfig.Environment,
			FolderPath:  folderPath,
		}

		if token != nil && (token.Type == util.SERVICE_TOKEN_IDENTIFIER || token.Type == util.UNIVERSAL_AUTH_TOKEN_IDENTIFIER) {
			params.InfisicalToken = token.Token
		}

		_, err := util.DeleteFolder(params)
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
			fmt.Print(output)
		} else {

			util.PrintSuccessMessage(fmt.Sprintf("folder named `%s` deleted in path %s", folderName, folderPath))
		}

		Telemetry.CaptureEvent("cli-command:folders delete", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}
