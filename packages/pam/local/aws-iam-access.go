package pam

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"gopkg.in/ini.v1"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
)

func startAWSAccess(_ *resty.Client, response *api.PAMAccessResponse, path, _ string, _ int) {
	expiresAtStr := response.Metadata["expiresAt"]
	accessKeyId := response.Metadata["accessKeyId"]
	secretAccessKey := response.Metadata["secretAccessKey"]
	sessionToken := response.Metadata["sessionToken"]

	if accessKeyId == "" || secretAccessKey == "" || sessionToken == "" || expiresAtStr == "" {
		util.PrintErrorMessageAndExit("Backend did not return AWS IAM credentials in session metadata")
		return
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to parse credential expiry time: %v", err))
		return
	}

	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		util.PrintErrorMessageAndExit("AWS credentials returned by the backend are already expired")
		return
	}

	folder, account := parsePath(path)
	profileName := fmt.Sprintf("infisical-pam/%s/%s", folder, account)

	credFilePath := awsCredentialsFilePath()
	createdFile := false

	dir := filepath.Dir(credFilePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to create directory %s: %v", dir, err))
		return
	}

	if _, statErr := os.Stat(credFilePath); os.IsNotExist(statErr) {
		createdFile = true
	}

	cfg, err := ini.LooseLoad(credFilePath)
	if err != nil {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to load AWS credentials file: %v", err))
		return
	}

	section := cfg.Section(profileName)
	section.Key("aws_access_key_id").SetValue(accessKeyId)
	section.Key("aws_secret_access_key").SetValue(secretAccessKey)
	section.Key("aws_session_token").SetValue(sessionToken)

	if err := cfg.SaveTo(credFilePath); err != nil {
		util.PrintErrorMessageAndExit(fmt.Sprintf("Failed to write AWS credentials file: %v", err))
		return
	}

	_ = os.Chmod(credFilePath, 0o600)

	log.Info().Str("profile", profileName).Str("file", credFilePath).Msg("AWS credentials written")

	printAWSSessionInfo(folder, account, remaining, profileName, expiresAt)

	cleanup := func() {
		removeAWSProfile(credFilePath, profileName, createdFile)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Info().Msgf("Received signal %v, cleaning up...", sig)
		cleanup()
	case <-time.After(remaining):
		fmt.Printf("\n  AWS session expired. Cleaning up credentials...\n\n")
		cleanup()
	}
}

func removeAWSProfile(credFilePath, profileName string, createdFile bool) {
	cfg, err := ini.LooseLoad(credFilePath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load AWS credentials file for cleanup")
		return
	}

	cfg.DeleteSection(profileName)

	// If we created the file and it's now empty (only DEFAULT section with no keys), remove it
	if createdFile && len(cfg.Sections()) <= 1 && len(cfg.Section("DEFAULT").Keys()) == 0 {
		if removeErr := os.Remove(credFilePath); removeErr != nil {
			log.Error().Err(removeErr).Msg("Failed to remove AWS credentials file")
		} else {
			log.Info().Str("file", credFilePath).Msg("Removed AWS credentials file (created by this session)")
		}
		return
	}

	if err := cfg.SaveTo(credFilePath); err != nil {
		log.Error().Err(err).Msg("Failed to save AWS credentials file after cleanup")
		return
	}

	log.Info().Str("profile", profileName).Msg("Removed AWS credentials profile")
}

func awsCredentialsFilePath() string {
	if envPath := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); envPath != "" {
		return envPath
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".aws", "credentials")
	}
	return filepath.Join(home, ".aws", "credentials")
}

func printAWSSessionInfo(folder, account string, duration time.Duration, profileName string, expiresAt time.Time) {
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("              AWS IAM Session Started!                                \n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
	if folder != "" {
		fmt.Printf("  Folder:    %s\n", folder)
	}
	fmt.Printf("  Account:   %s\n", account)
	fmt.Printf("  Duration:  %s\n", duration.Round(time.Second).String())
	fmt.Printf("  Expires:   %s\n", expiresAt.Local().Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                        Connection Details                            \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	fmt.Printf("  AWS credentials written to: %s\n", awsCredentialsFilePath())
	fmt.Printf("  Profile name:               %s\n", profileName)
	fmt.Printf("\n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("                           How to Connect                             \n")
	fmt.Printf("----------------------------------------------------------------------\n")
	fmt.Printf("\n")
	fmt.Printf("  Use the AWS CLI with the profile:\n")
	util.PrintfStderr("    $ aws s3 ls --profile \"%s\"\n", profileName)
	fmt.Printf("\n")
	fmt.Printf("  Or set the AWS_PROFILE environment variable:\n")
	util.PrintfStderr("    $ export AWS_PROFILE=\"%s\"\n", profileName)
	util.PrintfStderr("    $ aws sts get-caller-identity\n")
	fmt.Printf("\n")
	fmt.Printf("  Press Ctrl+C to stop and remove the credentials profile.\n")
	fmt.Printf("\n")
	fmt.Printf("**********************************************************************\n")
	fmt.Printf("\n")
}
