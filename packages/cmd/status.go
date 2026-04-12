/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

type statusOutput struct {
	Authenticated bool   `json:"authenticated"`
	SessionValid  bool   `json:"sessionValid"`
	Domain        string `json:"domain"`
	Profile       string `json:"profile"`
	AuthMethod    string `json:"authMethod"`
	User          string `json:"user,omitempty"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
	TokenSource   string `json:"tokenSource,omitempty"`
}

var statusCmd = &cobra.Command{
	Use:                   "status",
	Short:                 "Display the current authentication status and session information",
	DisableFlagsInUseLine: true,
	Example:               "infisical status\ninfisical status --json",
	Args:                  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")

		status := getStatus(cmd)

		if jsonOutput {
			printStatusJSON(status)
		} else {
			printStatusHuman(status)
		}

		Telemetry.CaptureEvent("cli-command:status", posthog.NewProperties().Set("authenticated", status.Authenticated).Set("version", util.CLI_VERSION))
	},
}

func getStatus(cmd *cobra.Command) statusOutput {
	status := statusOutput{
		Domain: config.INFISICAL_URL,
	}

	// Check for machine identity token first (from flags or env vars)
	token, err := util.GetInfisicalToken(cmd)
	if err == nil && token != nil {
		status.Authenticated = true
		status.SessionValid = true
		status.AuthMethod = token.Type
		status.TokenSource = token.Source

		// Try to extract expiry from machine token if it's a JWT
		if expiry, ok := extractJWTExpiry(token.Token); ok {
			// Use the same 30-second safety buffer as user session checks
			if expiry.Before(time.Now().Add(30 * time.Second)) {
				status.SessionValid = false
			}
			status.ExpiresAt = expiry.UTC().Format(time.RFC3339)
		}

		return status
	}

	// Check for user login session
	loggedInDetails, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil || !loggedInDetails.IsUserLoggedIn {
		status.Authenticated = false
		status.SessionValid = false
		status.AuthMethod = "none"
		return status
	}

	status.Authenticated = true
	status.SessionValid = !loggedInDetails.LoginExpired
	status.AuthMethod = "user"
	status.User = loggedInDetails.UserCredentials.Email
	status.Profile = loggedInDetails.UserCredentials.Email

	// Extract token expiry
	if expiry, ok := extractJWTExpiry(loggedInDetails.UserCredentials.JTWToken); ok {
		status.ExpiresAt = expiry.UTC().Format(time.RFC3339)
	}

	// Read domain from config file and ensure it's the API URL
	configFile, err := util.GetConfigFile()
	if err == nil {
		if configFile.LoggedInUserDomain != "" {
			status.Domain = util.AppendAPIEndpoint(configFile.LoggedInUserDomain)
		}
	}

	return status
}

func extractJWTExpiry(token string) (time.Time, bool) {
	parser := jwt.NewParser()
	claims := &jwt.RegisteredClaims{}
	_, _, err := parser.ParseUnverified(token, claims)
	if err != nil || claims.ExpiresAt == nil {
		return time.Time{}, false
	}
	return claims.ExpiresAt.Time, true
}

func printStatusJSON(status statusOutput) {
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		util.HandleError(err, "Unable to format status as JSON")
	}
	util.PrintlnStdout(string(data))
}

func printStatusHuman(status statusOutput) {
	bold := color.New(color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	yesNo := func(v bool) string {
		if v {
			return green("yes")
		}
		return red("no")
	}

	util.PrintfStdout("%-20s %s\n", bold("Authenticated:"), yesNo(status.Authenticated))

	if !status.Authenticated {
		util.PrintfStdout("\nNot logged in. Run %s to authenticate.\n", bold("infisical login"))
		return
	}

	util.PrintfStdout("%-20s %s\n", bold("Session valid:"), yesNo(status.SessionValid))
	util.PrintfStdout("%-20s %s\n", bold("Domain:"), status.Domain)
	util.PrintfStdout("%-20s %s\n", bold("Auth method:"), status.AuthMethod)

	if status.User != "" {
		util.PrintfStdout("%-20s %s\n", bold("User:"), status.User)
	}

	if status.TokenSource != "" {
		util.PrintfStdout("%-20s %s\n", bold("Token source:"), status.TokenSource)
	}

	if status.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, status.ExpiresAt)
		if err == nil {
			remaining := time.Until(expiresAt)
			var expiryDisplay string
			if remaining <= 0 {
				expiryDisplay = red(fmt.Sprintf("%s (expired)", status.ExpiresAt))
			} else if remaining < 5*time.Minute {
				expiryDisplay = yellow(fmt.Sprintf("%s (expires in %s)", status.ExpiresAt, remaining.Round(time.Second)))
			} else {
				expiryDisplay = fmt.Sprintf("%s (expires in %s)", status.ExpiresAt, remaining.Round(time.Second))
			}
			util.PrintfStdout("%-20s %s\n", bold("Token expires at:"), expiryDisplay)
		} else {
			util.PrintfStdout("%-20s %s\n", bold("Token expires at:"), status.ExpiresAt)
		}
	}

	if !status.SessionValid {
		if status.AuthMethod == "user" {
			util.PrintfStdout("\nSession expired. Run %s to re-authenticate.\n", bold("infisical login"))
		} else {
			util.PrintfStdout("\nToken expired or about to expire. Rotate or re-issue your %s token.\n", bold(status.AuthMethod))
		}
	}
}

func init() {
	statusCmd.Flags().Bool("json", false, "Output status in JSON format")
	statusCmd.Flags().String("token", "", "Check status using machine identity access token")
	RootCmd.AddCommand(statusCmd)
}
