package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/manifoldco/promptui"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

var userCmd = &cobra.Command{
	Use:                   "user",
	Short:                 "Used to manage local user credentials",
	DisableFlagsInUseLine: true,
	Example:               "infisical user",
	Args:                  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var switchCmd = &cobra.Command{
	Use:                   "switch",
	Short:                 "Switch the default login profile (same as [infisical profile use], with a picker)",
	DisableFlagsInUseLine: true,
	Example:               "infisical user switch",
	Args:                  cobra.ExactArgs(0),
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: func(cmd *cobra.Command, args []string) {
		configFile, err := util.GetMigratedConfigFile()
		if err != nil {
			util.HandleError(err, "[infisical user switch]: Unable to get config file")
		}

		if len(configFile.Profiles) == 0 {
			util.PrintErrorMessageAndExit("No login profiles found. Run [infisical login] to create one.")
		}

		labels := make([]string, len(configFile.Profiles))
		for idx, profile := range configFile.Profiles {
			label := fmt.Sprintf("%s (%s", profile.Name, profile.Email)
			if profile.OrganizationName != "" {
				label = fmt.Sprintf("%s, org %s", label, profile.OrganizationName)
			}
			labels[idx] = fmt.Sprintf("%s, %s)", label, util.DisplayDomain(profile.Domain))
		}

		prompt := promptui.Select{
			Label: "Which of your Infisical profiles would you like to use",
			Items: labels,
			Size:  7,
		}
		idx, _, err := prompt.Run()
		if err != nil {
			util.HandleError(err, "[infisical user switch]: Prompt error")
		}

		if err := util.SetActiveProfile(&configFile, configFile.Profiles[idx].Name); err != nil {
			util.HandleError(err, "[infisical user switch]: Unable to switch profile")
		}

		err = util.WriteConfigFile(&configFile)
		if err != nil {
			util.HandleError(err, "")
		}

		util.PrintlnStderr(fmt.Sprintf("Default profile is now '%s'", configFile.Profiles[idx].Name))

		Telemetry.CaptureEvent("cli-command:user switch", posthog.NewProperties().Set("numberOfLoggedInProfiles", len(configFile.Profiles)).Set("version", util.CLI_VERSION))
	},
}

var userGetCmd = &cobra.Command{
	Use:                   "get",
	Short:                 "Used to get properties of an Infisical profile",
	DisableFlagsInUseLine: true,
	Example:               "infisical user get",
	Args:                  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var userGetTokenCmd = &cobra.Command{
	Use:                   "token",
	Short:                 "Used to get the access token of an Infisical user",
	DisableFlagsInUseLine: true,
	Example:               "infisical user get token",
	Args:                  cobra.ExactArgs(0),
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: func(cmd *cobra.Command, args []string) {
		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
		if loggedInUserDetails.LoginExpired {
			loggedInUserDetails = util.EstablishUserLoginSession()
		}

		plain, err := cmd.Flags().GetBool("plain")
		if err != nil {
			util.HandleError(err, "[infisical user get token]: Unable to get plain flag")
		}

		if err != nil {
			util.HandleError(err, "[infisical user get token]: Unable to get logged in user token")
		}

		tokenParts := strings.Split(loggedInUserDetails.UserCredentials.JTWToken, ".")
		if len(tokenParts) != 3 {
			util.HandleError(errors.New("invalid token format"), "[infisical user get token]: Invalid token format")
		}

		payload, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
		if err != nil {
			util.HandleError(err, "[infisical user get token]: Unable to decode token payload")
		}

		var tokenPayload struct {
			TokenVersionId string `json:"tokenVersionId"`
			Exp            int64  `json:"exp"`
		}
		if err := json.Unmarshal(payload, &tokenPayload); err != nil {
			util.HandleError(err, "[infisical user get token]: Unable to parse token payload")
		}

		if plain {
			util.PrintlnStdout(loggedInUserDetails.UserCredentials.JTWToken)
		} else {
			util.PrintlnStdout("Session ID:", tokenPayload.TokenVersionId)
			util.PrintlnStdout("Token:", loggedInUserDetails.UserCredentials.JTWToken)

			if tokenPayload.Exp != 0 {
				expiresAt := time.Unix(tokenPayload.Exp, 0)
				ttl := time.Until(expiresAt)
				if ttl > 0 {
					util.PrintlnStdout("Expires At:", expiresAt.Format(time.RFC1123))
					util.PrintlnStdout("TTL:", ttl.Round(time.Second).String())
				} else {
					util.PrintlnStdout("Expires At:", expiresAt.Format(time.RFC1123), "(expired)")
					util.PrintlnStdout("TTL: expired")
				}
			}
		}
	},
}

var updateCmd = &cobra.Command{
	Use:                   "update",
	Short:                 "Used to update properties of an Infisical profile",
	DisableFlagsInUseLine: true,
	Example:               "infisical user update",
	Args:                  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Point a profile at a different Infisical instance",
	Long: `Point a profile at a different Infisical instance.

Exactly the profile you pick is changed, even when other profiles share its
account and instance. A session issued by the previous instance is not valid on
the new one and must not be sent there, so the profile's stored credentials are
cleared and you are asked to sign in again.`,
	DisableFlagsInUseLine: true,
	Example:               "infisical user update domain",
	Args:                  cobra.ExactArgs(0),
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: func(cmd *cobra.Command, args []string) {
		configFile, err := util.GetMigratedConfigFile()
		if err != nil {
			util.HandleError(err, "[infisical user update domain]: Unable to get config file")
		}
		if len(configFile.Profiles) == 0 {
			util.PrintErrorMessageAndExit("No login profiles found. Run [infisical login] to create one.")
		}

		// Selecting a profile rather than an email matters: several profiles can
		// share an email and an instance while holding different organizations,
		// and only the chosen one should move.
		labels := make([]string, len(configFile.Profiles))
		for idx, profile := range configFile.Profiles {
			labels[idx] = fmt.Sprintf("%s (%s, org %s, %s)", profile.Name, profile.Email, orgLabel(profile), util.DisplayDomain(profile.Domain))
		}
		prompt := promptui.Select{
			Label: "Which profile should point at a different instance",
			Items: labels,
			Size:  7,
		}
		index, _, err := prompt.Run()
		if err != nil {
			util.HandleError(err, "[infisical user update domain]: Prompt error")
		}
		selected := configFile.Profiles[index]

		domain := ""
		domainQuery := true
		if config.INFISICAL_URL_MANUAL_OVERRIDE != fmt.Sprintf("%s/api", util.INFISICAL_DEFAULT_EU_URL) && config.INFISICAL_URL_MANUAL_OVERRIDE != fmt.Sprintf("%s/api", util.INFISICAL_DEFAULT_US_URL) {
			override, err := DomainOverridePrompt()
			if err != nil {
				util.HandleError(err, "[infisical user update domain]: Domain override prompt error")
			}

			if !override {
				domainQuery = false
				domain = config.INFISICAL_URL_MANUAL_OVERRIDE
			}
		}

		if domainQuery {
			domain, err = NewDomainPrompt()
			if err != nil {
				util.HandleError(err, "[infisical user update domain]: Prompt error")
			}
		}

		if util.AppendAPIEndpoint(domain) == util.AppendAPIEndpoint(selected.Domain) {
			util.PrintlnStderr(fmt.Sprintf("Profile '%s' already uses %s. Nothing changed.", selected.Name, util.DisplayDomain(domain)))
			return
		}

		// Remove the old session before recording the new instance, and abandon
		// the change if it cannot be removed. Persisting the new instance while
		// the previous session survived under this profile name would send that
		// token to the new endpoint, which is the disclosure this clearing
		// exists to prevent.
		if err := util.ClearStoredSession(selected.Name); err != nil {
			util.HandleError(err, fmt.Sprintf("Unable to clear the stored session of profile '%s'. It still points at %s, because its existing session must not be sent to %s.",
				selected.Name, util.DisplayDomain(selected.Domain), util.DisplayDomain(domain)))
		}

		if !util.RepointProfileDomain(&configFile, selected.Name, domain) {
			util.PrintlnStderr(fmt.Sprintf("Profile '%s' already uses %s. Nothing changed.", selected.Name, util.DisplayDomain(domain)))
			return
		}

		if err := util.WriteConfigFile(&configFile); err != nil {
			util.HandleError(err, "")
		}

		util.PrintlnStderr(fmt.Sprintf("Profile '%s' now points at %s. Its previous session was cleared, so run [infisical login --profile %s --domain %s] to sign in there.",
			selected.Name, util.DisplayDomain(domain), selected.Name, util.DisplayDomain(domain)))

		Telemetry.CaptureEvent("cli-command:user domain", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

func init() {
	updateCmd.AddCommand(domainCmd)
	userCmd.AddCommand(updateCmd)

	userGetTokenCmd.Flags().Bool("plain", false, "print token without formatting")
	userGetCmd.AddCommand(userGetTokenCmd)

	userCmd.AddCommand(userGetCmd)
	userCmd.AddCommand(switchCmd)
	RootCmd.AddCommand(userCmd)
}

// This returns all logged in user emails from the config file.
// If none, it returns the current logged in user in a slice
func getLoggedInUsers() ([]string, error) {
	loggedInProfiles := []string{}

	if util.ConfigFileExists() {
		configFile, err := util.GetConfigFile()
		if err != nil {
			return loggedInProfiles, err
		}

		//get logged in profiles
		//
		if len(configFile.LoggedInUsers) > 0 {
			for _, v := range configFile.LoggedInUsers {
				loggedInProfiles = append(loggedInProfiles, v.Email)
			}
		} else {

			loggedInProfiles = append(loggedInProfiles, configFile.LoggedInUserEmail)
		}
		return loggedInProfiles, nil
	} else {
		//empty
		return loggedInProfiles, errors.New("couldn't retrieve config file")
	}
}

func NewDomainPrompt() (string, error) {
	urlValidation := func(input string) error {
		_, err := url.ParseRequestURI(input)
		if err != nil {
			return errors.New("this is an invalid url")
		}
		return nil
	}

	//else run prompt to enter domain
	domainPrompt := promptui.Prompt{
		Label:    "New Domain",
		Validate: urlValidation,
		Default:  "Example - https://my-self-hosted-instance.com/api",
	}

	domain, err := domainPrompt.Run()
	if err != nil {
		return "", err
	}

	return util.AppendAPIEndpoint(domain), nil
}

func LoggedInUsersPrompt(profiles []string) (string, error) {
	prompt := promptui.Select{Label: "Which of your Infisical profiles would you like to use",
		Items: profiles,
		Size:  7,
	}

	idx, _, err := prompt.Run()
	if err != nil {
		return "", err
	}

	return profiles[idx], nil
}
