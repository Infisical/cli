package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var loginStatusCmd = &cobra.Command{
	Use:                   "status",
	Short:                 "View the current authentication status",
	Long:                  "Reports whether the CLI is authenticated to Infisical and, when available, the organization the active session is scoped to.",
	DisableFlagsInUseLine: true,
	Example:               "infisical login status",
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")

		loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
		if err != nil {
			if strings.Contains(err.Error(), "we couldn't find your logged in details") {
				printNotAuthenticated(jsonOutput)
				os.Exit(1)
			}
			util.HandleError(err, "[infisical login status]: Unable to read logged-in user details")
		}

		if !loggedInUserDetails.IsUserLoggedIn {
			printNotAuthenticated(jsonOutput)
			os.Exit(1)
		}

		domain := strings.TrimSuffix(config.INFISICAL_URL, "/api")
		token := loggedInUserDetails.UserCredentials.JTWToken
		claims, claimsErr := decodeTokenClaims(token)

		var resolved resolvedLoginOrgNames
		if claimsErr == nil && claims.OrganizationID != "" {
			resolved = resolveLoggedInOrgNames(token, claims.OrganizationID, claims.SubOrganizationID)
		}

		if jsonOutput {
			out := loginStatusJSONOutput{Domain: domain}
			if claimsErr == nil {
				if claims.Exp != 0 {
					out.Token = &loginStatusTokenJSON{Exp: claims.Exp}
				}
				if claims.OrganizationID != "" || resolved.Organization != "" {
					out.Organization = &loginStatusOrgJSON{
						ID:   claims.OrganizationID,
						Name: resolved.Organization,
					}
				}
				if claims.SubOrganizationID != "" || resolved.SubOrganization != "" {
					out.SubOrganization = &loginStatusOrgJSON{
						ID:   claims.SubOrganizationID,
						Name: resolved.SubOrganization,
					}
				}
			}
			if err := writeLoginStatusJSON(out); err != nil {
				util.HandleError(err, "[infisical login status]: Unable to encode JSON output")
			}
			if loggedInUserDetails.LoginExpired {
				os.Exit(1)
			}
			return
		}

		bold := color.New(color.Bold)
		green := color.New(color.FgGreen).Add(color.Bold)
		red := color.New(color.FgRed).Add(color.Bold)

		util.PrintlnStdout(bold.Sprint(domain))

		if loggedInUserDetails.LoginExpired {
			util.PrintfStdout("  %s Logged in as %s (session expired)\n", red.Sprint("x"), bold.Sprint(loggedInUserDetails.UserCredentials.Email))
			util.PrintlnStdout("  - Run `infisical login` to re-authenticate.")
			os.Exit(1)
		}

		util.PrintfStdout("  %s Logged in as %s\n", green.Sprint("✓"), bold.Sprint(loggedInUserDetails.UserCredentials.Email))

		if claimsErr == nil && claims.Exp != 0 {
			printStatusItem("Token", fmt.Sprintf("true (expires %s)", formatExpiry(time.Unix(claims.Exp, 0))))
		} else {
			printStatusItem("Token", "true")
		}

		if claimsErr != nil {
			log.Debug().Err(claimsErr).Msg("login status: unable to decode token payload")
			printStatusItem("Organization", "unknown (could not parse token)")
			return
		}

		if claims.OrganizationID == "" {
			printStatusItem("Organization", "none (token is not scoped to an organization)")
			return
		}

		if resolved.Organization != "" {
			printStatusItem("Organization", fmt.Sprintf("%s (%s)", resolved.Organization, claims.OrganizationID))
		} else {
			printStatusItem("Organization", claims.OrganizationID)
		}

		if claims.SubOrganizationID != "" {
			if resolved.SubOrganization != "" {
				printStatusItem("Sub-organization", fmt.Sprintf("%s (%s)", resolved.SubOrganization, claims.SubOrganizationID))
			} else {
				printStatusItem("Sub-organization", claims.SubOrganizationID)
			}
		}
	},
}

type loginStatusJSONOutput struct {
	Domain          string                `json:"domain,omitempty"`
	Token           *loginStatusTokenJSON `json:"token,omitempty"`
	Organization    *loginStatusOrgJSON   `json:"organization,omitempty"`
	SubOrganization *loginStatusOrgJSON   `json:"sub_organization,omitempty"`
}

type loginStatusTokenJSON struct {
	Exp int64 `json:"exp,omitempty"`
}

type loginStatusOrgJSON struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

func writeLoginStatusJSON(out loginStatusJSONOutput) error {
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	util.PrintlnStdout(string(data))
	return nil
}

func printStatusItem(key, value string) {
	bold := color.New(color.Bold)
	util.PrintfStdout("  - %s: %s\n", key, bold.Sprint(value))
}

type loginTokenClaims struct {
	OrganizationID    string `json:"organizationId"`
	SubOrganizationID string `json:"subOrganizationId"`
	Exp               int64  `json:"exp"`
}

func decodeTokenClaims(token string) (loginTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return loginTokenClaims{}, fmt.Errorf("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return loginTokenClaims{}, err
	}
	var claims loginTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return loginTokenClaims{}, err
	}
	return claims, nil
}

func formatExpiry(expiresAt time.Time) string {
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return "expired"
	}
	hours := int(remaining.Hours())
	if hours >= 24 {
		days := hours / 24
		return fmt.Sprintf("in %dd %dh", days, hours%24)
	}
	if hours > 0 {
		return fmt.Sprintf("in %dh %dm", hours, int(remaining.Minutes())%60)
	}
	return fmt.Sprintf("in %dm", int(remaining.Minutes()))
}

type resolvedLoginOrgNames struct {
	Organization    string
	SubOrganization string
}

func resolveLoggedInOrgNames(token, orgID, subOrgID string) resolvedLoginOrgNames {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		log.Debug().Err(err).Msg("login status: unable to build http client")
		return resolvedLoginOrgNames{}
	}
	httpClient.SetAuthToken(token)

	var result resolvedLoginOrgNames

	if subOrgID != "" {
		if resp, err := api.CallGetAllOrganizationsWithSubOrgs(httpClient); err == nil {
			for _, org := range resp.Organizations {
				if org.ID == orgID {
					result.Organization = org.Name
					for _, sub := range org.SubOrganizations {
						if sub.ID == subOrgID {
							result.SubOrganization = sub.Name
							break
						}
					}
					break
				}
			}
		} else {
			log.Debug().Err(err).Msg("login status: failed to fetch orgs with sub-orgs")
		}
	}

	if result.Organization == "" {
		if resp, err := api.CallGetAllOrganizations(httpClient); err == nil {
			for _, org := range resp.Organizations {
				if org.ID == orgID {
					result.Organization = org.Name
					break
				}
			}
		} else {
			log.Debug().Err(err).Msg("login status: failed to fetch organizations")
		}
	}

	return result
}

func printNotAuthenticated(jsonOutput bool) {
	if jsonOutput {
		if err := writeLoginStatusJSON(loginStatusJSONOutput{}); err != nil {
			util.HandleError(err, "[infisical login status]: Unable to encode JSON output")
		}
		return
	}
	red := color.New(color.FgRed).Add(color.Bold)
	util.PrintfStdout("%s You are not authenticated.\nRun `infisical login` to log in.\n", red.Sprint("x"))
}

func init() {
	loginStatusCmd.Flags().Bool("json", false, "Output the login status as JSON")
	loginCmd.AddCommand(loginStatusCmd)
}
