package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	statusAuthenticated   = "authenticated"
	statusExpired         = "expired"
	statusUnauthenticated = "unauthenticated"
)

var (
	boldStyle  = color.New(color.Bold)
	greenStyle = color.New(color.FgGreen, color.Bold)
	redStyle   = color.New(color.FgRed, color.Bold)
)

var loginStatusCmd = &cobra.Command{
	Use:                   "status",
	Short:                 "View the current authentication status",
	Long:                  "Reports whether the CLI is authenticated to Infisical and, when available, the organization the active session is scoped to.",
	DisableFlagsInUseLine: true,
	Example:               "infisical login status",
	Args:                  cobra.NoArgs,
	Run:                   runLoginStatus,
}

func runLoginStatus(cmd *cobra.Command, args []string) {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil {
		if errors.Is(err, util.ErrUserNotLoggedIn) {
			renderNotAuthenticated(jsonOutput)
			os.Exit(1)
		}
		util.HandleError(err, "Unable to read logged-in user details")
	}

	if !loggedInUserDetails.IsUserLoggedIn {
		renderNotAuthenticated(jsonOutput)
		os.Exit(1)
	}

	// INFISICAL_URL may be reassigned by GetCurrentLoggedInUserDetails(true) above
	// to point at the logged-in user's domain — read it after the call.
	domain := strings.TrimSuffix(config.INFISICAL_URL, "/api")

	token := loggedInUserDetails.UserCredentials.JTWToken
	claims, claimsErr := parseLoginJWTClaims(token)

	var resolved resolvedLoginOrgNames
	if claimsErr == nil && claims.OrganizationID != "" {
		resolved = resolveLoggedInOrgNames(token, claims.OrganizationID, claims.SubOrganizationID)
	}

	ctx := loginStatusContext{
		domain:       domain,
		loggedInUser: loggedInUserDetails,
		claims:       claims,
		claimsErr:    claimsErr,
		resolved:     resolved,
	}

	if jsonOutput {
		if err := writeLoginStatusJSON(buildJSONOutput(ctx)); err != nil {
			util.HandleError(err, "Unable to encode JSON output")
		}
	} else {
		renderHuman(ctx)
	}

	if loggedInUserDetails.LoginExpired {
		os.Exit(1)
	}
}

type loginStatusContext struct {
	domain       string
	loggedInUser util.LoggedInUserDetails
	claims       loginTokenClaims
	claimsErr    error
	resolved     resolvedLoginOrgNames
}

type loginStatusJSONOutput struct {
	Status          string                `json:"status"`
	Domain          string                `json:"domain,omitempty"`
	Token           *loginStatusTokenJSON `json:"token,omitempty"`
	Organization    *loginStatusOrgJSON   `json:"organization,omitempty"`
	SubOrganization *loginStatusOrgJSON   `json:"subOrganization,omitempty"`
}

type loginStatusTokenJSON struct {
	Exp int64 `json:"exp,omitempty"`
}

type loginStatusOrgJSON struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

func buildJSONOutput(ctx loginStatusContext) loginStatusJSONOutput {
	out := loginStatusJSONOutput{
		Domain: ctx.domain,
		Status: statusAuthenticated,
	}
	if ctx.loggedInUser.LoginExpired {
		out.Status = statusExpired
	}

	if ctx.claimsErr != nil {
		return out
	}

	if ctx.claims.ExpiresAt != nil {
		out.Token = &loginStatusTokenJSON{Exp: ctx.claims.ExpiresAt.Unix()}
	}
	if ctx.claims.OrganizationID != "" || ctx.resolved.Organization != "" {
		out.Organization = &loginStatusOrgJSON{
			ID:   ctx.claims.OrganizationID,
			Name: ctx.resolved.Organization,
		}
	}
	if ctx.claims.SubOrganizationID != "" || ctx.resolved.SubOrganization != "" {
		out.SubOrganization = &loginStatusOrgJSON{
			ID:   ctx.claims.SubOrganizationID,
			Name: ctx.resolved.SubOrganization,
		}
	}
	return out
}

func writeLoginStatusJSON(out loginStatusJSONOutput) error {
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	util.PrintlnStdout(string(data))
	return nil
}

func renderHuman(ctx loginStatusContext) {
	util.PrintlnStdout(boldStyle.Sprint(ctx.domain))

	if ctx.loggedInUser.LoginExpired {
		util.PrintfStdout("  %s Logged in as %s (session expired)\n",
			redStyle.Sprint("x"), boldStyle.Sprint(ctx.loggedInUser.UserCredentials.Email))
		util.PrintlnStdout("  - Run `infisical login` to re-authenticate.")
		return
	}

	util.PrintfStdout("  %s Logged in as %s\n",
		greenStyle.Sprint("✓"), boldStyle.Sprint(ctx.loggedInUser.UserCredentials.Email))

	printStatusItem("Token", tokenStatusLine(ctx.claims, ctx.claimsErr))
	printStatusItem("Organization", orgStatusLine(ctx.claims, ctx.claimsErr, ctx.resolved))

	if ctx.claimsErr == nil && ctx.claims.SubOrganizationID != "" {
		printStatusItem("Sub-organization", subOrgStatusLine(ctx.claims, ctx.resolved))
	}
}

func tokenStatusLine(claims loginTokenClaims, claimsErr error) string {
	if claimsErr == nil && claims.ExpiresAt != nil {
		return fmt.Sprintf("true (expires %s)", formatExpiry(claims.ExpiresAt.Time))
	}
	return "true"
}

func orgStatusLine(claims loginTokenClaims, claimsErr error, resolved resolvedLoginOrgNames) string {
	if claimsErr != nil {
		log.Debug().Err(claimsErr).Msg("login status: unable to decode token payload")
		return "unknown (could not parse token)"
	}
	if claims.OrganizationID == "" {
		return "none (token is not scoped to an organization)"
	}
	if resolved.Organization != "" {
		return fmt.Sprintf("%s (%s)", resolved.Organization, claims.OrganizationID)
	}
	return claims.OrganizationID
}

func subOrgStatusLine(claims loginTokenClaims, resolved resolvedLoginOrgNames) string {
	if resolved.SubOrganization != "" {
		return fmt.Sprintf("%s (%s)", resolved.SubOrganization, claims.SubOrganizationID)
	}
	return claims.SubOrganizationID
}

func printStatusItem(key, value string) {
	util.PrintfStdout("  - %s: %s\n", key, boldStyle.Sprint(value))
}

type loginTokenClaims struct {
	OrganizationID    string `json:"organizationId"`
	SubOrganizationID string `json:"subOrganizationId"`
	jwt.RegisteredClaims
}

func parseLoginJWTClaims(token string) (loginTokenClaims, error) {
	var claims loginTokenClaims
	parser := jwt.NewParser()
	if _, _, err := parser.ParseUnverified(token, &claims); err != nil {
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
	subOrgEndpointSucceeded := false

	if subOrgID != "" {
		if resp, err := api.CallGetAllOrganizationsWithSubOrgs(httpClient); err == nil {
			subOrgEndpointSucceeded = true
			for _, org := range resp.Organizations {
				if org.ID != orgID {
					continue
				}
				result.Organization = org.Name
				for _, sub := range org.SubOrganizations {
					if sub.ID == subOrgID {
						result.SubOrganization = sub.Name
						break
					}
				}
				break
			}
		} else {
			log.Debug().Err(err).Msg("login status: failed to fetch orgs with sub-orgs")
		}
	}

	if !subOrgEndpointSucceeded {
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

func renderNotAuthenticated(jsonOutput bool) {
	if jsonOutput {
		if err := writeLoginStatusJSON(loginStatusJSONOutput{Status: statusUnauthenticated}); err != nil {
			util.HandleError(err, "Unable to encode JSON output")
		}
		return
	}
	util.PrintfStdout("%s You are not authenticated.\nRun `infisical login` to log in.\n", redStyle.Sprint("x"))
}

func init() {
	loginStatusCmd.Flags().Bool("json", false, "Output the login status as JSON")
	loginCmd.AddCommand(loginStatusCmd)
}
