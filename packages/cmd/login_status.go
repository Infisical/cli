package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	statusAuthenticated = "authenticated"
	statusExpired       = "expired"
	statusRejected      = "rejected"

	principalKindUser            = "user"
	principalKindMachineIdentity = "machine-identity"
	principalKindServiceToken    = "service-token"

	verifyStateVerified = "verified"
	verifyStateRejected = "rejected"
	verifyStateUnknown  = "unknown"
	verifyStateSkipped  = "skipped"

	tokenSourceLoginSession = "infisical login (keyring)"

	verifyTimeout = 10 * time.Second

	authTokenTypeAccess         = "accessToken"
	authTokenTypeIdentityAccess = "identityAccessToken"
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

	// Machine identity / service token domain comes from the env/flag-driven
	// config.INFISICAL_URL. The user-session domain is whatever the user's
	// saved config points at, which GetCurrentLoggedInUserDetails(true) writes
	// back into config.INFISICAL_URL — so capture the env value first.
	envDomain := strings.TrimSuffix(config.INFISICAL_URL, "/api")

	flagToken, _ := cmd.Flags().GetString("token")
	flagToken = strings.TrimSpace(flagToken)
	if flagToken != "" {
		if !cmd.Flags().Changed("domain") {
			if _, envSet := os.LookupEnv("INFISICAL_API_URL"); !envSet {
				util.PrintErrorMessageAndExit("--token requires --domain (or INFISICAL_API_URL) to be set so the status reflects the correct Infisical instance")
			}
		}
		ctx, err := buildContextFromToken(flagToken, "--token flag", envDomain)
		if err != nil {
			util.PrintErrorMessageAndExit(err.Error())
		}
		ctx.verification = verifySession(ctx)
		emitLoginStatus([]loginStatusContext{ctx}, jsonOutput)
		if shouldExitWithError(ctx) {
			os.Exit(1)
		}
		return
	}

	var sessions []loginStatusContext

	if token, source, ok := detectMachineIdentityEnvToken(); ok {
		ctx, err := buildContextFromToken(token, source, envDomain)
		if err != nil {
			util.PrintErrorMessageAndExit(err.Error())
		}
		sessions = append(sessions, ctx)
	}

	loggedInUserDetails, err := util.GetCurrentLoggedInUserDetails(true)
	if err != nil && !errors.Is(err, util.ErrUserNotLoggedIn) {
		util.HandleError(err, "Unable to read logged-in user details")
	}
	if loggedInUserDetails.IsUserLoggedIn {
		userDomain := strings.TrimSuffix(config.INFISICAL_URL, "/api")
		sessions = append(sessions, buildUserContext(loggedInUserDetails, userDomain))
	}

	if len(sessions) == 0 {
		renderNotAuthenticated(jsonOutput)
		os.Exit(1)
	}

	for i := range sessions {
		sessions[i].verification = verifySession(sessions[i])
	}

	emitLoginStatus(sessions, jsonOutput)

	for _, s := range sessions {
		if shouldExitWithError(s) {
			os.Exit(1)
		}
	}
}

func buildUserContext(details util.LoggedInUserDetails, domain string) loginStatusContext {
	claims, claimsErr := parseLoginJWTClaims(details.UserCredentials.JTWToken)
	return loginStatusContext{
		kind:         principalKindUser,
		domain:       domain,
		loggedInUser: details,
		rawToken:     details.UserCredentials.JTWToken,
		claims:       claims,
		claimsErr:    claimsErr,
	}
}

// classifyToken determines whether a raw credential is a service token, a user
// session JWT, or a machine identity access token JWT. Service tokens are
// recognized by their "st." prefix; JWTs are dispatched on the authTokenType
// claim the backend stamps into every token it signs. For very old JWTs that
// pre-date that claim, falls back to looking for identityId / userId so we
// preserve back-compat without misclassifying a user JWT as a machine identity.
func classifyToken(token string) (string, loginTokenClaims, error) {
	if strings.HasPrefix(token, "st.") {
		return principalKindServiceToken, loginTokenClaims{}, nil
	}

	claims, err := parseLoginJWTClaims(token)
	if err != nil {
		return "", claims, err
	}

	switch claims.AuthTokenType {
	case authTokenTypeIdentityAccess:
		return principalKindMachineIdentity, claims, nil
	case authTokenTypeAccess:
		return principalKindUser, claims, nil
	case "":
		// Legacy tokens issued before authTokenType existed.
		if claims.IdentityID != "" {
			return principalKindMachineIdentity, claims, nil
		}
		if claims.UserID != "" {
			return principalKindUser, claims, nil
		}
		return principalKindMachineIdentity, claims, nil
	default:
		return "", claims, fmt.Errorf("unsupported token type %q (CLI only accepts user access tokens and machine identity access tokens)", claims.AuthTokenType)
	}
}

// buildContextFromToken constructs a status context for any externally-supplied
// token (--token flag or environment variable). The principal kind is derived
// from the token itself rather than from where it came from.
func buildContextFromToken(token, source, domain string) (loginStatusContext, error) {
	kind, claims, classifyErr := classifyToken(token)
	if classifyErr != nil && kind == "" {
		return loginStatusContext{}, classifyErr
	}

	ctx := loginStatusContext{
		kind:        kind,
		domain:      domain,
		rawToken:    token,
		tokenSource: source,
	}
	if kind != principalKindServiceToken {
		ctx.claims = claims
		ctx.claimsErr = classifyErr
	}
	return ctx, nil
}

func isContextExpired(ctx loginStatusContext) bool {
	if ctx.kind == principalKindUser && ctx.loggedInUser.LoginExpired {
		return true
	}
	if ctx.kind == principalKindServiceToken {
		return false
	}
	return ctx.claimsErr == nil && ctx.claims.ExpiresAt != nil && !ctx.claims.ExpiresAt.After(time.Now())
}

func contextStatus(ctx loginStatusContext) string {
	if isContextExpired(ctx) {
		return statusExpired
	}
	if ctx.verification.state == verifyStateRejected {
		return statusRejected
	}
	return statusAuthenticated
}

func shouldExitWithError(ctx loginStatusContext) bool {
	s := contextStatus(ctx)
	return s == statusExpired || s == statusRejected
}

func emitLoginStatus(sessions []loginStatusContext, jsonOutput bool) {
	if jsonOutput {
		if err := writeLoginStatusJSON(buildJSONOutput(sessions)); err != nil {
			util.HandleError(err, "Unable to encode JSON output")
		}
		return
	}
	for i, s := range sessions {
		if i > 0 {
			util.PrintlnStdout("")
		}
		renderHuman(s)
	}
}

func detectMachineIdentityEnvToken() (token, source string, ok bool) {
	candidates := []string{
		util.INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME,
		util.INFISICAL_TOKEN_NAME,
	}
	for _, name := range candidates {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v, fmt.Sprintf("%s environment variable", name), true
		}
	}
	return "", "", false
}

type loginStatusContext struct {
	kind         string
	domain       string
	loggedInUser util.LoggedInUserDetails // populated when kind == principalKindUser
	rawToken     string                   // bearer credential used for backend verification
	tokenSource  string                   // populated for machine-identity / service-token
	claims       loginTokenClaims
	claimsErr    error
	verification verificationResult
}

type verificationResult struct {
	state  string
	reason string
}

type loginStatusJSONOutput struct {
	Sessions []loginStatusSessionJSON `json:"sessions"`
}

type loginStatusSessionJSON struct {
	PrincipalType   string                       `json:"principalType,omitempty"`
	Status          string                       `json:"status,omitempty"`
	Domain          string                       `json:"domain,omitempty"`
	Email           string                       `json:"email,omitempty"`
	UserID          string                       `json:"userId,omitempty"`
	AuthMethod      string                       `json:"authMethod,omitempty"`
	TokenSource     string                       `json:"tokenSource,omitempty"`
	Identity        *loginStatusIdentityJSON     `json:"identity,omitempty"`
	Token           *loginStatusTokenJSON        `json:"token,omitempty"`
	Organization    *string                      `json:"organization,omitempty"`
	SubOrganization *string                      `json:"subOrganization,omitempty"`
	Verification    *loginStatusVerificationJSON `json:"verification,omitempty"`
}

type loginStatusTokenJSON struct {
	Exp int64 `json:"exp,omitempty"`
}

type loginStatusIdentityJSON struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type loginStatusVerificationJSON struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

func buildJSONOutput(sessions []loginStatusContext) loginStatusJSONOutput {
	out := loginStatusJSONOutput{Sessions: make([]loginStatusSessionJSON, 0, len(sessions))}
	for _, ctx := range sessions {
		out.Sessions = append(out.Sessions, buildSessionJSON(ctx))
	}
	return out
}

func buildSessionJSON(ctx loginStatusContext) loginStatusSessionJSON {
	session := loginStatusSessionJSON{
		PrincipalType: ctx.kind,
		Domain:        ctx.domain,
		AuthMethod:    authMethodLabel(ctx),
		TokenSource:   tokenSourceLabel(ctx),
		Status:        contextStatus(ctx),
		Verification:  verificationJSON(ctx.verification),
	}

	switch ctx.kind {
	case principalKindUser:
		session.Email = ctx.loggedInUser.UserCredentials.Email
		if ctx.claimsErr != nil {
			return session
		}
		if ctx.claims.UserID != "" {
			session.UserID = ctx.claims.UserID
		}
		if ctx.claims.ExpiresAt != nil {
			session.Token = &loginStatusTokenJSON{Exp: ctx.claims.ExpiresAt.Unix()}
		}
		if ctx.claims.OrganizationID != "" {
			session.Organization = &ctx.claims.OrganizationID
		}
		if ctx.claims.SubOrganizationID != "" {
			session.SubOrganization = &ctx.claims.SubOrganizationID
		}

	case principalKindMachineIdentity:
		if ctx.claimsErr != nil {
			return session
		}
		if ctx.claims.IdentityID != "" || ctx.claims.IdentityName != "" {
			session.Identity = &loginStatusIdentityJSON{
				ID:   ctx.claims.IdentityID,
				Name: ctx.claims.IdentityName,
			}
		}
		if ctx.claims.ExpiresAt != nil {
			session.Token = &loginStatusTokenJSON{Exp: ctx.claims.ExpiresAt.Unix()}
		}
		if ctx.claims.OrgID != "" {
			session.Organization = &ctx.claims.OrgID
		}
	}

	return session
}

func verificationJSON(v verificationResult) *loginStatusVerificationJSON {
	if v.state == "" {
		return nil
	}
	return &loginStatusVerificationJSON{State: v.state, Reason: v.reason}
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
	label := principalLabel(ctx)
	status := contextStatus(ctx)

	if status == statusAuthenticated {
		util.PrintfStdout("%s Authenticated as %s\n", greenStyle.Sprint("✓"), boldStyle.Sprint(label))
	} else {
		util.PrintfStdout("%s Failed to authenticate as %s\n", redStyle.Sprint("x"), boldStyle.Sprint(label))
	}

	if status != statusAuthenticated {
		if status == statusExpired {
			printStatusItem("Reason", "session expired")
		}
		if line := verificationLine(ctx.verification); line != "" {
			printStatusItem("Reason", line)
		}
	}

	if ctx.domain != "" {
		printStatusItem("Domain", ctx.domain)
	}
	if method := authMethodLabel(ctx); method != "" {
		printStatusItem("Auth method", method)
	}
	if ctx.kind == principalKindMachineIdentity && ctx.claimsErr == nil && ctx.claims.IdentityID != "" {
		printStatusItem("Identity", ctx.claims.IdentityID)
	}
	if source := tokenSourceLabel(ctx); source != "" {
		printStatusItem("Token source", source)
	}
	if ctx.kind != principalKindServiceToken {
		printStatusItem("Token expiration", tokenStatusLine(ctx.claims, ctx.claimsErr))
	}
	if ctx.kind == principalKindUser && ctx.claimsErr == nil && ctx.claims.UserID != "" {
		printStatusItem("User ID", ctx.claims.UserID)
	}
	if org := organizationLineFor(ctx); org != "" {
		printStatusItem("Organization", org)
	}
	if ctx.kind == principalKindUser && ctx.claimsErr == nil && ctx.claims.SubOrganizationID != "" {
		printStatusItem("Sub-organization", ctx.claims.SubOrganizationID)
	}

	if status != statusAuthenticated {
		switch ctx.kind {
		case principalKindUser:
			util.PrintlnStdout("  - Run `infisical login` to re-authenticate.")
		case principalKindMachineIdentity:
			util.PrintlnStdout("  - Verify the domain being used or run `infisical login` to re-authenticate and re-export your token.")
		case principalKindServiceToken:
			util.PrintlnStdout("  - Verify the service token has not been revoked or expired in your Infisical instance.")
		}
	}
}

func verificationLine(v verificationResult) string {
	labels := map[string]string{
		verifyStateVerified: "verified",
		verifyStateRejected: "rejected",
		verifyStateUnknown:  "unreachable",
		verifyStateSkipped:  "skipped",
	}
	label, ok := labels[v.state]
	if !ok {
		return ""
	}
	if v.reason != "" && v.state != verifyStateVerified {
		return fmt.Sprintf("%s (%s)", label, v.reason)
	}
	return label
}

func principalLabel(ctx loginStatusContext) string {
	switch ctx.kind {
	case principalKindUser:
		if email := ctx.loggedInUser.UserCredentials.Email; email != "" {
			return email
		}
		return "user"
	case principalKindMachineIdentity:
		if ctx.claimsErr == nil && ctx.claims.IdentityName != "" {
			return ctx.claims.IdentityName
		}
		return "machine identity"
	case principalKindServiceToken:
		return "service token"
	}
	return ""
}

func authMethodLabel(ctx loginStatusContext) string {
	if ctx.claimsErr == nil {
		return ctx.claims.AuthMethod
	}
	return "unknown"
}

func tokenSourceLabel(ctx loginStatusContext) string {
	if ctx.tokenSource != "" {
		return ctx.tokenSource
	}
	if ctx.kind == principalKindUser {
		return tokenSourceLoginSession
	}
	return ""
}

func organizationLineFor(ctx loginStatusContext) string {
	switch ctx.kind {
	case principalKindUser:
		return orgStatusLine(ctx.claims.OrganizationID, ctx.claimsErr)
	case principalKindMachineIdentity:
		return orgStatusLine(ctx.claims.OrgID, ctx.claimsErr)
	}
	return ""
}

func tokenStatusLine(claims loginTokenClaims, claimsErr error) string {
	if claimsErr != nil {
		return "unknown (could not parse token)"
	}
	if claims.ExpiresAt == nil {
		return "no expiration set"
	}
	return formatExpiry(claims.ExpiresAt.Time)
}

func orgStatusLine(orgID string, claimsErr error) string {
	if claimsErr != nil {
		log.Debug().Err(claimsErr).Msg("login status: unable to decode token payload")
		return "unknown (could not parse token)"
	}
	if orgID == "" {
		return "none (token is not scoped to an organization)"
	}
	return orgID
}

func printStatusItem(key, value string) {
	util.PrintfStdout("  - %s: %s\n", key, boldStyle.Sprint(value))
}

type loginTokenClaims struct {
	// Token kind discriminator stamped by the backend on every JWT it issues.
	AuthTokenType string `json:"authTokenType"`

	// User session JWT claims
	UserID            string `json:"userId"`
	OrganizationID    string `json:"organizationId"`
	SubOrganizationID string `json:"subOrganizationId"`

	// Machine identity access token JWT claims
	IdentityID   string `json:"identityId"`
	IdentityName string `json:"identityName"`
	AuthMethod   string `json:"authMethod"`
	OrgID        string `json:"orgId"`

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
		return fmt.Sprintf("%dd %dh", days, hours%24)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, int(remaining.Minutes())%60)
	}
	return fmt.Sprintf("%dm", int(remaining.Minutes()))
}

func renderNotAuthenticated(jsonOutput bool) {
	if jsonOutput {
		if err := writeLoginStatusJSON(loginStatusJSONOutput{Sessions: []loginStatusSessionJSON{}}); err != nil {
			util.HandleError(err, "Unable to encode JSON output")
		}
		return
	}
	util.PrintfStdout("%s You are not authenticated.\nRun `infisical login` to log in.\n", redStyle.Sprint("x"))
}

// verifySession asks the backend whether the credential associated with the
// context is still valid. Local-only signals (missing token,
// already-expired-by-clock) short-circuit the network call.
func verifySession(ctx loginStatusContext) verificationResult {
	if ctx.rawToken == "" {
		return verificationResult{state: verifyStateSkipped, reason: "no token available"}
	}
	if isContextExpired(ctx) {
		return verificationResult{state: verifyStateSkipped, reason: "locally expired"}
	}
	switch ctx.kind {
	case principalKindServiceToken:
		return performVerification(ctx.rawToken, ctx.domain, "/api/v2/service-token", http.MethodGet)
	case principalKindMachineIdentity:
		return performVerification(ctx.rawToken, ctx.domain, "/api/v1/identities/details", http.MethodGet)
	}
	return performVerification(ctx.rawToken, ctx.domain, "/api/v1/auth/checkAuth", http.MethodPost)
}

func performVerification(token, domain, path, method string) verificationResult {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return verificationResult{state: verifyStateUnknown, reason: err.Error()}
	}
	httpClient.
		SetAuthToken(token).
		SetHeader("Accept", "application/json").
		SetTimeout(verifyTimeout)

	url := strings.TrimRight(domain, "/") + path
	req := httpClient.R().SetHeader("User-Agent", api.USER_AGENT)

	var (
		statusCode int
		callErr    error
	)
	switch method {
	case http.MethodGet:
		resp, e := req.Get(url)
		callErr = e
		if resp != nil {
			statusCode = resp.StatusCode()
		}
	default:
		resp, e := req.Post(url)
		callErr = e
		if resp != nil {
			statusCode = resp.StatusCode()
		}
	}

	if callErr != nil {
		log.Debug().Err(callErr).Str("url", url).Msg("login status: backend verification call failed")
		return verificationResult{state: verifyStateUnknown, reason: "network error"}
	}
	switch {
	case statusCode >= 200 && statusCode < 300:
		return verificationResult{state: verifyStateVerified}
	case statusCode == http.StatusUnauthorized, statusCode == http.StatusForbidden:
		return verificationResult{state: verifyStateRejected, reason: fmt.Sprintf("HTTP %d", statusCode)}
	default:
		return verificationResult{state: verifyStateUnknown, reason: fmt.Sprintf("HTTP %d", statusCode)}
	}
}

func init() {
	loginStatusCmd.Flags().Bool("json", false, "Output the login status as JSON")
	loginStatusCmd.Flags().String("token", "", "Inspect this machine identity access token instead of the active session or environment variables")
	loginCmd.AddCommand(loginStatusCmd)
}
