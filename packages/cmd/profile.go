/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/mattn/go-isatty"
	"github.com/posthog/posthog-go"
	"github.com/spf13/cobra"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage login profiles for working across organizations and instances",
	Long: `Manage login profiles.

A profile is one login: an account on one instance, plus the organization it
uses by default. Selecting a profile selects all three, so switching tenants
never means logging in again.

Create the first one with [infisical login], and one per extra organization
with [infisical profile new].

Which profile a command uses is decided in this order:
  1. --profile on the command
  2. the INFISICAL_PROFILE environment variable ([infisical profile pin])
  3. a directory bound with [infisical profile bind]
  4. the default profile ([infisical profile use])

The organization is a setting on the profile, changed with
[infisical profile set-org] or overridden for one command with --org.`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// shellOutputIsCaptured reports whether stdout is being read by something
// rather than shown on screen. Commands that work by printing shell statements
// only take effect when the caller captures them, as in eval "$(...)"; a
// terminal on stdout means the statement was displayed and nothing changed.
func shellOutputIsCaptured() bool {
	return !isatty.IsTerminal(os.Stdout.Fd())
}

// requireShellCapture stops a shell-mutating command that was run bare, and
// shows the form that actually works, rather than reporting a success that did
// not happen.
func requireShellCapture(invocation string) {
	if shellOutputIsCaptured() {
		return
	}
	util.PrintlnStderr(fmt.Sprintf("This command works by printing a shell statement, so it only takes effect when the shell reads it:\n\n    eval \"$(%s)\"\n\nNothing has been changed. Tip: add a shell alias if you use this often.", invocation))
	os.Exit(1)
}

// orgLabel renders a profile's default organization for humans.
func orgLabel(profile models.Profile) string {
	if profile.OrganizationName != "" {
		return profile.OrganizationName
	}
	if profile.OrganizationID != "" {
		return profile.OrganizationID
	}
	return "not set"
}

var profileListCmd = &cobra.Command{
	Use:                   "list",
	Short:                 "List all login profiles",
	DisableFlagsInUseLine: true,
	Example:               "infisical profile list",
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		configFile, err := util.GetMigratedConfigFile()
		if err != nil {
			util.HandleError(err, "Unable to read the Infisical config file")
		}

		if len(configFile.Profiles) == 0 {
			util.PrintlnStderr("No login profiles found. Run [infisical login] to create one.")
			return
		}

		resolved := util.ResolveProfile(configFile)

		scopesByProfile := map[string][]string{}
		for dir, name := range configFile.DirectoryProfiles {
			scopesByProfile[name] = append(scopesByProfile[name], dir)
		}

		writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(writer, "CURRENT\tNAME\tEMAIL\tORGANIZATION\tSESSION\tDOMAIN\tDIRECTORY SCOPES")
		for _, profile := range configFile.Profiles {
			marker := ""
			if profile.Name == resolved.Name {
				marker = "*"
			}

			organization := profile.OrganizationName
			if organization == "" {
				organization = profile.OrganizationID
			}
			if organization == "" {
				organization = "-"
			}

			scopes := append([]string(nil), scopesByProfile[profile.Name]...)
			sort.Strings(scopes)
			scopesDisplay := strings.Join(scopes, ", ")
			if scopesDisplay == "" {
				scopesDisplay = "-"
			}

			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", marker, util.SanitizeDisplay(profile.Name), util.SanitizeDisplay(profile.Email),
				util.SanitizeDisplay(organization), util.SessionStatus(profile.Name), util.SanitizeDisplay(util.DisplayDomain(profile.Domain)), scopesDisplay)
		}
		writer.Flush()

		Telemetry.CaptureEvent("cli-command:profile list", posthog.NewProperties().Set("numberOfProfiles", len(configFile.Profiles)).Set("version", util.CLI_VERSION))
	},
}

var profileCurrentCmd = &cobra.Command{
	Use:                   "current",
	Short:                 "Show which profile commands run here will use, and why",
	DisableFlagsInUseLine: true,
	Example:               "infisical profile current",
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		plain, err := cmd.Flags().GetBool("plain")
		if err != nil {
			util.HandleError(err)
		}

		resolved, profile, found := util.ResolveActiveProfileDetails()
		if resolved.Name == "" {
			util.PrintErrorMessageAndExit("No profile is selected. Run [infisical login] to create one.")
		}

		if plain {
			util.PrintlnStdout(resolved.Name)
			return
		}

		selectedVia := resolved.Source
		if resolved.ScopeDir != "" {
			selectedVia = fmt.Sprintf("%s (%s)", selectedVia, resolved.ScopeDir)
		}

		util.PrintlnStdout("Profile:", resolved.Name)
		util.PrintlnStdout("Selected via:", selectedVia)
		if resolved.ShadowedName != "" {
			util.PrintlnStdout("Overrides binding:", fmt.Sprintf("%s (bound at %s). Run [eval \"$(infisical profile unpin)\"] to use it.", resolved.ShadowedName, resolved.ShadowedScopeDir))
		}

		if !found {
			util.PrintlnStdout("Status: profile does not exist. Run [infisical login --profile " + resolved.Name + "] to create it.")
			return
		}

		util.PrintlnStdout("Email:", profile.Email)

		// The organization is a setting on the profile, so report it here too,
		// along with an override when one is in effect for this command.
		organization := profile.OrganizationName
		if organization != "" && profile.OrganizationID != "" {
			organization = fmt.Sprintf("%s (%s)", organization, profile.OrganizationID)
		} else if organization == "" {
			organization = profile.OrganizationID
		}

		orgSelector, orgSource := util.GetOrgOverride()
		if orgSelector != "" {
			util.PrintlnStdout("Organization:", orgSelector)
			util.PrintlnStdout("Organization via:", orgSource)
			if organization != "" {
				util.PrintlnStdout("Profile default organization:", organization)
			}
		} else if organization != "" {
			util.PrintlnStdout("Organization:", organization)
			util.PrintlnStdout("Organization via:", util.OrgSourceProfileDefault)
		}
		if profile.SubOrganizationID != "" {
			util.PrintlnStdout("Sub-organization id:", profile.SubOrganizationID)
		}
		util.PrintlnStdout("Domain:", util.DisplayDomain(profile.Domain))

		Telemetry.CaptureEvent("cli-command:profile current", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

var profileNewCmd = &cobra.Command{
	Use:   "new [name]",
	Short: "Create a profile for another organization, reusing your current login",
	Long: `Create a profile for another organization without logging in again.

The new profile reuses the account and instance you are already signed in to,
scoped to the organization you choose, so both organizations stay usable at the
same time. The organization comes from --org when given, otherwise you are
asked to pick one.

Creating a profile does not change which one other terminals use. Pass --pin to
start using it in this terminal (run the command through eval), or --use to
make it the default for the machine.

To add a different account, or an account on another instance, use
[infisical login --profile <name>] instead.`,
	DisableFlagsInUseLine: true,
	Example:               "infisical profile new client-b --org globex\neval \"$(infisical profile new client-b --org globex --pin)\"\ninfisical profile new client-b --org globex --use",
	Args:                  cobra.ExactArgs(1),
	PreRun: func(cmd *cobra.Command, args []string) {
		util.RequireLogin()
	},
	Run: func(cmd *cobra.Command, args []string) {
		profileName := args[0]
		if err := util.ValidateProfileName(profileName); err != nil {
			util.HandleError(err)
		}

		useAsDefault, err := cmd.Flags().GetBool("use")
		if err != nil {
			util.HandleError(err)
		}
		pinTerminal, err := cmd.Flags().GetBool("pin")
		if err != nil {
			util.HandleError(err)
		}

		configFile, err := util.GetMigratedConfigFile()
		if err != nil {
			util.HandleError(err, "Unable to read the Infisical config file")
		}
		if _, exists := util.FindProfile(configFile, profileName); exists {
			util.PrintErrorMessageAndExit(fmt.Sprintf("Profile '%s' already exists. Pick another name, or change the organization it uses with [infisical profile set-org --profile %s].", profileName, profileName))
		}

		// This command does its own organization exchange, which can prompt for
		// MFA, so resolve the session with the --org override suspended rather
		// than letting it be applied (and fail) during resolution.
		orgSelector, _ := util.GetOrgOverride()
		restoreOrgOverride := util.SuspendOrgOverride()
		details := requireUserSession()
		restoreOrgOverride()

		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			util.HandleError(err, "Unable to get resty client with custom headers")
		}
		httpClient.SetAuthToken(details.UserCredentials.JTWToken)

		var selectedOrgID string
		if orgSelector != "" {
			resolvedOrg, err := util.ResolveOrgSelector(details.UserCredentials.JTWToken, orgSelector)
			if err != nil {
				util.HandleError(err)
			}
			selectedOrgID = resolvedOrg.ID
		} else {
			selectedOrgID, _, err = pickOrganization(httpClient, fmt.Sprintf("Which organization should profile '%s' use?", profileName), details.UserCredentials.Email)
			if err != nil {
				util.HandleError(err, "Unable to select organization")
			}
		}

		sessionToken, err := selectOrganizationToken(details.UserCredentials.JTWToken, details.UserCredentials.Email, selectedOrgID)
		if err != nil {
			util.HandleError(err, "Unable to scope the session to that organization")
		}

		orgID, subOrgID := util.ParseTokenOrgClaims(sessionToken)
		orgName := util.OrgDisplayName(sessionToken, orgID, subOrgID)

		credentials := details.UserCredentials
		credentials.JTWToken = sessionToken
		// Cached organization tokens belong to the profile they were minted
		// under; a new profile starts with an empty cache.
		credentials.OrgTokens = nil

		domain := details.Profile.Domain
		if domain == "" {
			domain = config.INFISICAL_URL
		}

		// Creating a profile does not take over the machine default unless asked,
		// since other terminals may be relying on it.
		err = util.PersistLoginProfile(models.Profile{
			Name:              profileName,
			Email:             details.UserCredentials.Email,
			Domain:            domain,
			OrganizationID:    orgID,
			OrganizationName:  orgName,
			SubOrganizationID: subOrgID,
		}, &credentials, useAsDefault)
		if err != nil {
			util.HandleError(err, "Unable to store the new profile")
		}

		orgDisplay := orgName
		if orgDisplay == "" {
			orgDisplay = orgID
		}

		// The profile exists either way, so an uncaptured --pin is a warning
		// rather than a failure.
		pinTookEffect := pinTerminal && shellOutputIsCaptured()
		if pinTerminal {
			// stdout carries only the export so the output stays eval-safe.
			util.PrintlnStdout(fmt.Sprintf("export %s=%s", util.INFISICAL_PROFILE_ENV_NAME, util.ShellQuote(profileName)))
		}

		util.PrintlnStderr(fmt.Sprintf("Created profile '%s' (%s, org %s). Profile '%s' is unchanged.", profileName, details.UserCredentials.Email, orgDisplay, details.ProfileName))

		switch {
		case useAsDefault && pinTookEffect:
			util.PrintlnStderr("It is now the default profile, and this terminal is pinned to it.")
		case useAsDefault:
			util.PrintlnStderr("It is now the default profile for this machine.")
		case pinTookEffect:
			util.PrintlnStderr("This terminal is pinned to it. Other terminals and the default profile are unaffected.")
		case pinTerminal:
			util.PrintWarning(fmt.Sprintf("--pin had no effect because the shell did not read the output. Pin this terminal with [eval \"$(infisical profile pin %s)\"].", profileName))
		default:
			util.PrintlnStderr(fmt.Sprintf("Start using it here with [eval \"$(infisical profile pin %s)\"], in a directory with [infisical profile bind %s], or everywhere with [infisical profile use %s].", profileName, profileName, profileName))
		}

		Telemetry.CaptureEvent("cli-command:profile new", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

var profileUseCmd = &cobra.Command{
	Use:   "use [name]",
	Short: "Make a profile the default for this machine",
	Long: `Make a profile the default for this machine.

This is the fallback used when nothing more specific applies. To choose a
profile for one terminal use [infisical profile pin], and for one directory use
[infisical profile bind].`,
	DisableFlagsInUseLine: true,
	Example:               "infisical profile use work-eu",
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profileName := args[0]

		configFile, err := util.GetMigratedConfigFile()
		if err != nil {
			util.HandleError(err, "Unable to read the Infisical config file")
		}

		profile, found := util.FindProfile(configFile, profileName)
		if !found {
			util.PrintErrorMessageAndExit(fmt.Sprintf("Profile '%s' does not exist. Run [infisical profile list] to see available profiles.", profileName))
		}

		if err := util.SetActiveProfile(&configFile, profileName); err != nil {
			util.HandleError(err)
		}
		if err := util.WriteConfigFile(&configFile); err != nil {
			util.HandleError(err, "Unable to save the Infisical config file")
		}
		util.PrintlnStderr(fmt.Sprintf("Default profile is now '%s' (%s, org %s, %s)", profileName, profile.Email, orgLabel(profile), util.DisplayDomain(profile.Domain)))

		Telemetry.CaptureEvent("cli-command:profile use", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

var profilePinCmd = &cobra.Command{
	Use:   "pin [name]",
	Short: "Pin this terminal to a profile, leaving other terminals alone",
	Long: `Pin the current terminal to a profile.

Prints an export statement, so run it through eval to have it take effect in
the shell you are in:

  eval "$(infisical profile pin globex)"

Only this terminal is affected. The default profile and every other terminal
keep whatever they were using, which is what makes it possible to work in
several organizations at once. Undo with [infisical profile unpin].`,
	DisableFlagsInUseLine: true,
	Example:               "eval \"$(infisical profile pin globex)\"",
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profileName := args[0]

		configFile, err := util.GetMigratedConfigFile()
		if err != nil {
			util.HandleError(err, "Unable to read the Infisical config file")
		}

		profile, found := util.FindProfile(configFile, profileName)
		if !found {
			util.PrintErrorMessageAndExit(fmt.Sprintf("Profile '%s' does not exist. Run [infisical profile list] to see available profiles.", profileName))
		}

		requireShellCapture(fmt.Sprintf("infisical profile pin %s", profileName))

		// stdout carries only the export so the output stays eval-safe.
		util.PrintlnStdout(fmt.Sprintf("export %s=%s", util.INFISICAL_PROFILE_ENV_NAME, util.ShellQuote(profileName)))
		util.PrintlnStderr(fmt.Sprintf("Pinned this terminal to profile '%s' (%s, org %s). Other terminals and the default profile are unaffected.", profileName, profile.Email, orgLabel(profile)))

		Telemetry.CaptureEvent("cli-command:profile pin", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

var profileUnpinCmd = &cobra.Command{
	Use:   "unpin",
	Short: "Remove this terminal's profile pin",
	Long: `Remove the pin from the current terminal, so it falls back to a bound
directory or the default profile.

Prints an unset statement, so run it through eval:

  eval "$(infisical profile unpin)"`,
	DisableFlagsInUseLine: true,
	Example:               "eval \"$(infisical profile unpin)\"",
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		requireShellCapture("infisical profile unpin")

		util.PrintlnStdout(fmt.Sprintf("unset %s", util.INFISICAL_PROFILE_ENV_NAME))
		util.PrintlnStderr("Removed this terminal's profile pin. It now follows a bound directory, or the default profile.")

		Telemetry.CaptureEvent("cli-command:profile unpin", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

var profileBindCmd = &cobra.Command{
	Use:   "bind [name] [path]",
	Short: "Bind a directory to a profile, so commands run there select it automatically",
	Long: `Bind a directory, and everything under it, to a profile.

Commands run inside that directory select the profile with no flag and no
environment variable, so moving between projects moves between organizations.
The nearest bound directory wins, and the binding is stored in your own
configuration, never in the repository.

With no arguments, binds the current directory to the profile already in
effect, which is usually what you want right after logging in or switching.
Name a profile to bind a different one, and add a path to bind somewhere other
than the current directory. Undo with [infisical profile unbind].`,
	DisableFlagsInUseLine: true,
	Example:               "infisical profile bind\ninfisical profile bind client-a\ninfisical profile bind client-a ~/work/client-a",
	Args:                  cobra.MaximumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, err := util.GetMigratedConfigFile()
		if err != nil {
			util.HandleError(err, "Unable to read the Infisical config file")
		}

		var profileName string
		var chosenVia string

		if len(args) == 0 {
			// Bind whatever this directory would already have used, so the
			// common "make this stick here" case needs no arguments.
			resolved := util.ResolveProfile(configFile)
			if resolved.Name == "" {
				util.PrintErrorMessageAndExit("No profile is in effect here, so there is nothing to bind. Run [infisical login], or name a profile: [infisical profile bind <name>].")
			}
			profileName = resolved.Name
			chosenVia = resolved.Source
		} else {
			profileName = args[0]
		}

		if _, found := util.FindProfile(configFile, profileName); !found {
			// A lone path is the likely mistake here, since the first argument
			// is the profile and the second is the directory.
			if len(args) == 1 {
				if info, statErr := os.Stat(args[0]); statErr == nil && info.IsDir() {
					util.PrintErrorMessageAndExit(fmt.Sprintf("'%s' is a directory, not a profile. Use [infisical profile bind] on its own to bind the profile already in effect, or [infisical profile bind <name> %s] to name one.", args[0], args[0]))
				}
			}
			util.PrintErrorMessageAndExit(fmt.Sprintf("Profile '%s' does not exist. Run [infisical profile list] to see available profiles.", profileName))
		}

		target := "."
		if len(args) == 2 {
			target = args[1]
		}

		boundDir, err := filepath.Abs(target)
		if err != nil {
			util.HandleError(err, "Unable to resolve the directory")
		}
		dirInfo, err := os.Stat(boundDir)
		if err != nil || !dirInfo.IsDir() {
			util.PrintErrorMessageAndExit(fmt.Sprintf("%s is not an existing directory", boundDir))
		}

		// An identical binding on a parent already covers this directory, so
		// say so rather than silently adding a redundant entry.
		existingName, existingDir, hasExisting := util.FindGoverningDirectoryProfile(configFile, boundDir)
		redundant := hasExisting && existingName == profileName && existingDir != filepath.Clean(boundDir)

		util.SetDirectoryProfile(&configFile, boundDir, profileName)
		if err := util.WriteConfigFile(&configFile); err != nil {
			util.HandleError(err, "Unable to save the Infisical config file")
		}

		if chosenVia != "" {
			util.PrintlnStderr(fmt.Sprintf("Directory %s (and its subdirectories) now uses profile '%s', which was already in effect here via the %s.", boundDir, profileName, chosenVia))
		} else {
			util.PrintlnStderr(fmt.Sprintf("Directory %s (and its subdirectories) now uses profile '%s'.", boundDir, profileName))
		}
		if redundant {
			util.PrintlnStderr(fmt.Sprintf("Note: %s was already covered by the binding on %s, so this only makes it explicit.", boundDir, existingDir))
		}
		util.PrintlnStderr("Remove with [infisical profile unbind].")

		Telemetry.CaptureEvent("cli-command:profile bind", posthog.NewProperties().Set("implicitProfile", len(args) == 0).Set("version", util.CLI_VERSION))
	},
}

var profileUnbindCmd = &cobra.Command{
	Use:   "unbind [path]",
	Short: "Remove a directory's profile binding",
	Long: `Remove a directory's profile binding.

Defaults to whichever binding covers the current directory, so running it
inside a bound tree undoes that binding.`,
	DisableFlagsInUseLine: true,
	Example:               "infisical profile unbind\ninfisical profile unbind ~/work/client-a",
	Args:                  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, err := util.GetMigratedConfigFile()
		if err != nil {
			util.HandleError(err, "Unable to read the Infisical config file")
		}

		var target string
		if len(args) == 1 {
			target, err = filepath.Abs(args[0])
			if err != nil {
				util.HandleError(err, "Unable to resolve the given path")
			}
			if _, ok := configFile.DirectoryProfiles[filepath.Clean(target)]; !ok {
				util.PrintErrorMessageAndExit(fmt.Sprintf("No directory binding exists for %s. Run [infisical profile list] to see bindings.", target))
			}
		} else {
			cwd, err := os.Getwd()
			if err != nil {
				util.HandleError(err, "Unable to determine the current directory")
			}
			_, scopeDir, ok := util.FindGoverningDirectoryProfile(configFile, cwd)
			if !ok {
				util.PrintlnStderr("No directory binding covers the current directory.")
				return
			}
			target = scopeDir
		}

		util.RemoveDirectoryProfile(&configFile, target)
		if err := util.WriteConfigFile(&configFile); err != nil {
			util.HandleError(err, "Unable to save the Infisical config file")
		}
		util.PrintlnStderr(fmt.Sprintf("Removed the profile binding for %s", target))

		Telemetry.CaptureEvent("cli-command:profile unbind", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

var profileDeleteCmd = &cobra.Command{
	Use:                   "delete [name]",
	Short:                 "Delete a profile and its stored session credentials",
	DisableFlagsInUseLine: true,
	Example:               "infisical profile delete old-client",
	Args:                  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		profileName := args[0]

		configFile, err := util.GetMigratedConfigFile()
		if err != nil {
			util.HandleError(err, "Unable to read the Infisical config file")
		}

		if _, found := util.FindProfile(configFile, profileName); !found {
			util.PrintErrorMessageAndExit(fmt.Sprintf("Profile '%s' does not exist. Run [infisical profile list] to see available profiles.", profileName))
		}

		localOnly, err := cmd.Flags().GetBool("local-only")
		if err != nil {
			util.HandleError(err)
		}

		// Deleting a profile ends its session too, otherwise the credential
		// would keep working on the server after it looks gone locally.
		for _, result := range util.LogoutProfilesAcrossDomains(configFile, []string{profileName}, localOnly) {
			switch {
			case result.SharedWith != "":
				util.PrintlnStderr(fmt.Sprintf("The server session is still used by profile '%s', so it was left active.", result.SharedWith))
			case result.RevokeErr != nil:
				util.PrintWarning(fmt.Sprintf("Could not revoke the session on the server [err=%s]. It stays valid until it expires.", result.RevokeErr))
			case result.Revoked:
				util.PrintlnStderr("Revoked the session on the server.")
			}
		}

		util.RemoveProfile(&configFile, profileName)
		if err := util.WriteConfigFile(&configFile); err != nil {
			util.HandleError(err, "Unable to save the Infisical config file")
		}

		util.PrintlnStderr(fmt.Sprintf("Deleted profile '%s'", profileName))
		if configFile.ActiveProfile == "" && len(configFile.Profiles) > 0 {
			util.PrintlnStderr("No default profile is set. Pick one with [infisical profile use <name>].")
		}

		Telemetry.CaptureEvent("cli-command:profile delete", posthog.NewProperties().Set("version", util.CLI_VERSION))
	},
}

func init() {
	profileCurrentCmd.Flags().Bool("plain", false, "print only the profile name (useful for shell prompts)")
	profileDeleteCmd.Flags().Bool("local-only", false, "remove the profile without revoking its session on the server")

	profileNewCmd.Flags().Bool("use", false, "also make the new profile the default for this machine")
	profileNewCmd.Flags().Bool("pin", false, "also pin this terminal to the new profile, for use with: eval \"$(infisical profile new <name> --pin)\"")
	profileCmd.AddCommand(profileNewCmd)
	profileCmd.AddCommand(newSetOrgCommand("set-org [org]", "profile set-org", "Set the organization this profile uses by default"))
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileCurrentCmd)
	profileCmd.AddCommand(profileUseCmd)
	profileCmd.AddCommand(profilePinCmd)
	profileCmd.AddCommand(profileUnpinCmd)
	profileCmd.AddCommand(profileBindCmd)
	profileCmd.AddCommand(profileUnbindCmd)
	profileCmd.AddCommand(profileDeleteCmd)
	RootCmd.AddCommand(profileCmd)
}
