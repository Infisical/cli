package util

import (
	"fmt"
	"io"
	"sync"
)

var (
	profileNoticeWriter io.Writer
	profileNoticeOnce   sync.Once
)

// EnableProfileNotice turns on the one-time "Using profile ..." notice, written
// to w the first time a command actually loads a login session. The root
// command enables it for ordinary commands; profile-management commands print
// their own outcome, and silent or structured-output runs stay quiet, so they
// leave it off. Commands that never load a session, such as scan or agent,
// therefore never print it even when a profile is pinned.
func EnableProfileNotice(w io.Writer) {
	profileNoticeWriter = w
}

// printProfileNotice reports which profile and organization a session load
// resolved to, once per process. See FormatProfileNotice for when it is quiet.
func printProfileNotice(resolved ResolvedProfile, details LoggedInUserDetails) {
	if profileNoticeWriter == nil {
		return
	}
	notice := FormatProfileNotice(resolved, details)
	if notice == "" {
		return
	}
	profileNoticeOnce.Do(func() {
		fmt.Fprintln(profileNoticeWriter, notice)
	})
}

// FormatProfileNotice renders the notice for a session load whose selection
// came from somewhere non-obvious: the --profile flag, INFISICAL_PROFILE, a
// directory binding, or an --org/INFISICAL_ORG override. Plain default-profile
// usage yields "", so single-profile setups never see it.
func FormatProfileNotice(resolved ResolvedProfile, details LoggedInUserDetails) string {
	overridden := details.OrganizationSource != "" && details.OrganizationSource != OrgSourceProfileDefault
	if resolved.Source == ProfileSourceDefault && !overridden {
		return ""
	}

	orgName := details.OrganizationName
	if orgName == "" {
		orgName = details.OrganizationID
	}
	detail := ""
	if orgName != "" {
		detail = fmt.Sprintf(" (org %s)", orgName)
	}

	via := resolved.Source
	if resolved.ScopeDir != "" {
		via = fmt.Sprintf("%s %s", via, resolved.ScopeDir)
	}
	if overridden {
		if resolved.Source == ProfileSourceDefault {
			via = details.OrganizationSource
		} else {
			via = fmt.Sprintf("%s, org via %s", via, details.OrganizationSource)
		}
	}

	shadowed := ""
	if resolved.ShadowedName != "" {
		shadowed = fmt.Sprintf(", overriding this directory's binding to '%s'", resolved.ShadowedName)
	}

	return fmt.Sprintf("Using profile '%s'%s via %s%s", SanitizeDisplay(resolved.Name), SanitizeDisplay(detail), via, SanitizeDisplay(shadowed))
}
