package session

import (
	"net/url"
	"strings"
)

// MaskURL removes the userinfo of rawURL and replaces query and fragment values with ***,
// keeping the parameter names.
func MaskURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "***"
	}
	u.User = nil
	if u.RawQuery != "" {
		u.RawQuery = maskParams(u.RawQuery)
	}
	if u.Fragment != "" {
		fragment := maskParams(u.EscapedFragment())
		u.Fragment, _ = url.PathUnescape(fragment)
		u.RawFragment = fragment
	}
	return u.String()
}

func maskParams(params string) string {
	parts := strings.Split(params, "&")
	for i, part := range parts {
		if name, _, ok := strings.Cut(part, "="); ok {
			parts[i] = name + "=***"
		}
	}
	return strings.Join(parts, "&")
}
