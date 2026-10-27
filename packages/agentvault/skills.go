package agentvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/rs/zerolog/log"
)

const (
	SkillsPath = "/_agent-vault/skills"

	skillsUnsupportedBody = "skills are not supported by this Infisical instance"
)

// A seam so the endpoint can be tested without a server, like sessionResolver.
type skillsSource interface {
	listSkills(sessionToken string) (api.AgentVaultProxySkillsResponse, error)
}

// SkillFilesSha256 is the hash Infisical stores for a version: sha256 over the files sorted by the UTF-8 bytes
// of their paths, as the JSON array [{path, mode, contentBase64}] that JavaScript's JSON.stringify produces.
// encoding/json is not used because it escapes <, >, & and U+2028/U+2029 where JSON.stringify does not.
func SkillFilesSha256(files []api.AgentVaultSkillFile) string {
	sorted := append([]api.AgentVaultSkillFile(nil), files...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, f := range sorted {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"path":`)
		writeJSString(&buf, f.Path)
		buf.WriteString(`,"mode":`)
		writeJSString(&buf, f.Mode)
		buf.WriteString(`,"contentBase64":`)
		writeJSString(&buf, f.ContentBase64)
		buf.WriteByte('}')
	}
	buf.WriteByte(']')
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func writeJSString(buf *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[r>>4])
				buf.WriteByte(hexDigits[r&0xf])
				continue
			}
			var enc [utf8.UTFMax]byte
			n := utf8.EncodeRune(enc[:], r)
			buf.Write(enc[:n])
		}
	}
	buf.WriteByte('"')
}

// Fastify's own answer for a route it does not have. A NotFoundError thrown by a handler is named "NotFound"
// and never carries documentationUrl, so the two cannot be confused.
const infisicalRouteMissingName = "Not Found"

func isInfisicalRouteMissing(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound &&
		apiErr.Name == infisicalRouteMissingName && apiErr.DocumentationURL != ""
}

// serveSkills answers GET /_agent-vault/skills with the latest version of every skill the session can reach,
// and reports whether the path was that one.
func (ps *proxyServer) serveSkills(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != SkillsPath {
		return false
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}

	sessionToken, ok := requestSessionToken(r)
	if !ok {
		writeProxyAuthChallenge(w)
		return true
	}

	if _, _, err := ps.cache.lookup(sessionToken); err != nil {
		ps.denySkills(w, sessionToken, err)
		return true
	}
	skills, err := ps.skillsSource.listSkills(sessionToken)
	if err != nil {
		ps.denySkills(w, sessionToken, err)
		return true
	}
	if skills.Skills == nil {
		skills.Skills = []api.AgentVaultProxySkill{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(skills)
	return true
}

// The same verdicts as denyAtGate, plus an Infisical that has no skills route.
func (ps *proxyServer) denySkills(w http.ResponseWriter, sessionToken string, err error) {
	switch {
	case isInfisicalRouteMissing(err):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": skillsUnsupportedBody})
	case isProxyTokenRejected(err):
		log.Error().Err(err).Str("sessionKey", sessionKey(sessionToken)).Int("status", http.StatusServiceUnavailable).
			Msg("agent-vault: skills refused, Infisical rejected this proxy's token")
		http.Error(w, proxyRevokedBody, http.StatusServiceUnavailable)
	case isSessionGone(err):
		log.Warn().Str("sessionKey", sessionKey(sessionToken)).Int("status", http.StatusForbidden).
			Msg("agent-vault: skills refused, the session is no longer valid")
		http.Error(w, "the session is no longer valid", http.StatusForbidden)
	default:
		log.Error().Err(err).Str("sessionKey", sessionKey(sessionToken)).Int("status", http.StatusBadGateway).
			Msg("agent-vault: skills could not be fetched from Infisical")
		http.Error(w, "failed to fetch skills from Infisical", http.StatusBadGateway)
	}
}
