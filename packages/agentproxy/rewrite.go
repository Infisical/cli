package agentproxy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	roleHeaderRewrite  = "header-rewrite"
	roleCredentialSub  = "credential-substitution"
	purposeUsername    = "username"
	purposePassword    = "password"
	surfaceHeader      = "header"
	surfacePath        = "path"
	surfaceQuery       = "query"
	surfaceBody        = "body"
	maxBodyRewriteSize = 10 * 1024 * 1024
)

type AppliedCredential struct {
	Key                string   `json:"key,omitempty"`
	DynamicSecretName  string   `json:"dynamicSecretName,omitempty"`
	DynamicSecretField string   `json:"dynamicSecretField,omitempty"`
	Role               string   `json:"role"`
	Header             string   `json:"header,omitempty"`
	Purpose            string   `json:"purpose,omitempty"`
	Surfaces           []string `json:"surfaces,omitempty"`
}

// credLabel identifies the secret behind a credential for the activity log: a static key, or a dynamic
// secret name and output field. It never carries the value.
func credLabel(cred resolvedCredential) AppliedCredential {
	if cred.dynamic != nil {
		return AppliedCredential{DynamicSecretName: cred.dynamic.key.secretName, DynamicSecretField: cred.dynamic.field}
	}
	return AppliedCredential{Key: cred.secretKey}
}

func applyCredentials(req *http.Request, creds []resolvedCredential) ([]AppliedCredential, error) {
	var applied []AppliedCredential
	var basicUser, basicPass string
	var basicUserCred, basicPassCred resolvedCredential
	haveUser, havePass := false, false

	for _, cred := range creds {
		switch cred.role {
		case roleHeaderRewrite:
			switch cred.headerPurpose {
			case purposeUsername:
				basicUser = cred.value
				basicUserCred = cred
				haveUser = true
			case purposePassword:
				basicPass = cred.value
				basicPassCred = cred
				havePass = true
			default:
				headerName := cred.headerName
				if headerName == "" {
					headerName = "Authorization"
				}
				value := cred.value
				if cred.headerPrefix != "" {
					value = cred.headerPrefix + " " + value
				}
				req.Header.Set(headerName, value)
				ac := credLabel(cred)
				ac.Role = roleHeaderRewrite
				ac.Header = headerName
				applied = append(applied, ac)
			}
		case roleCredentialSub:
			surfaces, err := applySubstitution(req, cred)
			if err != nil {
				return nil, err
			}
			if len(surfaces) > 0 {
				ac := credLabel(cred)
				ac.Role = roleCredentialSub
				ac.Surfaces = surfaces
				applied = append(applied, ac)
			}
		}
	}

	if haveUser || havePass {
		token := base64.StdEncoding.EncodeToString([]byte(basicUser + ":" + basicPass))
		req.Header.Set("Authorization", "Basic "+token)
		if haveUser {
			ac := credLabel(basicUserCred)
			ac.Role = roleHeaderRewrite
			ac.Header = "Authorization"
			ac.Purpose = purposeUsername
			applied = append(applied, ac)
		}
		if havePass {
			ac := credLabel(basicPassCred)
			ac.Role = roleHeaderRewrite
			ac.Header = "Authorization"
			ac.Purpose = purposePassword
			applied = append(applied, ac)
		}
	}

	return applied, nil
}

func hasSurface(surfaces []string, target string) bool {
	for _, s := range surfaces {
		if s == target {
			return true
		}
	}
	return false
}

// replaceWithinLimit substitutes every occurrence of old in s, but only when the expanded result stays
// within limit bytes; otherwise it returns the input unchanged (ok=false). This stops a short placeholder
// mapped to a long secret (or a request stuffed with placeholders) from ballooning proxy memory, since
// ReplaceAll otherwise allocates by the expansion ratio rather than the input size.
func replaceWithinLimit(s, old, replacement string, limit int) (string, bool) {
	count := strings.Count(s, old)
	if count == 0 {
		return s, true
	}
	if len(s)+count*(len(replacement)-len(old)) > limit {
		return s, false
	}
	return strings.ReplaceAll(s, old, replacement), true
}

// Plain substring ReplaceAll on distinctive random placeholders; short or common placeholder values would over-match.
func applySubstitution(req *http.Request, cred resolvedCredential) ([]string, error) {
	placeholder := cred.placeholder
	if placeholder == "" {
		return nil, nil
	}
	real := cred.value

	var changed []string

	if hasSurface(cred.surfaces, surfacePath) && strings.Contains(req.URL.Path, placeholder) {
		if v, ok := replaceWithinLimit(req.URL.Path, placeholder, real, maxBodyRewriteSize); ok {
			req.URL.Path = v
			// Clearing RawPath makes Go re-encode the path from Path, which can change the byte form of other escaped segments.
			req.URL.RawPath = ""
			changed = append(changed, surfacePath)
		}
	}

	if hasSurface(cred.surfaces, surfaceQuery) && strings.Contains(req.URL.RawQuery, placeholder) {
		if v, ok := replaceWithinLimit(req.URL.RawQuery, placeholder, real, maxBodyRewriteSize); ok {
			req.URL.RawQuery = v
			changed = append(changed, surfaceQuery)
		}
	}

	if hasSurface(cred.surfaces, surfaceHeader) {
		headerChanged := false
		for name, values := range req.Header {
			for i, v := range values {
				if !strings.Contains(v, placeholder) {
					continue
				}
				if replaced, ok := replaceWithinLimit(v, placeholder, real, maxBodyRewriteSize); ok {
					req.Header[name][i] = replaced
					headerChanged = true
				}
			}
		}
		if headerChanged {
			changed = append(changed, surfaceHeader)
		}
	}

	if hasSurface(cred.surfaces, surfaceBody) && req.Body != nil {
		if req.Header.Get("Content-Encoding") != "" {
			return changed, nil
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, maxBodyRewriteSize+1))
		if err != nil {
			_ = req.Body.Close()
			return changed, fmt.Errorf("failed to read request body for substitution: %w", err)
		}
		if len(body) > maxBodyRewriteSize {
			req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), req.Body))
			return changed, nil
		}
		_ = req.Body.Close()
		count := bytes.Count(body, []byte(placeholder))
		// Forward unchanged when expanding the placeholder would push the body past the cap.
		if count > 0 && len(body)+count*(len(real)-len(placeholder)) > maxBodyRewriteSize {
			req.Body = io.NopCloser(bytes.NewReader(body))
			return changed, nil
		}
		rewritten := bytes.ReplaceAll(body, []byte(placeholder), []byte(real))
		req.Body = io.NopCloser(bytes.NewReader(rewritten))
		req.ContentLength = int64(len(rewritten))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
		if count > 0 {
			changed = append(changed, surfaceBody)
		}
	}

	return changed, nil
}
