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

func applyCredentials(req *http.Request, svc *resolvedService) error {
	var basicUser, basicPass string
	haveBasic := false

	for _, cred := range svc.credentials {
		switch cred.role {
		case roleHeaderRewrite:
			switch cred.headerPurpose {
			case purposeUsername:
				basicUser = cred.value
				haveBasic = true
			case purposePassword:
				basicPass = cred.value
				haveBasic = true
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
			}
		case roleCredentialSub:
			if err := applySubstitution(req, cred); err != nil {
				return err
			}
		}
	}

	if haveBasic {
		token := base64.StdEncoding.EncodeToString([]byte(basicUser + ":" + basicPass))
		req.Header.Set("Authorization", "Basic "+token)
	}

	return nil
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
func applySubstitution(req *http.Request, cred resolvedCredential) error {
	placeholder := cred.placeholder
	if placeholder == "" {
		return nil
	}
	real := cred.value

	if hasSurface(cred.surfaces, surfacePath) {
		if v, ok := replaceWithinLimit(req.URL.Path, placeholder, real, maxBodyRewriteSize); ok {
			req.URL.Path = v
			// Clearing RawPath makes Go re-encode the path from Path, which can change the byte form of other escaped segments.
			req.URL.RawPath = ""
		}
	}

	if hasSurface(cred.surfaces, surfaceQuery) {
		if v, ok := replaceWithinLimit(req.URL.RawQuery, placeholder, real, maxBodyRewriteSize); ok {
			req.URL.RawQuery = v
		}
	}

	if hasSurface(cred.surfaces, surfaceHeader) {
		for name, values := range req.Header {
			for i, v := range values {
				if replaced, ok := replaceWithinLimit(v, placeholder, real, maxBodyRewriteSize); ok {
					req.Header[name][i] = replaced
				}
			}
		}
	}

	if hasSurface(cred.surfaces, surfaceBody) && req.Body != nil {
		if req.Header.Get("Content-Encoding") != "" {
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, maxBodyRewriteSize+1))
		if err != nil {
			_ = req.Body.Close()
			return fmt.Errorf("failed to read request body for substitution: %w", err)
		}
		if len(body) > maxBodyRewriteSize {
			req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), req.Body))
			return nil
		}
		_ = req.Body.Close()
		// Forward unchanged when expanding the placeholder would push the body past the cap.
		count := bytes.Count(body, []byte(placeholder))
		if count > 0 && len(body)+count*(len(real)-len(placeholder)) > maxBodyRewriteSize {
			req.Body = io.NopCloser(bytes.NewReader(body))
			return nil
		}
		rewritten := bytes.ReplaceAll(body, []byte(placeholder), []byte(real))
		req.Body = io.NopCloser(bytes.NewReader(rewritten))
		req.ContentLength = int64(len(rewritten))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	}

	return nil
}
