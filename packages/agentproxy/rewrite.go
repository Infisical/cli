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
	maxBodyRewriteSize = 10 * 1024 * 1024 // 10 MiB
)

// applyCredentials rewrites headers and substitutes placeholder values on the outbound request.
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

// applySubstitution replaces the placeholder value with the real credential across the
// configured surfaces (header/path/query/body). Replacement is a plain substring ReplaceAll, so
// every occurrence is swapped, including where the placeholder is a prefix/substring of a longer
// token. This is safe in practice because placeholders are distinctive random strings
// (see genPlaceholder), but callers must not use short/common placeholder values.
func applySubstitution(req *http.Request, cred resolvedCredential) error {
	placeholder := cred.placeholder
	if placeholder == "" {
		return nil
	}
	real := cred.value

	if hasSurface(cred.surfaces, surfacePath) {
		req.URL.Path = strings.ReplaceAll(req.URL.Path, placeholder, real)
		req.URL.RawPath = ""
	}

	if hasSurface(cred.surfaces, surfaceQuery) {
		req.URL.RawQuery = strings.ReplaceAll(req.URL.RawQuery, placeholder, real)
	}

	if hasSurface(cred.surfaces, surfaceHeader) {
		for name, values := range req.Header {
			for i, v := range values {
				if strings.Contains(v, placeholder) {
					req.Header[name][i] = strings.ReplaceAll(v, placeholder, real)
				}
			}
		}
	}

	if hasSurface(cred.surfaces, surfaceBody) && req.Body != nil {
		// don't rewrite encoded bodies; the placeholder wouldn't be present verbatim
		if req.Header.Get("Content-Encoding") != "" {
			return nil
		}
		// read one byte past the cap to detect oversized bodies
		body, err := io.ReadAll(io.LimitReader(req.Body, maxBodyRewriteSize+1))
		if err != nil {
			_ = req.Body.Close()
			return fmt.Errorf("failed to read request body for substitution: %w", err)
		}
		if len(body) > maxBodyRewriteSize {
			// too large to safely rewrite: forward the already-buffered body unchanged rather than
			// truncating it (truncation would corrupt the request)
			req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), req.Body))
			return nil
		}
		_ = req.Body.Close()
		rewritten := bytes.ReplaceAll(body, []byte(placeholder), []byte(real))
		req.Body = io.NopCloser(bytes.NewReader(rewritten))
		req.ContentLength = int64(len(rewritten))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	}

	return nil
}
