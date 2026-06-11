package broker

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

func InjectAuth(req *http.Request, rule *ParsedRule) {
	switch rule.AuthType {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+rule.SecretValue)
	case "basic":
		credentials := rule.SecretValue
		if rule.Username != "" {
			credentials = rule.Username + ":" + rule.SecretValue
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		req.Header.Set("Authorization", "Basic "+encoded)
	case "api-key":
		header := rule.HeaderName
		if header == "" {
			return
		}
		req.Header.Set(header, rule.SecretValue)
	case "custom":
		if rule.HeaderTemplate != "" {
			parts := strings.SplitN(rule.HeaderTemplate, ":", 2)
			if len(parts) == 2 {
				headerName := strings.TrimSpace(parts[0])
				headerValue := strings.TrimSpace(parts[1])
				headerValue = strings.ReplaceAll(headerValue, "{{ VALUE }}", rule.SecretValue)
				headerValue = strings.ReplaceAll(headerValue, "{{VALUE}}", rule.SecretValue)
				req.Header.Set(headerName, headerValue)
			}
		}
	case "passthrough":
		// no credential injection
	}

	ApplySubstitutions(req, rule)
}

func ApplySubstitutions(req *http.Request, rule *ParsedRule) {
	for _, sub := range rule.Substitutions {
		surfaces := sub.In
		if len(surfaces) == 0 {
			surfaces = []string{"path", "query"}
		}

		for _, surface := range surfaces {
			switch surface {
			case "path":
				req.URL.Path = strings.ReplaceAll(req.URL.Path, sub.Placeholder, rule.SecretValue)
			case "query":
				req.URL.RawQuery = strings.ReplaceAll(req.URL.RawQuery, sub.Placeholder, rule.SecretValue)
			case "header":
				for key, values := range req.Header {
					for i, v := range values {
						if strings.Contains(v, sub.Placeholder) {
							req.Header[key][i] = strings.ReplaceAll(v, sub.Placeholder, rule.SecretValue)
						}
					}
				}
			case "body":
				// body substitution requires buffering -- simplified for PoC
				if req.Body != nil && req.ContentLength > 0 {
					bodyBytes := make([]byte, req.ContentLength)
					n, err := req.Body.Read(bodyBytes)
					if err == nil || n > 0 {
						body := strings.ReplaceAll(string(bodyBytes[:n]), sub.Placeholder, rule.SecretValue)
						req.Body = nopCloser(strings.NewReader(body))
						req.ContentLength = int64(len(body))
					}
				}
			}
		}
	}
}

type nopCloserReader struct {
	*strings.Reader
}

func (nopCloserReader) Close() error { return nil }

func nopCloser(r *strings.Reader) *nopCloserReader {
	return &nopCloserReader{r}
}

func FormatProposalHint(host string) string {
	return fmt.Sprintf(
		`{"error":"forbidden","message":"No proxy rule matching host '%s'","proposal_hint":{"host":"%s","supported_auth_types":["bearer","basic","api-key","custom","passthrough"]}}`,
		host, host,
	)
}
