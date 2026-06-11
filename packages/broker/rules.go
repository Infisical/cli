package broker

import (
	"net"
	"strconv"
	"strings"
)

type ProxyRule struct {
	Host           string          `json:"host"`
	AuthType       string          `json:"authType"`
	HeaderName     string          `json:"headerName,omitempty"`
	Username       string          `json:"username,omitempty"`
	HeaderTemplate string          `json:"headerTemplate,omitempty"`
	Substitutions  []Substitution  `json:"substitutions,omitempty"`
}

type Substitution struct {
	Key         string   `json:"key"`
	Placeholder string   `json:"placeholder"`
	In          []string `json:"in,omitempty"`
}

type ServiceEntry struct {
	SecretKey   string
	SecretValue string
	Placeholder string
	Rules       []ProxyRule
}

type ParsedRule struct {
	Host         string
	Port         int
	Path         string
	AuthType     string
	HeaderName   string
	Username     string
	HeaderTemplate string
	Substitutions []Substitution
	SecretKey    string
	SecretValue  string
	Placeholder  string
	DeclOrder    int
}

func SplitInlineHost(host string) (string, string, int) {
	pathIdx := strings.IndexByte(host, '/')
	var path string
	if pathIdx > 0 {
		path = host[pathIdx:]
		host = host[:pathIdx]
	}

	h, port := splitHostPort(host)
	return h, path, port
}

func splitHostPort(host string) (string, int) {
	idx := strings.LastIndexByte(host, ':')
	if idx < 0 {
		return host, -1
	}
	portStr := host[idx+1:]
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return host, -1
	}
	return host[:idx], p
}

func MatchRule(reqHost string, reqPort int, reqPath string, rules []ParsedRule) *ParsedRule {
	var best *ParsedRule
	var bestScore matchScore

	for i := range rules {
		r := &rules[i]
		hostTier, hostOK := matchHostPattern(r.Host, reqHost)
		if !hostOK {
			continue
		}

		portSpecific := false
		if r.Port >= 0 {
			if reqPort != r.Port {
				continue
			}
			portSpecific = true
		}

		pathLen, pathOK := matchPathGlob(r.Path, reqPath)
		if !pathOK {
			continue
		}

		score := matchScore{
			hostTier:       hostTier,
			portSpecific:   portSpecific,
			pathLiteralLen: pathLen,
			declOrder:      r.DeclOrder,
		}

		if best == nil || score.better(bestScore) {
			best = r
			bestScore = score
		}
	}
	return best
}

type matchScore struct {
	hostTier       int
	portSpecific   bool
	pathLiteralLen int
	declOrder      int
}

func (s matchScore) better(other matchScore) bool {
	if s.hostTier != other.hostTier {
		return s.hostTier < other.hostTier
	}
	if s.portSpecific != other.portSpecific {
		return s.portSpecific
	}
	if s.pathLiteralLen != other.pathLiteralLen {
		return s.pathLiteralLen > other.pathLiteralLen
	}
	return s.declOrder < other.declOrder
}

func matchHostPattern(pattern, host string) (int, bool) {
	if strings.EqualFold(pattern, host) {
		return 0, true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if strings.HasSuffix(host, suffix) {
			prefix := host[:len(host)-len(suffix)]
			if !strings.Contains(prefix, ".") && len(prefix) > 0 {
				return 1, true
			}
		}
	}
	return 0, false
}

func matchPathGlob(pattern, path string) (int, bool) {
	if pattern == "" {
		return 0, true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		if strings.HasPrefix(path, prefix) {
			return len(prefix), true
		}
		return 0, false
	}
	if pattern == path {
		return len(pattern), true
	}
	return 0, false
}

func ParseRules(entries []ServiceEntry) []ParsedRule {
	var parsed []ParsedRule
	order := 0
	for _, entry := range entries {
		for _, rule := range entry.Rules {
			host, path, port := SplitInlineHost(rule.Host)
			parsed = append(parsed, ParsedRule{
				Host:           host,
				Port:           port,
				Path:           path,
				AuthType:       rule.AuthType,
				HeaderName:     rule.HeaderName,
				Username:       rule.Username,
				HeaderTemplate: rule.HeaderTemplate,
				Substitutions:  rule.Substitutions,
				SecretKey:      entry.SecretKey,
				SecretValue:    entry.SecretValue,
				Placeholder:    entry.Placeholder,
				DeclOrder:      order,
			})
			order++
		}
	}
	return parsed
}

func ExtractHostPort(host string) (string, int) {
	h, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return host, 443
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return h, 443
	}
	return h, port
}
