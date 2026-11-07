package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/fatih/color"
	"golang.org/x/net/http/httpproxy"
)

// The value Claude Code sends in the header the proxy sets. The proxy replaces it, and it keeps Claude Code from starting
// an OAuth sign-in for a server it would otherwise see as unauthenticated.
const agentVaultMCPCredentialPlaceholder = "agent-vault"

type agentVaultClaudeMCPServer struct {
	Type    string            `json:"type"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

// agentVaultClaudeMCPConfig is Claude Code's --mcp-config for the session's MCP services that are ready, as
// `claude mcp add` would add them, and the names it gives them. It is "" when there are none. leftOut says why each
// other ready MCP service isn't in it.
func agentVaultClaudeMCPConfig(services []api.AgentVaultSessionService, bypassesProxy func(rawURL string) bool) (config string, names, leftOut []string) {
	servers := map[string]agentVaultClaudeMCPServer{}
	for _, service := range services {
		parsed, err := url.Parse(service.URL)
		if service.Type != "mcp" || service.Status != "ready" || err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			continue
		}
		// Claude Code expands ${VAR} in its MCP configuration, which would send a variable from this host's
		// environment, such as the proxy URL with the session token, to the server.
		if strings.Contains(service.URL, "$") || strings.Contains(service.Credential.Header, "$") || strings.Contains(service.Name, "$") {
			leftOut = append(leftOut, quoted(service.Name, "name")+": its URL or header names an environment variable, which Claude Code would fill in")
			continue
		}
		// Claude Code honors NO_PROXY, and a server it reaches directly gets the placeholder instead of the credential.
		if bypassesProxy(service.URL) {
			leftOut = append(leftOut, quoted(service.Name, "name")+": NO_PROXY covers its host, so Claude Code would reach it without the proxy's credential")
			continue
		}
		server := agentVaultClaudeMCPServer{Type: "http", URL: service.URL}
		if service.Transport == "sse" {
			server.Type = "sse"
		}
		if header := service.Credential.Header; service.Credential.AddedByProxy && header != "" {
			server.Headers = map[string]string{header: agentVaultMCPCredentialValue(header, service.Credential.Type)}
		}
		// Services from different access bundles can share a name; each still needs its own key.
		name := service.Name
		for n := 2; servers[name].URL != ""; n++ {
			name = fmt.Sprintf("%s-%d", service.Name, n)
		}
		servers[name] = server
		names = append(names, name)
	}
	if len(servers) == 0 {
		return "", nil, leftOut
	}
	encoded, err := json.Marshal(map[string]any{"mcpServers": servers})
	if err != nil {
		return "", nil, leftOut
	}
	return string(encoded), names, leftOut
}

func agentVaultMCPCredentialValue(header, credentialType string) string {
	if !strings.EqualFold(header, "Authorization") {
		return agentVaultMCPCredentialPlaceholder
	}
	if credentialType == "basic" {
		return "Basic " + agentVaultMCPCredentialPlaceholder
	}
	return "Bearer " + agentVaultMCPCredentialPlaceholder
}

// agentVaultBypassesProxy reports whether a client honoring noProxy reaches a URL directly instead of through the proxy.
// Like Claude Code's, it never sends localhost or a loopback address through a proxy.
func agentVaultBypassesProxy(noProxy string) func(rawURL string) bool {
	proxyFor := (&httpproxy.Config{HTTPProxy: "http://agent-vault-proxy", HTTPSProxy: "http://agent-vault-proxy", NoProxy: noProxy}).ProxyFunc()
	return func(rawURL string) bool {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return true
		}
		proxy, err := proxyFor(parsed)
		return err != nil || proxy == nil
	}
}

// withAgentVaultMCPConfig puts --mcp-config=<config> right after Claude Code's command. The = form matters: the flag
// takes several values, so a separate value would also swallow a prompt passed as the first argument. Claude Code loads
// it on top of any --mcp-config the user passes.
func withAgentVaultMCPConfig(args []string, config string) []string {
	out := make([]string, 0, len(args)+1)
	out = append(out, args[0], "--mcp-config="+config)
	return append(out, args[1:]...)
}

// agentVaultRunMCPConfig gets the session's services and returns Claude Code's --mcp-config for its MCP servers, or ""
// when there are none or the list can't be read, which a warning says. quiet (--silent) leaves out the line naming the
// servers added, but not the warnings.
func agentVaultRunMCPConfig(ctx context.Context, client *agentVaultSkillsClient, bypassesProxy func(rawURL string) bool, quiet bool) string {
	listed, err := client.services(ctx)
	if err != nil {
		reason := agentVaultSkillsFailureReason(err)
		if isAgentVaultSessionInvalid(err) {
			reason = "the session is no longer valid"
		}
		util.PrintWarning(fmt.Sprintf("Starting Claude Code without the session's MCP servers: %s.", reason))
		return ""
	}
	config, names, leftOut := agentVaultClaudeMCPConfig(listed.Services, bypassesProxy)
	for _, why := range leftOut {
		util.PrintWarning("Left out the MCP server " + why + ".")
	}
	if len(names) > 0 && !quiet {
		noun := "servers"
		if len(names) == 1 {
			noun = "server"
		}
		fmt.Fprintln(util.GetStderrWriter(), color.HiBlackString(fmt.Sprintf("Added %d MCP %s to Claude Code: %s.", len(names), noun, listOf(names))))
	}
	return config
}
