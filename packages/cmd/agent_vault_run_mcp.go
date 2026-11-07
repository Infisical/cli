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
// `claude mcp add` would add them, and the names it gives them. It is "" when there are none.
func agentVaultClaudeMCPConfig(services []api.AgentVaultSessionService) (config string, names []string) {
	servers := map[string]agentVaultClaudeMCPServer{}
	for _, service := range services {
		parsed, err := url.Parse(service.URL)
		if service.Type != "mcp" || service.Status != "ready" || err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
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
		return "", nil
	}
	encoded, err := json.Marshal(map[string]any{"mcpServers": servers})
	if err != nil {
		return "", nil
	}
	return string(encoded), names
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

// withAgentVaultMCPConfig puts --mcp-config=<config> right after Claude Code's command. The = form matters: the flag
// takes several values, so a separate value would also swallow a prompt passed as the first argument. Claude Code loads
// it on top of any --mcp-config the user passes.
func withAgentVaultMCPConfig(args []string, config string) []string {
	out := make([]string, 0, len(args)+1)
	out = append(out, args[0], "--mcp-config="+config)
	return append(out, args[1:]...)
}

// agentVaultRunMCPConfig gets the session's services and returns Claude Code's --mcp-config for its MCP servers, or ""
// when there are none or the list can't be read, which a warning says.
func agentVaultRunMCPConfig(ctx context.Context, client *agentVaultSkillsClient) string {
	listed, err := client.services(ctx)
	if err != nil {
		reason := agentVaultSkillsFailureReason(err)
		if isAgentVaultSessionInvalid(err) {
			reason = "the session is no longer valid"
		}
		util.PrintWarning(fmt.Sprintf("Starting Claude Code without the session's MCP servers: %s.", reason))
		return ""
	}
	config, names := agentVaultClaudeMCPConfig(listed.Services)
	if len(names) > 0 {
		noun := "servers"
		if len(names) == 1 {
			noun = "server"
		}
		fmt.Fprintln(util.GetStderrWriter(), color.HiBlackString(fmt.Sprintf("Added %d MCP %s to Claude Code: %s.", len(names), noun, strings.Join(names, ", "))))
	}
	return config
}
