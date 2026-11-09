package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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
		if service.Type != "mcp" || err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			continue
		}
		if service.Status != "ready" {
			leftOut = append(leftOut, quoted(service.Name, "name")+": set up your personal values for it in Agent Vault first")
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

// withAgentVaultMCPConfig puts --mcp-config=<path> right after Claude Code's command. The = form matters: the flag
// takes several values, so a separate value would also swallow a prompt passed as the first argument. Claude Code loads
// it on top of any --mcp-config the user passes.
func withAgentVaultMCPConfig(args []string, path string) []string {
	out := make([]string, 0, len(args)+1)
	out = append(out, args[0], "--mcp-config="+path)
	return append(out, args[1:]...)
}

// What cmd.exe leaves alone in an argument. On Windows, npm installs Claude Code as claude.cmd, which runs through
// cmd.exe, and cmd.exe reads |, &, ^ and %NAME% in its arguments even inside quotes.
var agentVaultCmdExeSafePath = regexp.MustCompile(`^[A-Za-z0-9_.:\\/~ -]+$`)

// agentVaultIsBatchFile reports whether a command resolved to path on goos runs through cmd.exe.
func agentVaultIsBatchFile(goos, path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return goos == "windows" && (ext == ".cmd" || ext == ".bat")
}

// Names no path: the temporary folder comes from the environment, which the CLI never repeats in a message.
var errAgentVaultMCPConfigUnwritable = errors.New("their configuration couldn't be written to the temporary folder")

// writeAgentVaultMCPConfig writes Claude Code's --mcp-config to a file only this user can read, and returns its path and
// a function that removes it. The JSON goes in a file, never on the command line, where cmd.exe would read an admin's
// server URL or header name as part of a command; the file's path has to be safe for cmd.exe too.
func writeAgentVaultMCPConfig(command, config string) (string, func(), error) {
	file, err := os.CreateTemp("", "agent-vault-mcp-*.json")
	if err != nil {
		return "", nil, errAgentVaultMCPConfigUnwritable
	}
	path := file.Name()
	remove := func() { _ = os.Remove(path) }
	_, err = file.WriteString(config)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		remove()
		return "", nil, errAgentVaultMCPConfigUnwritable
	}
	if resolved, lookErr := exec.LookPath(command); lookErr == nil && agentVaultIsBatchFile(runtime.GOOS, resolved) && !agentVaultCmdExeSafePath.MatchString(path) {
		remove()
		return "", nil, errors.New("the temporary folder's path has characters that cmd.exe, which runs Claude Code here, would read as part of a command")
	}
	return path, remove, nil
}

// agentVaultRunMCPConfig gets the session's services and writes Claude Code's --mcp-config for its MCP servers to a file
// for command, returning its path and a function that removes it. The path is "" when there are none, or when the list
// can't be read or the file written, which a warning says. quiet (--silent) leaves out the line naming the servers
// added, but not the warnings.
func agentVaultRunMCPConfig(ctx context.Context, client *agentVaultSkillsClient, bypassesProxy func(rawURL string) bool, quiet bool, command string) (string, func()) {
	listed, err := client.services(ctx)
	if err != nil {
		reason := agentVaultSkillsFailureReason(err)
		if isAgentVaultSessionInvalid(err) {
			reason = "the session is no longer valid"
		}
		util.PrintWarning(fmt.Sprintf("Starting Claude Code without the session's MCP servers: %s.", reason))
		return "", nil
	}
	config, names, leftOut := agentVaultClaudeMCPConfig(listed.Services, bypassesProxy)
	for _, why := range leftOut {
		util.PrintWarning("Left out the MCP server " + why + ".")
	}
	if config == "" {
		return "", nil
	}
	path, remove, err := writeAgentVaultMCPConfig(command, config)
	if err != nil {
		util.PrintWarning(fmt.Sprintf("Starting Claude Code without the session's MCP servers: %v.", err))
		return "", nil
	}
	if !quiet {
		noun := "servers"
		if len(names) == 1 {
			noun = "server"
		}
		fmt.Fprintln(util.GetStderrWriter(), color.HiBlackString(fmt.Sprintf("Added %d MCP %s to Claude Code: %s.", len(names), noun, listOf(names))))
	}
	return path, remove
}
