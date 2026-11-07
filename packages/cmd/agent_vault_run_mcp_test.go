package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/go-resty/resty/v2"
)

func mcpService(name, url, transport, status string, credential api.AgentVaultSessionServiceCredential) api.AgentVaultSessionService {
	return api.AgentVaultSessionService{Name: name, Type: "mcp", URL: url, Transport: transport, Status: status, Credential: credential}
}

var bearerByProxy = api.AgentVaultSessionServiceCredential{Type: "bearer", Header: "Authorization", AddedByProxy: true}

func TestTheSessionsReadyMCPServersBecomeClaudeCodesConfig(t *testing.T) {
	services := []api.AgentVaultSessionService{
		mcpService("linear", "https://mcp.linear.app/mcp", "streamable-http", "ready", bearerByProxy),
		mcpService("legacy", "https://mcp.example.com/sse", "sse", "ready",
			api.AgentVaultSessionServiceCredential{Type: "oauth", Header: "Authorization", AddedByProxy: true}),
		mcpService("keyed", "https://mcp.keyed.example/mcp", "streamable-http", "ready",
			api.AgentVaultSessionServiceCredential{Type: "bearer", Header: "X-Api-Key", AddedByProxy: true}),
		mcpService("open", "https://mcp.open.example/mcp", "streamable-http", "ready", api.AgentVaultSessionServiceCredential{Type: "none"}),
		mcpService("waiting", "https://mcp.waiting.example/mcp", "streamable-http", "needs-personal-values", bearerByProxy),
		{Name: "github", Type: "http", URL: "https://api.github.com", Status: "ready", Credential: bearerByProxy},
		mcpService("linear", "https://mcp.linear.app/other", "streamable-http", "ready", bearerByProxy),
		mcpService("local-file", "file:///etc/passwd", "streamable-http", "ready", bearerByProxy),
	}
	config, names := agentVaultClaudeMCPConfig(services)
	if want := []string{"linear", "legacy", "keyed", "open", "linear-2"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("names %v, want %v", names, want)
	}
	var parsed struct {
		MCPServers map[string]agentVaultClaudeMCPServer `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(config), &parsed); err != nil {
		t.Fatalf("config %q: %v", config, err)
	}
	want := map[string]agentVaultClaudeMCPServer{
		"linear":   {Type: "http", URL: "https://mcp.linear.app/mcp", Headers: map[string]string{"Authorization": "Bearer agent-vault"}},
		"legacy":   {Type: "sse", URL: "https://mcp.example.com/sse", Headers: map[string]string{"Authorization": "Bearer agent-vault"}},
		"keyed":    {Type: "http", URL: "https://mcp.keyed.example/mcp", Headers: map[string]string{"X-Api-Key": "agent-vault"}},
		"open":     {Type: "http", URL: "https://mcp.open.example/mcp"},
		"linear-2": {Type: "http", URL: "https://mcp.linear.app/other", Headers: map[string]string{"Authorization": "Bearer agent-vault"}},
	}
	if !reflect.DeepEqual(parsed.MCPServers, want) {
		t.Fatalf("servers %+v, want %+v", parsed.MCPServers, want)
	}
}

func TestASessionWithoutMCPServersAddsNoConfig(t *testing.T) {
	config, names := agentVaultClaudeMCPConfig([]api.AgentVaultSessionService{
		{Name: "github", Type: "http", URL: "https://api.github.com", Status: "ready", Credential: bearerByProxy},
	})
	if config != "" || names != nil {
		t.Fatalf("config %q, names %v", config, names)
	}
}

// The flag takes several values, so a separate value would also take a prompt passed as the first argument.
func TestTheMCPConfigGoesInWithoutTakingThePrompt(t *testing.T) {
	got := withAgentVaultMCPConfig([]string{"claude", "fix the bug", "--model", "opus"}, `{"mcpServers":{}}`)
	want := []string{"claude", `--mcp-config={"mcpServers":{}}`, "fix the bug", "--model", "opus"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args %q, want %q", got, want)
	}
}

func listMCPServersThrough(config *string) agentVaultRunProxyStep {
	return func(ctx context.Context, tunnel *agentVaultSkillsTunnel, proxyTooOld bool) {
		*config = agentVaultRunMCPConfig(ctx, &agentVaultSkillsClient{httpClient: resty.New(), sessionToken: "agv_tok", tunnel: tunnel, proxyTooOld: proxyTooOld})
	}
}

func TestRunGetsClaudeCodesMCPServersThroughTheProxy(t *testing.T) {
	warnings := captureWarnings(t)
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusOK, api.ListAgentVaultSessionServicesResponse{
		Services: []api.AgentVaultSessionService{mcpService("linear", "https://mcp.linear.app/mcp", "streamable-http", "ready", bearerByProxy)},
	})

	var config string
	apiURL := prepareAgentVaultRunProxy(context.Background(), proxy.addr, "agv_tok", proxy.caPEM, nil, listMCPServersThrough(&config))
	if !strings.Contains(config, `"linear":{"type":"http","url":"https://mcp.linear.app/mcp","headers":{"Authorization":"Bearer agent-vault"}}`) {
		t.Fatalf("config %q", config)
	}
	// The services list's answer from inside TLS confirms the API URL, so no separate question is needed.
	if apiURL != testProxyAPIURL || proxy.requests.Load() != 1 || proxy.lastRequest.Load() != "GET /api/v1/agent-vault/session/services" {
		t.Fatalf("API URL %q, %d requests, last %v", apiURL, proxy.requests.Load(), proxy.lastRequest.Load())
	}
	if !strings.Contains(warnings.String(), "Added 1 MCP server to Claude Code: linear.") {
		t.Fatalf("printed %q", warnings.String())
	}
}

func TestAServicesListThatCantBeReadStartsClaudeCodeWithoutThem(t *testing.T) {
	warnings := captureWarnings(t)
	proxy := newFakeTunnelProxy(t, "forwards", http.StatusBadGateway,
		map[string]any{"error": "infisical_unreachable", "message": "the proxy could not reach Infisical"})

	var config string
	prepareAgentVaultRunProxy(context.Background(), proxy.addr, "agv_tok", proxy.caPEM, nil, listMCPServersThrough(&config))
	if config != "" || !strings.Contains(warnings.String(), "Starting Claude Code without the session's MCP servers: the proxy could not reach Infisical.") {
		t.Fatalf("config %q, warned %q", config, warnings.String())
	}
}

// Behind a proxy that names no Infisical, the list comes from Infisical directly, as the skills do.
func TestAnOldProxysSessionGetsItsMCPServersFromInfisical(t *testing.T) {
	isolateSkillsHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent-vault/session/services" || r.Header.Get("Authorization") != "Bearer agv_tok" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.ListAgentVaultSessionServicesResponse{
			Services: []api.AgentVaultSessionService{mcpService("notion", "https://mcp.notion.com/mcp", "streamable-http", "ready", bearerByProxy)},
		})
	}))
	defer srv.Close()
	useInfisicalURL(t, srv.URL+"/api")
	proxy := newFakeTunnelProxy(t, "old", 0, nil)

	var config string
	prepareAgentVaultRunProxy(context.Background(), proxy.addr, "agv_tok", proxy.caPEM, nil, listMCPServersThrough(&config))
	if !strings.Contains(config, `"notion":{"type":"http","url":"https://mcp.notion.com/mcp"`) || proxy.requests.Load() != 0 {
		t.Fatalf("config %q, %d requests through the old proxy", config, proxy.requests.Load())
	}
}
