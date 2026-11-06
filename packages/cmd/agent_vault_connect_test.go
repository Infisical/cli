package cmd

import (
	"runtime"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/util"
)

func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

func TestRunGivesTheAgentWhatConnectNeeds(t *testing.T) {
	parent := []string{
		agentVaultProxyAddressEnv + "=stale:1",
		agentVaultCaFileEnv + "=/old/ca.pem",
		"PATH=/usr/bin",
	}
	env := withAgentVaultConnectEnv(parent, "10.0.0.5:17323", "agv_new", "/data/ca-1.pem", "https://eu.infisical.com/api")

	for key, want := range map[string]string{
		agentVaultSessionTokenEnv:      "agv_new",
		agentVaultProxyAddressEnv:      "10.0.0.5:17323",
		agentVaultCaFileEnv:            "/data/ca-1.pem",
		util.INFISICAL_DOMAIN_ENV_NAME: "https://eu.infisical.com",
		"PATH":                         "/usr/bin",
	} {
		if got, _ := envValue(env, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if strings.Contains(strings.Join(env, "\n"), "stale:1") {
		t.Error("a stale proxy address from the parent reached the agent")
	}
}

func TestRunLeavesTheOperatorsDomainAndDropsAStaleCaFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("keys compare case-insensitively on Windows")
	}
	parent := []string{util.INFISICAL_DOMAIN_ENV_NAME + "=https://self.example.com", agentVaultCaFileEnv + "=/old/ca.pem"}
	env := withAgentVaultConnectEnv(parent, "p:1", "agv", "", "https://app.infisical.com/api")

	if got, _ := envValue(env, util.INFISICAL_DOMAIN_ENV_NAME); got != "https://self.example.com" {
		t.Errorf("domain = %q, want the operator's", got)
	}
	if _, ok := envValue(env, agentVaultCaFileEnv); ok {
		t.Error("a CA file from another run reached the agent under --no-ca-trust")
	}
}

func TestConnectPicksServicesByNameOrAll(t *testing.T) {
	available := []agentvault.NativeServiceInfo{{Name: "analytics", Type: "postgres"}, {Name: "bastion", Type: "ssh"}}

	picked, err := pickAgentVaultConnectServices(available, []string{"Bastion"}, false)
	if err != nil || len(picked) != 1 || picked[0].Name != "bastion" {
		t.Fatalf("picked %v, %v", picked, err)
	}
	if all, _ := pickAgentVaultConnectServices(available, nil, true); len(all) != 2 {
		t.Fatalf("--all picked %d services", len(all))
	}
	if _, err := pickAgentVaultConnectServices(available, []string{"nope"}, false); err == nil ||
		!strings.Contains(err.Error(), "analytics, bastion") {
		t.Fatalf("an unknown name gave %v, want the list of services", err)
	}
	if _, err := pickAgentVaultConnectServices(nil, nil, true); err == nil {
		t.Fatal("a session with no services wasn't refused")
	}
}

func TestConnectPrintsAReadyCommandPerService(t *testing.T) {
	for _, tc := range []struct {
		service agentvault.NativeServiceInfo
		want    string
	}{
		{agentvault.NativeServiceInfo{Type: "postgres", Database: "app"}, `psql "postgres://agent@127.0.0.1:5000/app?sslmode=disable"`},
		{agentvault.NativeServiceInfo{Type: "mysql", Database: "orders"}, "mysql -h 127.0.0.1 -P 5000 -u agent orders"},
		{agentvault.NativeServiceInfo{Type: "ssh"}, "ssh -p 5000 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null agent@127.0.0.1"},
	} {
		if got := agentVaultConnectCommand(tc.service, 5000); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.service.Type, got, tc.want)
		}
	}
}
