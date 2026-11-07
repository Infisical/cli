package cmd

import (
	"github.com/Infisical/infisical-merge/packages/pam/handlers/webapp"
	"strings"
	"testing"
)

func TestGatewayBrowserOptions(t *testing.T) {
	names := []string{"image", "egress-network", "memory", "cpus", "spool-max-bytes", "max-sessions"}
	for _, name := range names {
		t.Setenv("INFISICAL_PAM_BROWSER_"+strings.ToUpper(strings.ReplaceAll(name, "-", "_")), "")
	}
	defaults, err := gatewayBrowserOptions(gatewayStartCmd)
	if err != nil || defaults != webapp.DefaultOptions() {
		t.Fatalf("omitted flags: %+v, %v", defaults, err)
	}
	for _, name := range names {
		f := gatewayStartCmd.Flags().Lookup("pam-browser-" + name)
		original, changed := f.Value.String(), f.Changed
		t.Cleanup(func() { _ = f.Value.Set(original); f.Changed = changed })
	}
	values := []string{"task-image", "task-network", "2g", "1.5", "123456789", "7"}
	for i, name := range names {
		t.Setenv("INFISICAL_PAM_BROWSER_"+strings.ToUpper(strings.ReplaceAll(name, "-", "_")), values[i])
	}
	env, err := gatewayBrowserOptions(gatewayStartCmd)
	if err != nil || env.Image != "task-image" || env.EgressNetwork != "task-network" || env.Memory != "2g" || env.CPUs != "1.5" || env.SpoolMaxBytes != 123456789 || env.MaxSessions != 7 {
		t.Fatalf("environment: %+v, %v", env, err)
	}
	values = []string{"explicit-image", "explicit-network", "3g", "2.0", "2147483648", "4"}
	for i, name := range names {
		if err := gatewayStartCmd.Flags().Set("pam-browser-"+name, values[i]); err != nil {
			t.Fatal(err)
		}
	}
	explicit, err := gatewayBrowserOptions(gatewayStartCmd)
	if err != nil || explicit.Image != "explicit-image" || explicit.EgressNetwork != "explicit-network" || explicit.Memory != "3g" || explicit.CPUs != "2.0" || explicit.SpoolMaxBytes != 2147483648 || explicit.MaxSessions != 4 {
		t.Fatalf("typed explicit flags: %+v, %v", explicit, err)
	}
}
