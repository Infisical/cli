package kmip

import "os"
import "testing"

func cleanup(t *testing.T, name string) {
	t.Helper()
	if p, err := kmipConfPath(name); err == nil {
		_ = os.Remove(p)
	}
}

func TestAwsRefreshOnlyForAwsEnrolledServers(t *testing.T) {
	// The review finding: token-enrolled, but the environment carries a server ID.
	t.Run("token enrolled with env server id", func(t *testing.T) {
		name := "probe-token"
		defer cleanup(t, name)
		if err := SaveEnrollMethod(name, EnrollMethodToken); err != nil {
			t.Fatal(err)
		}
		t.Setenv(INFISICAL_KMIP_SERVER_ID_KEY, "srv-from-environment")
		if _, aws := ResolveAwsRefreshServerID(name); aws {
			t.Fatal("token-enrolled server must not be wired for STS refresh")
		}
	})

	t.Run("aws enrolled", func(t *testing.T) {
		name := "probe-aws"
		defer cleanup(t, name)
		if err := SaveEnrollMethod(name, EnrollMethodAws); err != nil {
			t.Fatal(err)
		}
		if err := SaveServerID(name, "srv-real"); err != nil {
			t.Fatal(err)
		}
		id, aws := ResolveAwsRefreshServerID(name)
		if !aws || id != "srv-real" {
			t.Fatalf("aws-enrolled server should refresh via STS, got id=%q aws=%v", id, aws)
		}
	})

	// Enrolled before the method was recorded: must keep working.
	t.Run("legacy aws enrolled without a recorded method", func(t *testing.T) {
		name := "probe-legacy"
		defer cleanup(t, name)
		if err := SaveServerID(name, "srv-legacy"); err != nil {
			t.Fatal(err)
		}
		id, aws := ResolveAwsRefreshServerID(name)
		if !aws || id != "srv-legacy" {
			t.Fatalf("legacy aws server should still refresh, got id=%q aws=%v", id, aws)
		}
	})

	// A legacy token-enrolled server has no server ID in the conf file, only the env var.
	t.Run("legacy token enrolled with env server id", func(t *testing.T) {
		name := "probe-legacy-token"
		defer cleanup(t, name)
		if err := SaveEnrollmentToken(name, "tok"); err != nil {
			t.Fatal(err)
		}
		t.Setenv(INFISICAL_KMIP_SERVER_ID_KEY, "srv-from-environment")
		if _, aws := ResolveAwsRefreshServerID(name); aws {
			t.Fatal("env var must not make a legacy token-enrolled server look aws-enrolled")
		}
	})
}
