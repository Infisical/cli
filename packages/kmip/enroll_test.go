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

func TestResolveAwsRefreshServerIDEdgeCases(t *testing.T) {
	t.Run("never enrolled", func(t *testing.T) {
		name := "probe-absent"
		defer cleanup(t, name)
		if _, aws := ResolveAwsRefreshServerID(name); aws {
			t.Fatal("a server with no config must not refresh")
		}
	})

	t.Run("aws method recorded but no server id", func(t *testing.T) {
		name := "probe-aws-no-id"
		defer cleanup(t, name)
		if err := SaveEnrollMethod(name, EnrollMethodAws); err != nil {
			t.Fatal(err)
		}
		if _, aws := ResolveAwsRefreshServerID(name); aws {
			t.Fatal("there is nothing to re-authenticate with without a server id")
		}
	})

	t.Run("stale server id from a previous aws enrollment", func(t *testing.T) {
		name := "probe-reenrolled"
		defer cleanup(t, name)
		if err := SaveServerID(name, "srv-old-aws"); err != nil {
			t.Fatal(err)
		}
		if err := SaveEnrollMethod(name, EnrollMethodToken); err != nil {
			t.Fatal(err)
		}
		if _, aws := ResolveAwsRefreshServerID(name); aws {
			t.Fatal("a token re-enrollment must not keep refreshing via the old aws server id")
		}
	})

	t.Run("env server id differs from the recorded one", func(t *testing.T) {
		name := "probe-env-differs"
		defer cleanup(t, name)
		if err := SaveEnrollMethod(name, EnrollMethodAws); err != nil {
			t.Fatal(err)
		}
		if err := SaveServerID(name, "srv-recorded"); err != nil {
			t.Fatal(err)
		}
		t.Setenv(INFISICAL_KMIP_SERVER_ID_KEY, "srv-from-environment")
		id, aws := ResolveAwsRefreshServerID(name)
		if !aws || id != "srv-recorded" {
			t.Fatalf("must re-authenticate as the recorded server, got id=%q aws=%v", id, aws)
		}
	})

	t.Run("unrecognised method", func(t *testing.T) {
		name := "probe-unknown"
		defer cleanup(t, name)
		if err := SaveEnrollMethod(name, "kubernetes"); err != nil {
			t.Fatal(err)
		}
		if err := SaveServerID(name, "srv-x"); err != nil {
			t.Fatal(err)
		}
		if _, aws := ResolveAwsRefreshServerID(name); aws {
			t.Fatal("only aws enrollment refreshes via STS")
		}
	})

	t.Run("method is overwritten on re-enrollment", func(t *testing.T) {
		name := "probe-overwrite"
		defer cleanup(t, name)
		if err := SaveEnrollMethod(name, EnrollMethodToken); err != nil {
			t.Fatal(err)
		}
		if err := SaveEnrollMethod(name, EnrollMethodAws); err != nil {
			t.Fatal(err)
		}
		if err := SaveServerID(name, "srv-now-aws"); err != nil {
			t.Fatal(err)
		}
		if got, _ := LoadStoredEnrollMethod(name); got != EnrollMethodAws {
			t.Fatalf("re-enrollment should replace the method, got %q", got)
		}
		if id, aws := ResolveAwsRefreshServerID(name); !aws || id != "srv-now-aws" {
			t.Fatalf("expected refresh as srv-now-aws, got id=%q aws=%v", id, aws)
		}
	})
}
