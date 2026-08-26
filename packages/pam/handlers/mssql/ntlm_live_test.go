package mssql

import (
	"os"
	"testing"
)

// Live NTLM check against a real SQL Server. Skipped unless PAM_MSSQL_NTLM_HOST is set.
func TestVerifyCredentialNTLMLive(t *testing.T) {
	host := os.Getenv("PAM_MSSQL_NTLM_HOST")
	if host == "" {
		t.Skip("PAM_MSSQL_NTLM_HOST not set")
	}

	base := MssqlProxyConfig{
		TargetAddr:     host,
		InjectUsername: os.Getenv("PAM_MSSQL_NTLM_USER"),
		InjectPassword: os.Getenv("PAM_MSSQL_NTLM_PASS"),
		InjectDomain:   os.Getenv("PAM_MSSQL_NTLM_DOMAIN"),
		InjectDatabase: "master",
		AuthMethod:     "ntlm",
		SessionID:      "ntlm-live-test",
	}

	if err := VerifyCredential(base); err != nil {
		t.Fatalf("expected NTLM login to succeed, got: %v", err)
	}

	bad := base
	bad.InjectPassword = "definitely-not-the-password"
	if err := VerifyCredential(bad); err == nil {
		t.Fatal("expected a wrong password to be rejected")
	} else {
		t.Logf("wrong password correctly rejected: %v", err)
	}
}
