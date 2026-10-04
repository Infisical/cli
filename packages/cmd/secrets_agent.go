package cmd

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/sandbox"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
)

var agentSecretEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type agentSecretReference struct {
	api.AgentSecretScope
	Key string `json:"key"`
	ID  string `json:"id"`
	Ref string `json:"ref"`
}

func newAgentSecretReference(scope api.AgentSecretScope, secret api.AgentSecretMetadata) agentSecretReference {
	query := url.Values{
		"environment": {scope.Environment}, "path": {scope.Path}, "key": {secret.Key},
		"domain": {config.INFISICAL_URL},
	}
	reference := url.URL{Scheme: "infisical", Host: scope.ProjectID, Path: "/" + secret.ID, RawQuery: query.Encode()}
	return agentSecretReference{scope, secret.Key, secret.ID, reference.String()}
}

func parseAgentSecretReference(input string) (agentSecretReference, error) {
	reference, err := url.Parse(input)
	if err != nil || reference.Scheme != "infisical" || reference.Host == "" || reference.User != nil || reference.Fragment != "" {
		return agentSecretReference{}, errors.New("invalid secret reference; use a reference returned by find or save")
	}
	query, err := url.ParseQuery(reference.RawQuery)
	if err != nil || len(query) != 4 {
		return agentSecretReference{}, errors.New("invalid secret reference parameters")
	}
	for _, name := range []string{"environment", "path", "key", "domain"} {
		if len(query[name]) != 1 || query.Get(name) == "" {
			return agentSecretReference{}, errors.New("secret reference is missing its location")
		}
	}
	referenceDomain, domainErr := url.Parse(query.Get("domain"))
	selectedDomain, selectedErr := url.Parse(config.INFISICAL_URL)
	if domainErr != nil || selectedErr != nil || referenceDomain.User != nil || referenceDomain.Fragment != "" ||
		!strings.EqualFold(referenceDomain.Scheme, selectedDomain.Scheme) || !strings.EqualFold(referenceDomain.Host, selectedDomain.Host) ||
		referenceDomain.EscapedPath() != selectedDomain.EscapedPath() || referenceDomain.RawQuery != selectedDomain.RawQuery {
		return agentSecretReference{}, errors.New("this reference belongs to a different Infisical instance; select its domain explicitly")
	}
	id := strings.TrimPrefix(reference.Path, "/")
	if id == "" || strings.Contains(id, "/") || !strings.HasPrefix(query.Get("path"), "/") {
		return agentSecretReference{}, errors.New("invalid secret reference location")
	}
	return agentSecretReference{
		AgentSecretScope: api.AgentSecretScope{ProjectID: reference.Host, Environment: query.Get("environment"), Path: query.Get("path")},
		Key:              query.Get("key"), ID: id, Ref: input,
	}, nil
}

func agentSecretsClient(cmd *cobra.Command) (*resty.Client, error) {
	token, err := util.GetInfisicalToken(cmd)
	if err != nil {
		return nil, errors.New("could not load authentication")
	}
	accessToken := ""
	if token != nil {
		if token.Type == util.SERVICE_TOKEN_IDENTIFIER {
			return nil, errors.New("agent secret commands require a user login or machine identity, not a legacy service token")
		}
		accessToken = token.Token
	} else {
		details, err := util.GetCurrentLoggedInUserDetails(true)
		if err != nil || !details.IsUserLoggedIn || details.LoginExpired {
			return nil, errors.New("run infisical login or set INFISICAL_TOKEN to a machine identity access token")
		}
		accessToken = details.UserCredentials.JTWToken
	}
	if accessToken == "" {
		return nil, errors.New("no Infisical access token is available")
	}
	client, err := util.GetRestyClientWithPolicy(util.RetryPolicy{})
	if err != nil {
		return nil, errors.New("could not configure the HTTP client; check INFISICAL_CUSTOM_HEADERS")
	}
	client.SetAuthToken(accessToken).SetDebug(false).SetRedirectPolicy(resty.NoRedirectPolicy()).SetTimeout(30 * time.Second)
	return client, nil
}

func agentSecretsScope(cmd *cobra.Command) (api.AgentSecretScope, error) {
	projectID, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "projectId", []string{util.INFISICAL_PROJECT_ID_NAME}, "")
	if err != nil {
		return api.AgentSecretScope{}, err
	}
	environment, _ := cmd.Flags().GetString("env")
	path, _ := cmd.Flags().GetString("path")
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(environment) == "" {
		return api.AgentSecretScope{}, errors.New("select a project with --projectId or INFISICAL_PROJECT_ID and an environment with --env")
	}
	if !strings.HasPrefix(path, "/") || strings.TrimSpace(path) != path {
		return api.AgentSecretScope{}, errors.New("--path must be an absolute secret folder path")
	}
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}
	return api.AgentSecretScope{ProjectID: strings.TrimSpace(projectID), Environment: strings.TrimSpace(environment), Path: path}, nil
}

func findAgentSecrets(cmd *cobra.Command, queries []string) error {
	scope, err := agentSecretsScope(cmd)
	if err != nil {
		return err
	}
	client, err := agentSecretsClient(cmd)
	if err != nil {
		return err
	}
	secrets, err := api.FindAgentSecrets(client, scope)
	if err != nil {
		return err
	}
	matches := make([]agentSecretReference, 0)
	for _, secret := range secrets {
		if secret.Type != "shared" || secret.ID == "" || secret.Key == "" {
			continue
		}
		matched := len(queries) == 0
		for _, query := range queries {
			if strings.Contains(strings.ToLower(secret.Key), strings.ToLower(query)) {
				matched = true
			}
		}
		if matched {
			matches = append(matches, newAgentSecretReference(scope, secret))
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Key < matches[j].Key })
	return json.NewEncoder(cmd.OutOrStdout()).Encode(matches)
}

func runAgentSecrets(cmd *cobra.Command, args []string) error {
	assignments, _ := cmd.Flags().GetStringArray("secret")
	if len(assignments) == 0 {
		return errors.New("provide at least one --secret ENV_NAME=reference")
	}
	references := make(map[string]agentSecretReference, len(assignments))
	for _, assignment := range assignments {
		parts := strings.SplitN(assignment, "=", 2)
		if len(parts) != 2 || !agentSecretEnvName.MatchString(parts[0]) {
			return errors.New("--secret must be ENV_NAME=reference with a valid environment variable name")
		}
		if agentSecretAuthVariable(parts[0]) {
			return errors.New("Infisical CLI environment variables cannot be used as injection targets")
		}
		if _, exists := references[parts[0]]; exists {
			return errors.New("each environment variable may be assigned only once")
		}
		reference, err := parseAgentSecretReference(parts[1])
		if err != nil {
			return err
		}
		references[parts[0]] = reference
	}
	client, err := agentSecretsClient(cmd)
	if err != nil {
		return err
	}
	values := make(map[string]string, len(references))
	for name, reference := range references {
		secret, err := api.ReadAgentSecret(client, reference.AgentSecretScope, reference.Key, true)
		if err != nil {
			return err
		}
		if secret.ID != reference.ID {
			return errors.New("the referenced secret was replaced or overridden; use find to select it again")
		}
		if strings.ContainsRune(*secret.Value, '\x00') {
			return errors.New("a secret contains a NUL character and cannot be injected into an environment variable")
		}
		values[name] = *secret.Value
	}
	environment := make([]string, 0, len(os.Environ())+len(values))
	for _, assignment := range os.Environ() {
		name, _, _ := strings.Cut(assignment, "=")
		if _, replaced := values[name]; replaced || agentSecretAuthVariable(name) {
			continue
		}
		environment = append(environment, assignment)
	}
	for name, value := range values {
		environment = append(environment, name+"="+value)
	}
	child := exec.CommandContext(cmd.Context(), args[0], args[1:]...)
	child.Env = environment
	child.Stdin, child.Stdout, child.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
	if err := child.Start(); err != nil {
		return errors.New("could not start the requested command")
	}
	stopForwarding := sandbox.ForwardTerminationSignals(child)
	err = child.Wait()
	stopForwarding()
	if err != nil {
		if code, ok := sandbox.WaitExitCode(err); ok {
			os.Exit(code)
		}
		return errors.New("could not start the requested command")
	}
	return nil
}

func agentSecretAuthVariable(name string) bool {
	return strings.HasPrefix(strings.ToUpper(name), "INFISICAL_") || strings.EqualFold(name, "TOKEN")
}

func saveAgentSecret(cmd *cobra.Command, args []string) error {
	stdin, _ := cmd.Flags().GetBool("stdin")
	if !stdin || !agentSecretEnvName.MatchString(args[0]) {
		return errors.New("use save SECRET_NAME --stdin with a valid secret name; values are never accepted as arguments")
	}
	scope, err := agentSecretsScope(cmd)
	if err != nil {
		return err
	}
	input, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 1024*1024+1))
	if err != nil || len(input) > 1024*1024 || !utf8.Valid(input) {
		return errors.New("could not read stdin; provide UTF-8 input of at most 1 MiB")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(input), "\n"), "\r")
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') {
		return errors.New("provide a nonempty secret without NUL characters or surrounding whitespace; one final stdin line ending is removed")
	}
	client, err := agentSecretsClient(cmd)
	if err != nil {
		return err
	}
	created, err := api.CreateAgentSecret(client, scope, args[0], value)
	if err != nil {
		return err
	}
	if created.Key != args[0] || created.Type != "shared" {
		return errors.New("the write returned an unexpected secret and is not verified; use find before attempting another write")
	}
	stored, err := api.ReadAgentSecret(client, scope, args[0], false)
	if err != nil || stored.ID != created.ID || stored.Value == nil || subtle.ConstantTimeCompare([]byte(*stored.Value), []byte(value)) != 1 {
		return errors.New("the write occurred but could not be verified; use find to inspect the location, do not retry the write")
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
		agentSecretReference
		Verified bool `json:"verified"`
	}{newAgentSecretReference(scope, created), true})
}

func init() {
	agent := &cobra.Command{
		Use: "agent", Short: "Find, use, and save secret references without printing values",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			_ = cmd.Flags().Set("silent", "true")
			RootCmd.PersistentPreRun(cmd, args)
		},
		SilenceUsage: true,
	}
	agent.PersistentFlags().String("token", "", "machine identity access token (prefer INFISICAL_TOKEN)")
	agent.PersistentFlags().String("projectId", "", "project ID for find and save")
	agent.PersistentFlags().String("env", "", "explicit environment for find and save")
	agent.PersistentFlags().String("path", "/", "secret folder for find and save")
	find := &cobra.Command{Use: "find [queries...]", Short: "Find shared secret names and references, never values", RunE: findAgentSecrets}
	run := &cobra.Command{
		Use: "run --secret ENV_NAME=reference -- command [args...]", Args: cobra.MinimumNArgs(1),
		Short: "Inject selected secrets into a trusted command, without writing an env file",
		Long:  "Inject selected secrets into a trusted command. The child receives plaintext values and can print them. This is not an agent sandbox; use Agent Vault or the agent proxy for credential-free agents.",
		RunE:  runAgentSecrets,
	}
	run.Flags().StringArray("secret", nil, "ENV_NAME=reference (repeat for each secret)")
	save := &cobra.Command{Use: "save SECRET_NAME --stdin", Args: cobra.ExactArgs(1), Short: "Create a shared secret from stdin and verify it without printing its value", RunE: saveAgentSecret}
	save.Flags().Bool("stdin", false, "read the new credential from stdin, never an argument")
	agent.AddCommand(find, run, save)
	secretsCmd.AddCommand(agent)
}
