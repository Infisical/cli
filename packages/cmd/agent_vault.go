package cmd

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/Infisical/infisical-merge/packages/agentvault"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/posthog/posthog-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// Top-level, beside gateway / relay / pam: the existing `infisical secrets agent-proxy` tree is a
// different product.
var agentVaultCmd = &cobra.Command{
	Use:     "agent-vault",
	Aliases: []string{"av"},
	Short:   "Agent Vault commands",
	Long:    "Run agents that hold no credentials, with a proxy that attaches them at the network boundary",
}

var agentVaultProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run an Agent Vault proxy",
	Long: `Run an Agent Vault proxy.

The proxy decides per request whether a host is allowed and attaches the real credential on the way out,
so the agent never holds a secret.

Start the proxy with the proxy token shown when it was created or its token was last rotated. You can run
it on as many machines as you need with one token: each loads its settings and certificate authority from
Infisical when it starts. On a shared host, pass the token in INFISICAL_AGENT_VAULT_PROXY_TOKEN rather than --proxy-token,
which other users can read from the process list:

  INFISICAL_AGENT_VAULT_PROXY_TOKEN=... infisical agent-vault proxy

After each start the proxy saves its settings and certificate authority under --data-dir, when that
directory is writable, and uses them only if Infisical can't be reached on a later start with the same
token.

Infisical issues the certificate authority the proxy serves. To serve your own instead, pass --ca-cert
and --ca-key, each as a PEM, the base64 of a PEM, or a file path.

The proxy also accepts SOCKS5 over TLS on a second port, for clients such as E2B that send a sandbox's
traffic to the proxy from outside the sandbox, with the session token as the password. Pass --socks5-port
and --socks5-tls-name, the name clients reach the proxy by; the proxy makes the port's certificate from its
certificate authority. To use your own certificate instead, pass --socks5-tls-cert and --socks5-tls-key.

A proxy's settings - its traffic policy, the exceptions to it, and how often it refreshes - are set in
Infisical and reach the proxy while it runs, so they have no flags here. Every HTTPS host is intercepted either way; an exception is not blocked,
not un-intercepted.`,
	Example: `  INFISICAL_AGENT_VAULT_PROXY_TOKEN=eyJhb... infisical agent-vault proxy
  INFISICAL_AGENT_VAULT_PROXY_TOKEN=eyJhb... infisical agent-vault proxy --listen-host 127.0.0.1 --socks5-port 1080 --socks5-tls-name proxy.example.com`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		in, err := readAgentVaultProxyInputs(cmd)
		if err != nil {
			util.HandleError(err)
		}

		logFormat, err := cmd.Flags().GetString("log-format")
		if err != nil {
			util.HandleError(err, "Unable to read --log-format")
		}
		logFile, err := cmd.Flags().GetString("log-file")
		if err != nil {
			util.HandleError(err, "Unable to read --log-file")
		}

		writer, err := BuildAgentProxyLogWriter(logFormat, logFile)
		if err != nil {
			util.HandleError(err, "Unable to configure logging")
		}
		log.Logger = zerolog.New(writer).With().Timestamp().Logger()

		for _, warning := range in.warnings {
			log.Warn().Msg("agent-vault: " + warning)
		}

		opts := agentvault.Options{
			Port:       in.port,
			ListenHost: in.listenHost,
			DataDir:    in.dataDir,
			OwnCa:      in.ownCa,
			Socks5:     in.socks5,
			OnReady: func() {
				Telemetry.CaptureEventAsync("cli-command:agent-vault proxy", posthog.NewProperties().
					Set("version", util.CLI_VERSION).
					Set("platform", runtime.GOOS).
					Set("customPort", in.port != agentvault.DefaultPort).
					Set("customListenHost", in.listenHost != "").
					Set("customDataDir", in.dataDir != "").
					Set("ownCa", in.ownCa != nil).
					Set("socks5", in.socks5 != nil).
					Set("socks5OwnCert", in.socks5 != nil && in.socks5.Cert != nil).
					Set("socks5AllowPrivate", in.socks5 != nil && in.socks5.AllowPrivateDestinations).
					Set("logFormat", logFormat))
			},
		}

		if err := agentvault.Start(opts, in.proxyToken); err != nil {
			util.HandleError(err, "Agent Vault proxy failed")
		}
	},
}

type agentVaultProxyInputs struct {
	proxyToken string
	dataDir    string
	port       int
	listenHost string
	ownCa      *agentvault.OwnCa
	socks5     *agentvault.Socks5Options
	warnings   []string
}

// Warnings are returned rather than logged because the logger is configured after this runs.
func readAgentVaultProxyInputs(cmd *cobra.Command) (agentVaultProxyInputs, error) {
	var in agentVaultProxyInputs
	var err error

	in.proxyToken, err = util.GetCmdFlagOrEnvWithDefaultValue(
		cmd, "proxy-token", []string{"INFISICAL_AGENT_VAULT_PROXY_TOKEN"}, "")
	if err != nil {
		return in, fmt.Errorf("unable to read --proxy-token: %w", err)
	}

	in.dataDir, err = util.GetCmdFlagOrEnvWithDefaultValue(
		cmd, "data-dir", []string{"INFISICAL_AGENT_VAULT_DATA_DIR"}, "")
	if err != nil {
		return in, fmt.Errorf("unable to read --data-dir: %w", err)
	}

	port, portSource, _, err := agentVaultPortFlagOrEnv(cmd, "port", "INFISICAL_AGENT_VAULT_PORT")
	if err != nil {
		return in, err
	}
	if port < 0 || port > 65535 {
		return in, fmt.Errorf("%s must be between 0 and 65535, got %d. 0 asks for any free port", portSource, port)
	}
	in.port = port

	listenHost, listenHostSource, err := agentVaultFlagOrEnv(cmd, "listen-host", "INFISICAL_AGENT_VAULT_LISTEN_HOST")
	if err != nil {
		return in, err
	}
	if in.listenHost, err = hostOnly(listenHost, listenHostSource); err != nil {
		return in, err
	}

	caCert, caCertSource, err := agentVaultFlagOrEnv(cmd, "ca-cert", "INFISICAL_AGENT_VAULT_CA_CERT")
	if err != nil {
		return in, err
	}
	caKey, caKeySource, err := agentVaultFlagOrEnv(cmd, "ca-key", "INFISICAL_AGENT_VAULT_CA_KEY")
	if err != nil {
		return in, err
	}
	if (caCert == "") != (caKey == "") {
		return in, errors.New("--ca-cert and --ca-key go together")
	}
	if caCert != "" {
		// Only the key is a secret; the certificate is handed to every agent anyway.
		if caKeySource == "--ca-key" && strings.Contains(caKey, "-----BEGIN ") {
			in.warnings = append(in.warnings, "--ca-key is visible in the process list; prefer the env var INFISICAL_AGENT_VAULT_CA_KEY")
		}
		in.ownCa, err = agentvault.LoadOwnCa(agentvault.OwnCaInput{
			Cert: caCert, CertSource: caCertSource,
			Key: caKey, KeySource: caKeySource,
		})
		if err != nil {
			return in, err
		}
		in.warnings = append(in.warnings, in.ownCa.Warnings()...)
	}

	if in.socks5, err = readAgentVaultSocks5Inputs(cmd, &in); err != nil {
		return in, err
	}

	return in, nil
}

func readAgentVaultSocks5Inputs(cmd *cobra.Command, in *agentVaultProxyInputs) (*agentvault.Socks5Options, error) {
	port, portSource, portSet, err := agentVaultPortFlagOrEnv(cmd, "socks5-port", "INFISICAL_AGENT_VAULT_SOCKS5_PORT")
	if err != nil {
		return nil, err
	}
	tlsName, tlsNameSource, err := agentVaultFlagOrEnv(cmd, "socks5-tls-name", "INFISICAL_AGENT_VAULT_SOCKS5_TLS_NAME")
	if err != nil {
		return nil, err
	}
	tlsCert, tlsCertSource, err := agentVaultFlagOrEnv(cmd, "socks5-tls-cert", "INFISICAL_AGENT_VAULT_SOCKS5_TLS_CERT")
	if err != nil {
		return nil, err
	}
	tlsKey, tlsKeySource, err := agentVaultFlagOrEnv(cmd, "socks5-tls-key", "INFISICAL_AGENT_VAULT_SOCKS5_TLS_KEY")
	if err != nil {
		return nil, err
	}
	allowPrivate, allowPrivateSource, err := agentVaultBoolFlagOrEnv(cmd, "socks5-allow-private-destinations", "INFISICAL_AGENT_VAULT_SOCKS5_ALLOW_PRIVATE_DESTINATIONS")
	if err != nil {
		return nil, err
	}

	if !portSet {
		for _, set := range []struct {
			source string
			given  bool
		}{
			{tlsNameSource, tlsName != ""},
			{tlsCertSource, tlsCert != ""},
			{tlsKeySource, tlsKey != ""},
			{allowPrivateSource, allowPrivate},
		} {
			if set.given {
				return nil, fmt.Errorf("%s only applies with --socks5-port", set.source)
			}
		}
		return nil, nil
	}

	// 0 is not "off" or "any free port" here: a SOCKS5 client has to be told the port in advance.
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%s must be between 1 and 65535, got %d", portSource, port)
	}
	if port == in.port {
		return nil, fmt.Errorf("%s and --port can't be the same port (%d)", portSource, port)
	}

	opts := &agentvault.Socks5Options{Port: port, AllowPrivateDestinations: allowPrivate}

	if (tlsCert == "") != (tlsKey == "") {
		return nil, errors.New("--socks5-tls-cert and --socks5-tls-key go together")
	}
	if tlsCert != "" {
		if tlsKeySource == "--socks5-tls-key" && strings.Contains(tlsKey, "-----BEGIN ") {
			in.warnings = append(in.warnings, "--socks5-tls-key is visible in the process list; prefer the env var INFISICAL_AGENT_VAULT_SOCKS5_TLS_KEY")
		}
		opts.Cert, err = agentvault.LoadListenerCert(agentvault.OwnCaInput{
			Cert: tlsCert, CertSource: tlsCertSource,
			Key: tlsKey, KeySource: tlsKeySource,
		})
		if err != nil {
			return nil, err
		}
		return opts, nil
	}

	if tlsName == "" {
		return nil, errors.New("--socks5-port needs --socks5-tls-name, the DNS name or IP address clients reach the proxy by, so the proxy can make the port's certificate. To use your own certificate instead, pass --socks5-tls-cert and --socks5-tls-key")
	}
	if opts.TLSName, err = socks5TLSName(tlsName, tlsNameSource); err != nil {
		return nil, err
	}
	return opts, nil
}

// A certificate made for "Proxy.Example.com." or "proxy.example.com:1080" is one clients reject, so the name
// is reduced to the form a client checks against.
func socks5TLSName(raw, source string) (string, error) {
	name, err := hostOnly(raw, source)
	if err != nil {
		return "", err
	}
	name = strings.ToLower(strings.TrimRight(name, "."))
	if name == "" || strings.ContainsAny(name, "/* \t") {
		return "", fmt.Errorf("%s must be a DNS name or an IP address, got %q", source, raw)
	}
	return name, nil
}

// hostOnly accepts a host name or an IP address, with or without the brackets an IPv6 address is often written
// in, and refuses a value that also names a port, since the port has a flag of its own.
func hostOnly(raw, source string) (string, error) {
	host := strings.TrimSpace(raw)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("%s takes a host only, got %q. Set the port with its own flag", source, raw)
		}
	}
	return host, nil
}

// set reports whether the value came from the flag or the env var rather than the flag's default.
func agentVaultPortFlagOrEnv(cmd *cobra.Command, flag, env string) (port int, source string, set bool, err error) {
	port, err = cmd.Flags().GetInt(flag)
	if err != nil {
		return 0, "", false, fmt.Errorf("unable to read --%s: %w", flag, err)
	}
	if cmd.Flags().Changed(flag) {
		return port, "--" + flag, true, nil
	}
	if raw := strings.TrimSpace(os.Getenv(env)); raw != "" {
		port, err = strconv.Atoi(raw)
		if err != nil {
			return 0, env, true, fmt.Errorf("%s must be a whole number, got %q", env, raw)
		}
		return port, env, true, nil
	}
	return port, "--" + flag, false, nil
}

// Stricter than util.GetBoolFlagOrEnv, which turns an unreadable value into false with a warning: this switch
// turns a protection off, so a value that says neither must stop the start rather than be guessed at.
func agentVaultBoolFlagOrEnv(cmd *cobra.Command, flag, env string) (value bool, source string, err error) {
	if cmd.Flags().Changed(flag) {
		value, err = cmd.Flags().GetBool(flag)
		if err != nil {
			return false, "", fmt.Errorf("unable to read --%s: %w", flag, err)
		}
		return value, "--" + flag, nil
	}
	switch raw := strings.ToLower(strings.TrimSpace(os.Getenv(env))); raw {
	case "":
		return false, "--" + flag, nil
	case "true", "1":
		return true, env, nil
	case "false", "0":
		return false, env, nil
	default:
		return false, env, fmt.Errorf("%s must be true, false, 1 or 0, got %q", env, raw)
	}
}

// The source is the flag's name or the env var's, whichever the value came from, so errors can point at it.
func agentVaultFlagOrEnv(cmd *cobra.Command, flag, env string) (value, source string, err error) {
	value, err = cmd.Flags().GetString(flag)
	if err != nil {
		return "", "", fmt.Errorf("unable to read --%s: %w", flag, err)
	}
	if value != "" {
		return value, "--" + flag, nil
	}
	return strings.TrimSpace(os.Getenv(env)), env, nil
}

func init() {
	addAgentVaultProxyFlags(agentVaultProxyCmd)

	agentVaultCmd.AddCommand(agentVaultProxyCmd)
	RootCmd.AddCommand(agentVaultCmd)
}

func addAgentVaultProxyFlags(cmd *cobra.Command) {
	cmd.Flags().String("proxy-token", "",
		"token from Infisical that starts this proxy; you can run it on as many machines as you need")
	cmd.Flags().String("data-dir", "",
		fmt.Sprintf("where the proxy saves its settings and certificate authority for starts while Infisical can't be reached (default: %s)", defaultDataDirHelp()))
	cmd.Flags().String("ca-cert", "", "your own certificate authority to serve, instead of the one Infisical issues: PEM, base64 PEM or file path")
	cmd.Flags().String("ca-key", "", "private key for --ca-cert: PEM, base64 PEM or file path")
	cmd.Flags().Int("port", agentvault.DefaultPort, "port for the HTTP proxy; 0 binds any free port, which the startup line then reports")
	cmd.Flags().String("listen-host", "", "host or IP address the HTTP proxy listens on, such as 127.0.0.1 (default: all interfaces)")
	cmd.Flags().Int("socks5-port", 0, "port for SOCKS5 over TLS, which listens on all interfaces (default: off)")
	cmd.Flags().String("socks5-tls-name", "", "DNS name or IP address clients reach the SOCKS5 port by; the proxy makes the port's certificate for it")
	cmd.Flags().String("socks5-tls-cert", "", "your own certificate for the SOCKS5 port, instead of one the proxy makes: PEM, base64 PEM or file path")
	cmd.Flags().String("socks5-tls-key", "", "private key for --socks5-tls-cert: PEM, base64 PEM or file path")
	cmd.Flags().Bool("socks5-allow-private-destinations", false, "let SOCKS5 traffic that no service covers reach private, loopback and link-local addresses")
	cmd.Flags().String("log-format", "console", "log output format: console | json")
	cmd.Flags().String("log-file", "", "path to also write logs to")
	// Units written for enrollment still pass this on every start; failing on an unknown flag would take an
	// enrolled proxy down on a CLI upgrade, so it is accepted and ignored. Remove after 2026-12-21.
	cmd.Flags().String("enrollment-token", "", "no longer used")
	_ = cmd.Flags().MarkHidden("enrollment-token")
	_ = cmd.Flags().MarkDeprecated("enrollment-token", "start the proxy with --proxy-token instead")
}

func defaultDataDirHelp() string {
	dir, err := agentvault.DefaultDataDir()
	if err != nil {
		return "~/.infisical/agent-vault"
	}
	return dir
}
