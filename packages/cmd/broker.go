package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/broker"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var brokerCmd = &cobra.Command{
	Use:   "broker",
	Short: "Credential brokering HTTP proxy for AI agents",
	Long:  "Start and manage a local HTTP proxy that injects real credentials into outbound requests from AI agents that only see placeholder values.",
}

var brokerStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the credential broker proxy",
	Run: func(cmd *cobra.Command, args []string) {
		port, _ := cmd.Flags().GetInt("port")
		pollInterval, _ := cmd.Flags().GetInt("poll-interval")
		environmentName, _ := cmd.Flags().GetString("env")
		projectId, _ := cmd.Flags().GetString("projectId")

		token, err := util.GetInfisicalToken(cmd)
		if err != nil {
			util.HandleError(err, "Unable to parse token")
		}

		if projectId == "" {
			workspaceFile, err := util.GetWorkSpaceFromFile()
			if err == nil && workspaceFile.WorkspaceId != "" {
				projectId = workspaceFile.WorkspaceId
			} else {
				util.HandleError(fmt.Errorf("--projectId is required, or run 'infisical init' to set up a project"))
			}
		}

		allowHostsStr, _ := cmd.Flags().GetString("allow-hosts")
		var allowedHosts []string
		if allowHostsStr != "" {
			for _, h := range strings.Split(allowHostsStr, ",") {
				if trimmed := strings.TrimSpace(h); trimmed != "" {
					allowedHosts = append(allowedHosts, trimmed)
				}
			}
		}

		blockUnknownHosts, _ := cmd.Flags().GetBool("block-unknown-hosts")

		cfg := broker.Config{
			Port:              port,
			PollInterval:      time.Duration(pollInterval) * time.Second,
			AllowedHosts:      allowedHosts,
			BlockUnknownHosts: blockUnknownHosts,
		}

		fetchFn := buildBrokerFetchFn(token, projectId, environmentName)

		b, err := broker.New(cfg, fetchFn)
		if err != nil {
			util.HandleError(err, "Failed to initialize broker")
		}

		// Write broker.json and combined CA so infisical run can auto-detect
		home, _ := os.UserHomeDir()
		brokerDir := filepath.Join(home, ".infisical", "broker")
		os.MkdirAll(brokerDir, 0700)

		caCertPath := filepath.Join(brokerDir, "mitm-ca.pem")
		combinedCAPath := filepath.Join(brokerDir, "combined-ca.pem")
		brokerInfoPath := filepath.Join(brokerDir, "broker.json")

		// Write the CA cert
		caPEM := b.CACertPEM()
		os.WriteFile(caCertPath, caPEM, 0644)

		// Create combined CA bundle (system + broker)
		systemCAPath := "/etc/ssl/cert.pem"
		if systemCA, err := os.ReadFile(systemCAPath); err == nil {
			combined := append(systemCA, '\n')
			combined = append(combined, caPEM...)
			os.WriteFile(combinedCAPath, combined, 0644)
		} else {
			combinedCAPath = caCertPath
		}

		// Resolve domain for NO_PROXY
		domain := config.INFISICAL_URL
		noProxyHost := domain
		if parsed, parseErr := url.Parse(domain); parseErr == nil && parsed.Hostname() != "" {
			noProxyHost = parsed.Hostname()
		}

		// Write broker.json
		brokerInfo := map[string]interface{}{
			"port":             port,
			"caCertPath":       caCertPath,
			"combinedCACertPath": combinedCAPath,
			"domain":           domain,
			"noProxyHost":      noProxyHost,
			"pid":              os.Getpid(),
		}
		brokerInfoJSON, _ := json.Marshal(brokerInfo)
		os.WriteFile(brokerInfoPath, brokerInfoJSON, 0644)

		ctx, cancel := context.WithCancel(context.Background())
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			sig := <-sigCh
			log.Info().Str("signal", sig.String()).Msg("Shutting down broker")
			os.Remove(brokerInfoPath)
			cancel()
			b.Stop()
			<-sigCh
			os.Exit(1)
		}()

		b.SetProposalFunc(buildProposalFunc(token, projectId, environmentName))

		log.Info().
			Int("port", port).
			Str("env", environmentName).
			Str("projectId", projectId).
			Msg("Starting credential broker")

		if err := b.Start(ctx); err != nil {
			os.Remove(brokerInfoPath)
			log.Error().Err(err).Msg("Broker stopped")
		}
	},
}

var brokerEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Print shell export statements for broker proxy environment",
	Run: func(cmd *cobra.Command, args []string) {
		port, _ := cmd.Flags().GetInt("port")
		domain, _ := cmd.Flags().GetString("domain")

		if domain == "" {
			domain = config.INFISICAL_URL
		}

		// Fetch CA cert from running broker
		caURL := fmt.Sprintf("http://localhost:%d/ca.pem", port)
		resp, err := http.Get(caURL)
		if err != nil {
			util.HandleError(fmt.Errorf("broker not reachable at %s -- is it running? Start it with 'infisical broker start'", caURL))
		}
		defer resp.Body.Close()

		home, _ := os.UserHomeDir()
		caPath := filepath.Join(home, ".infisical", "broker", "mitm-ca.pem")
		os.MkdirAll(filepath.Dir(caPath), 0700)

		caData, err := io.ReadAll(resp.Body)
		if err != nil || len(caData) == 0 {
			util.HandleError(fmt.Errorf("failed to read CA cert from broker"))
		}
		os.WriteFile(caPath, caData, 0644)

		// Create combined CA bundle: system CAs + broker CA
		// This lets clients trust both the broker's MITM cert and real TLS certs
		combinedPath := filepath.Join(filepath.Dir(caPath), "combined-ca.pem")
		systemCAPath := "/etc/ssl/cert.pem" // macOS system CA bundle
		if systemCA, err := os.ReadFile(systemCAPath); err == nil {
			combined := append(systemCA, '\n')
			combined = append(combined, caData...)
			os.WriteFile(combinedPath, combined, 0644)
		} else {
			// Fallback: just use broker CA
			combinedPath = caPath
		}

		proxyAddr := fmt.Sprintf("http://localhost:%d", port)

		fmt.Printf("export HTTP_PROXY=%s\n", proxyAddr)
		fmt.Printf("export HTTPS_PROXY=%s\n", proxyAddr)
		fmt.Printf("export SSL_CERT_FILE=%s\n", combinedPath)
		fmt.Printf("export NODE_EXTRA_CA_CERTS=%s\n", caPath)
		fmt.Printf("export REQUESTS_CA_BUNDLE=%s\n", combinedPath)
		fmt.Printf("export CURL_CA_BUNDLE=%s\n", combinedPath)
		fmt.Printf("export DENO_CERT=%s\n", caPath)
		noProxyHost := domain
		if parsed, err := url.Parse(domain); err == nil && parsed.Hostname() != "" {
			noProxyHost = parsed.Hostname()
		}
		fmt.Printf("export NO_PROXY=localhost,127.0.0.1,%s\n", noProxyHost)
		fmt.Printf("export INFISICAL_INJECT_PLACEHOLDERS=true\n")
		fmt.Printf("export NODE_USE_ENV_PROXY=1\n")
	},
}

var brokerSetupSrtCmd = &cobra.Command{
	Use:   "setup-srt",
	Short: "Configure SRT (sandbox-runtime) to use the broker for OS-level isolation",
	Run: func(cmd *cobra.Command, args []string) {
		port, _ := cmd.Flags().GetInt("port")

		home, err := os.UserHomeDir()
		if err != nil {
			util.HandleError(fmt.Errorf("cannot determine home directory: %w", err))
		}

		brokerDir := filepath.Join(home, ".infisical", "broker")
		srtSettingsPath := filepath.Join(home, ".srt-settings.json")

		// Verify broker CA cert exists
		caCertPath := filepath.Join(brokerDir, "mitm-ca.pem")
		combinedCAPath := filepath.Join(brokerDir, "combined-ca.pem")
		if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
			util.HandleError(fmt.Errorf("broker CA cert not found at %s -- start the broker first with 'infisical broker start'", caCertPath))
		}

		// Create combined CA if it doesn't exist
		if _, err := os.Stat(combinedCAPath); os.IsNotExist(err) {
			systemCAPath := "/etc/ssl/cert.pem"
			if systemCA, readErr := os.ReadFile(systemCAPath); readErr == nil {
				brokerCA, _ := os.ReadFile(caCertPath)
				combined := append(systemCA, '\n')
				combined = append(combined, brokerCA...)
				os.WriteFile(combinedCAPath, combined, 0644)
			}
		}

		// Write SRT settings
		srtConfig := map[string]interface{}{
			"network": map[string]interface{}{
				"allowedDomains": []string{},
				"deniedDomains":  []string{},
				"httpProxyPort":  port,
			},
			"filesystem": map[string]interface{}{
				"denyRead":   []string{"~/.infisical", "~/.ssh", "~/.aws", "~/.config/gcloud"},
				"allowRead":  []string{"~/.infisical/broker"},
				"allowWrite": []string{".", "~", "/tmp", "/private/tmp"},
				"denyWrite":  []string{},
			},
			"allowPty": true,
		}

		srtJSON, _ := json.MarshalIndent(srtConfig, "", "  ")
		if err := os.WriteFile(srtSettingsPath, srtJSON, 0644); err != nil {
			util.HandleError(fmt.Errorf("failed to write SRT settings to %s: %w", srtSettingsPath, err))
		}

		fmt.Printf("SRT settings written to %s\n", srtSettingsPath)
		fmt.Printf("  httpProxyPort: %d\n", port)
		fmt.Printf("  denyRead: ~/.infisical, ~/.ssh, ~/.aws, ~/.config/gcloud\n")
		fmt.Printf("  allowRead: ~/.infisical/broker (CA cert)\n")
		fmt.Println()
		fmt.Println("To run an agent with OS-level isolation:")
		fmt.Printf("  NODE_EXTRA_CA_CERTS=%s srt \"claude\"\n", caCertPath)
		fmt.Println()
		fmt.Println("Or with infisical run (auto-wraps with SRT when detected):")
		fmt.Println("  infisical run --env dev -- claude")
	},
}

func init() {
	brokerStartCmd.Flags().Int("port", 14322, "port for the broker proxy")
	brokerStartCmd.Flags().Int("poll-interval", 10, "poll interval in seconds for config updates")
	brokerStartCmd.Flags().StringP("env", "e", "dev", "environment to fetch proxy configs from")
	brokerStartCmd.Flags().String("projectId", "", "project ID to fetch proxy configs from")
	brokerStartCmd.Flags().String("token", "", "authentication token")
	brokerStartCmd.Flags().String("allow-hosts", "", "comma-separated list of hosts to pass through without credential injection")
	brokerStartCmd.Flags().Bool("block-unknown-hosts", false, "block requests to hosts without proxy configs (default: passthrough)")

	brokerEnvCmd.Flags().Int("port", 14322, "broker proxy port")
	brokerEnvCmd.Flags().String("domain", "", "Infisical domain (auto-detected from config if not set)")

	brokerSetupSrtCmd.Flags().Int("port", 14322, "broker proxy port to configure in SRT settings")

	brokerCmd.AddCommand(brokerStartCmd)
	brokerCmd.AddCommand(brokerEnvCmd)
	brokerCmd.AddCommand(brokerSetupSrtCmd)
	RootCmd.AddCommand(brokerCmd)
}
