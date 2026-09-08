package pam

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

// The local end is a plain pipe to the gateway, which authenticates, runs each statement and records it.
// Clients connect with TLS off, since the hop to the gateway is already an encrypted tunnel.
func startSnowflakeProxy(httpClient *resty.Client, response *api.PAMAccessResponse, path, durationStr string, port int) {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		util.HandleError(err, "Failed to parse duration")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &DatabaseProxyServer{
		BaseProxyServer: BaseProxyServer{
			httpClient:             httpClient,
			relayHost:              response.RelayHost,
			relayClientCert:        response.RelayClientCertificate,
			relayClientKey:         response.RelayClientPrivateKey,
			relayServerCertChain:   response.RelayServerCertificateChain,
			gatewayClientCert:      response.GatewayClientCertificate,
			gatewayClientKey:       response.GatewayClientPrivateKey,
			gatewayServerCertChain: response.GatewayServerCertificateChain,
			sessionExpiry:          time.Now().Add(duration),
			sessionId:              response.SessionId,
			resourceType:           response.AccountType,
			ctx:                    ctx,
			cancel:                 cancel,
			shutdownCh:             make(chan struct{}),
		},
	}

	if err := proxy.ValidateResourceTypeSupported(); err != nil {
		util.HandleError(err, "Gateway version outdated")
		return
	}

	if err := proxy.Start(port); err != nil {
		util.HandleError(err, "Failed to start proxy server")
		return
	}

	folder, account := parsePath(path)
	log.Info().Msgf("Snowflake proxy server listening on port %d", proxy.port)
	printSnowflakeSessionInfo(folder, account, duration, response.Metadata, proxy.port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %v, initiating graceful shutdown...", sig)
		proxy.gracefulShutdown()
	}()

	proxy.Run()
}

func printSnowflakeSessionInfo(folder, account string, duration time.Duration, metadata map[string]string, port int) {
	target := metadata["account"]
	if target == "" {
		target = "<account>"
	}

	rule := "**********************************************************************\n"
	divider := "----------------------------------------------------------------------\n"

	fmt.Print("\n" + rule)
	fmt.Printf("              Snowflake Proxy Session Started!                \n")
	fmt.Print(rule + "\n")
	if folder != "" {
		fmt.Printf("  Folder:    %s\n", folder)
	}
	fmt.Printf("  Account:   %s\n", account)
	fmt.Printf("  Duration:  %s\n\n", duration.String())
	fmt.Print(divider)
	fmt.Printf("                        Connection Details                            \n")
	fmt.Print(divider + "\n")
	fmt.Printf("  Host:      127.0.0.1\n")
	fmt.Printf("  Port:      %d\n", port)
	fmt.Printf("  Protocol:  http\n")
	for _, row := range [][2]string{{"Database", metadata["database"]}, {"Schema", metadata["schema"]}, {"Warehouse", metadata["warehouse"]}} {
		if row[1] != "" {
			fmt.Printf("  %-10s %s\n", row[0]+":", row[1])
		}
	}
	fmt.Print("\n" + divider)
	fmt.Printf("                           How to Connect                             \n")
	fmt.Print(divider + "\n")
	fmt.Printf("  Any username and password work; the gateway authenticates for you.\n\n")
	fmt.Printf("  Connection string:\n")
	util.PrintfStderr("    jdbc:snowflake://127.0.0.1:%d/?ssl=off&account=%s%s\n\n", port, target,
		jdbcExtras(metadata["database"], metadata["schema"], metadata["warehouse"]))
	fmt.Printf("  snowsql:\n")
	util.PrintfStderr("    $ SNOWSQL_PWD=x snowsql -a %s -u pam -h 127.0.0.1 -p %d\n", target, port)
	fmt.Printf("\n  Press Ctrl+C to stop the proxy.\n\n")
	fmt.Print(rule + "\n")
}

func jdbcExtras(database, schema, warehouse string) string {
	extras := make([]string, 0, 3)
	for _, pair := range [][2]string{{"db", database}, {"schema", schema}, {"warehouse", warehouse}} {
		if pair[1] != "" {
			extras = append(extras, pair[0]+"="+url.QueryEscape(pair[1]))
		}
	}
	if len(extras) == 0 {
		return ""
	}
	return "&" + strings.Join(extras, "&")
}
