package pam

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/ch-go"
	"github.com/ClickHouse/ch-go/proto"
	"github.com/docker/docker/api/types/container"
	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	openapitypes "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	clickhouseImage    = "clickhouse/clickhouse-server:24.8"
	clickhouseDatabase = "analytics"
	clickhouseUser     = "default"
	clickhousePassword = "clickhouse"
)

func startClickHouseContainer(t *testing.T, ctx context.Context) (testcontainers.Container, string, int, int) {
	t.Helper()

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        clickhouseImage,
			ExposedPorts: []string{"8123/tcp", "9000/tcp"},
			Env: map[string]string{
				"CLICKHOUSE_DB":       clickhouseDatabase,
				"CLICKHOUSE_USER":     clickhouseUser,
				"CLICKHOUSE_PASSWORD": clickhousePassword,
			},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.ExtraHosts = append(hc.ExtraHosts, "host.docker.internal:host-gateway")
			},
			WaitingFor: wait.ForAll(
				wait.ForListeningPort("8123/tcp"),
				wait.ForListeningPort("9000/tcp"),
			).WithStartupTimeout(180 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := ctr.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate ClickHouse container: %v", err)
		}
	})

	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	httpPort, err := ctr.MappedPort(ctx, "8123")
	require.NoError(t, err)
	nativePort, err := ctr.MappedPort(ctx, "9000")
	require.NoError(t, err)

	seedClickHouse(t, ctx, ctr)
	return ctr, host, httpPort.Int(), nativePort.Int()
}

// queryOverNative drives the session with ch-go's client, which performs a real native handshake and
// query exchange. It runs on this host because a PAM proxy binds loopback only
// (TestLocalProxiesBindLoopback), so nothing inside a container can reach it.
func queryOverNative(t *testing.T, ctx context.Context, proxyPort int, sql string, compress bool) (string, error) {
	t.Helper()

	options := ch.Options{
		Address:  fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Database: clickhouseDatabase,
		// The proxy injects the account's credentials, so whatever the client sends is discarded.
		User:     "not-the-account",
		Password: "not-the-password",
	}
	if compress {
		options.Compression = ch.CompressionLZ4
	}

	client, err := ch.Dial(ctx, options)
	if err != nil {
		return "", err
	}
	defer client.Close()

	var answer proto.ColStr
	if err := client.Do(ctx, ch.Query{
		Body:   sql,
		Result: proto.Results{{Name: "answer", Data: &answer}},
	}); err != nil {
		return "", err
	}
	if answer.Rows() == 0 {
		return "", fmt.Errorf("no rows returned")
	}
	return answer.First(), nil
}

func seedClickHouse(t *testing.T, ctx context.Context, ctr testcontainers.Container) {
	t.Helper()

	statements := []string{
		"CREATE TABLE IF NOT EXISTS events (id UInt64, name String) ENGINE = MergeTree ORDER BY id",
		"INSERT INTO events VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma')",
	}
	for _, sql := range statements {
		exitCode, _, err := ctr.Exec(ctx, []string{
			"clickhouse-client",
			"--user", clickhouseUser, "--password", clickhousePassword,
			"--database", clickhouseDatabase,
			"--query", sql,
		})
		require.NoError(t, err)
		require.Zero(t, exitCode, "seeding failed for: %s", sql)
	}
}

func createClickHousePamAccount(t *testing.T, ctx context.Context, infra *PAMTestInfra,
	folderId, templateId openapitypes.UUID, name, host string, httpPort, nativePort *int) {
	t.Helper()

	connectionDetails := map[string]interface{}{
		"host":                  host,
		"database":              clickhouseDatabase,
		"sslEnabled":            false,
		"sslRejectUnauthorized": false,
	}
	if httpPort != nil {
		connectionDetails["port"] = *httpPort
	}
	if nativePort != nil {
		connectionDetails["nativePort"] = *nativePort
	}

	CreatePamAccount(t, ctx, infra, "clickhouse", name, folderId, templateId, connectionDetails,
		map[string]interface{}{"username": clickhouseUser, "password": clickhousePassword})
}

func startClickHouseProxy(t *testing.T, ctx context.Context, infra *PAMTestInfra,
	folderName, accountName string) (int, *helpers.Command) {
	t.Helper()

	freePort := helpers.GetFreePort()
	pamCmd := helpers.Command{
		Test:               t,
		RunMethod:          helpers.RunMethodSubprocess,
		DisableTempHomeDir: true,
		Args: []string{
			"pam", "access", fmt.Sprintf("%s/%s", folderName, accountName),
			"--duration", "5m",
			"--port", fmt.Sprintf("%d", freePort),
		},
		Env: map[string]string{
			"HOME":              infra.SharedHomeDir,
			"INFISICAL_API_URL": infra.Infisical.ApiUrl(t),
		},
	}
	pamCmd.Start(ctx)
	t.Cleanup(pamCmd.Stop)

	result := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &pamCmd,
		Condition: func() helpers.ConditionResult {
			if strings.Contains(pamCmd.Stdout(), "ClickHouse Proxy Session Started") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	if result != helpers.WaitSuccess {
		infra.DumpOutput(&pamCmd)
	}
	require.Equal(t, helpers.WaitSuccess, result, "ClickHouse proxy should start successfully")

	return freePort, &pamCmd
}

func queryOverHTTP(t *testing.T, ctx context.Context, proxyPort int, sql string) (int, string) {
	t.Helper()

	url := fmt.Sprintf("http://127.0.0.1:%d/?database=%s", proxyPort, clickhouseDatabase)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(sql))
	require.NoError(t, err)

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

// waitForProxyHTTP absorbs the gap between the banner and the listener accepting.
func waitForProxyHTTP(t *testing.T, ctx context.Context, pamCmd *helpers.Command, proxyPort int) {
	t.Helper()

	result := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: pamCmd,
		Interval:         2 * time.Second,
		Timeout:          60 * time.Second,
		Condition: func() helpers.ConditionResult {
			status, _ := queryOverHTTP(t, ctx, proxyPort, "SELECT 1")
			if status == http.StatusOK {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "the proxy should answer HTTP")
}

func TestPAM_ClickHouse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)
	LoginUser(t, ctx, infra)

	folderName := "clickhouse-folder"
	folderId := CreatePamFolder(t, ctx, infra, folderName)
	templateId := CreatePamTemplate(t, ctx, infra, "clickhouse-template",
		client.CreatePamAccountTemplateJSONBodyType("clickhouse"))

	_, chHost, chHTTPPort, chNativePort := startClickHouseContainer(t, ctx)

	t.Run("both interfaces on one session port", func(t *testing.T) {
		accountName := "clickhouse-dual-account"
		createClickHousePamAccount(t, ctx, infra, folderId, templateId, accountName, chHost,
			&chHTTPPort, &chNativePort)

		proxyPort, pamCmd := startClickHouseProxy(t, ctx, infra, folderName, accountName)
		waitForProxyHTTP(t, ctx, pamCmd, proxyPort)

		status, body := queryOverHTTP(t, ctx, proxyPort, "SELECT name FROM events ORDER BY id")
		require.Equal(t, http.StatusOK, status, body)
		require.Equal(t, "alpha\nbeta\ngamma", strings.TrimSpace(body))
		slog.Info("HTTP interface answered through the proxy")

		answer, err := queryOverNative(t, ctx, proxyPort, "SELECT toString(count()) AS answer FROM events", false)
		require.NoError(t, err)
		require.Equal(t, "3", answer)
		slog.Info("native interface answered the same session port")
	})

	t.Run("compression is negotiated end to end", func(t *testing.T) {
		accountName := "clickhouse-compression-account"
		createClickHousePamAccount(t, ctx, infra, folderId, templateId, accountName, chHost,
			&chHTTPPort, &chNativePort)

		proxyPort, pamCmd := startClickHouseProxy(t, ctx, infra, folderName, accountName)
		waitForProxyHTTP(t, ctx, pamCmd, proxyPort)

		for _, compression := range []bool{true, false} {
			answer, err := queryOverNative(t, ctx, proxyPort,
				"SELECT toString(count()) AS answer FROM events", compression)
			require.NoError(t, err, "compression=%v", compression)
			require.Equal(t, "3", answer, "compression=%v", compression)
		}
	})

	t.Run("a native-only account turns HTTP clients away", func(t *testing.T) {
		accountName := "clickhouse-native-only-account"
		createClickHousePamAccount(t, ctx, infra, folderId, templateId, accountName, chHost,
			nil, &chNativePort)

		proxyPort, pamCmd := startClickHouseProxy(t, ctx, infra, folderName, accountName)

		result := helpers.WaitFor(t, helpers.WaitForOptions{
			EnsureCmdRunning: pamCmd,
			Interval:         2 * time.Second,
			Timeout:          60 * time.Second,
			Condition: func() helpers.ConditionResult {
				answer, err := queryOverNative(t, ctx, proxyPort, "SELECT toString(count()) AS answer FROM events", false)
				if err == nil && answer == "3" {
					return helpers.ConditionSuccess
				}
				return helpers.ConditionWait
			},
		})
		require.Equal(t, helpers.WaitSuccess, result, "a native client should still work")

		status, body := queryOverHTTP(t, ctx, proxyPort, "SELECT 1")
		require.NotEqual(t, http.StatusOK, status, body)
		require.Contains(t, body, "HTTP port",
			"an HTTP client must be told why, not left with a transport error")
	})

	t.Run("an HTTP-only account turns native clients away", func(t *testing.T) {
		accountName := "clickhouse-http-only-account"
		createClickHousePamAccount(t, ctx, infra, folderId, templateId, accountName, chHost,
			&chHTTPPort, nil)

		proxyPort, pamCmd := startClickHouseProxy(t, ctx, infra, folderName, accountName)
		waitForProxyHTTP(t, ctx, pamCmd, proxyPort)

		_, err := queryOverNative(t, ctx, proxyPort, "SELECT toString(count()) AS answer FROM events", false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "native port",
			"a native client must be told why, not left with a transport error")
	})
}
