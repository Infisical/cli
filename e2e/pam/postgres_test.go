package pam

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestPAM_Postgres_ConnectToDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)

	const (
		pgUser     = "pamuser"
		pgPassword = "pampassword"
		pgDatabase = "testdb"
	)

	// Start PAM-target Postgres via testcontainers
	pgContainer, err := tcpostgres.Run(ctx, "postgres:16",
		tcpostgres.WithDatabase(pgDatabase),
		tcpostgres.WithUsername(pgUser),
		tcpostgres.WithPassword(pgPassword),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate Postgres container: %v", err)
		}
	})

	// Verify PAM Postgres is reachable directly
	pgConnStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	directConn, err := pgx.Connect(ctx, pgConnStr)
	require.NoError(t, err)
	var directResult int
	err = directConn.QueryRow(ctx, "SELECT 1").Scan(&directResult)
	require.NoError(t, err)
	require.Equal(t, 1, directResult)
	directConn.Close(ctx)
	slog.Info("Verified PAM Postgres is accessible directly")

	// Get host/port for the PAM account
	pgHost, err := pgContainer.Host(ctx)
	require.NoError(t, err)
	pgPort, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)

	// Create folder + template + account (new PAM model)
	folderName := "pg-folder"
	accountName := "pg-account"
	folderId := CreatePamFolder(t, ctx, infra, folderName)
	templateId := CreatePamTemplate(t, ctx, infra, "pg-template", client.CreatePamAccountTemplateJSONBodyTypePostgres)

	gatewayId := infra.GatewayId
	password := pgPassword
	acctResp, err := infra.ApiClient.CreatePostgresPamAccountWithResponse(
		ctx,
		client.CreatePostgresPamAccountJSONRequestBody{
			FolderId:   folderId,
			TemplateId: templateId,
			GatewayId:  &gatewayId,
			Name:       accountName,
			ConnectionDetails: struct {
				Database              string  `json:"database"`
				Host                  string  `json:"host"`
				Port                  float32 `json:"port"`
				SslCertificate        *string `json:"sslCertificate,omitempty"`
				SslEnabled            bool    `json:"sslEnabled"`
				SslRejectUnauthorized bool    `json:"sslRejectUnauthorized"`
			}{
				Host:                  pgHost,
				Port:                  float32(pgPort.Int()),
				Database:              pgDatabase,
				SslEnabled:            false,
				SslRejectUnauthorized: false,
			},
			Credentials: struct {
				Password *string `json:"password,omitempty"`
				Username string  `json:"username"`
			}{
				Username: pgUser,
				Password: &password,
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, acctResp.StatusCode(), "create account: %s", string(acctResp.Body))
	slog.Info("Created Postgres PAM account")

	// Login with provisioned admin user
	LoginUser(t, ctx, infra)

	// Run pam access <folder>/<account>
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

	// Wait for proxy to be ready (printed to stdout via fmt.Printf)
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &pamCmd,
		Condition: func() helpers.ConditionResult {
			if strings.Contains(pamCmd.Stdout(), "Proxy Session Started") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	if result != helpers.WaitSuccess {
		infra.DumpOutput(&pamCmd)
	}
	require.Equal(t, helpers.WaitSuccess, result, "Database proxy should start successfully")

	// Connect via pgx to the proxy and run SELECT 1
	proxyConnStr := fmt.Sprintf("postgres://%s@127.0.0.1:%d/%s?sslmode=disable", pgUser, freePort, pgDatabase)
	var proxyConn *pgx.Conn
	connectResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &pamCmd,
		Interval:         2 * time.Second,
		Timeout:          30 * time.Second,
		Condition: func() helpers.ConditionResult {
			conn, err := pgx.Connect(ctx, proxyConnStr)
			if err != nil {
				slog.Warn("Proxy connection attempt failed, retrying...", "error", err)
				return helpers.ConditionWait
			}
			proxyConn = conn
			return helpers.ConditionSuccess
		},
	})
	if connectResult != helpers.WaitSuccess {
		infra.DumpOutput(&pamCmd)
	}
	require.Equal(t, helpers.WaitSuccess, connectResult, "Should connect to database through proxy")
	defer proxyConn.Close(ctx)

	var proxyResult int
	err = proxyConn.QueryRow(ctx, "SELECT 1").Scan(&proxyResult)
	require.NoError(t, err)
	require.Equal(t, 1, proxyResult)
	slog.Info("SELECT 1 through PAM proxy succeeded")
}
