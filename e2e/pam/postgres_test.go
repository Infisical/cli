package pam

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const (
	pgUser     = "pamuser"
	pgPassword = "pampassword"
	pgDatabase = "testdb"
)

type recordedQuery struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

func startPostgresTarget(t *testing.T, ctx context.Context) (string, int) {
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

	pgHost, err := pgContainer.Host(ctx)
	require.NoError(t, err)
	pgPort, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)
	return pgHost, pgPort.Int()
}

func createPostgresPamAccount(t *testing.T, ctx context.Context, infra *PAMTestInfra, prefix, pgHost string, pgPort int) (folderName, accountName string) {
	folderName = prefix + "-folder"
	accountName = prefix + "-account"
	folderId := CreatePamFolder(t, ctx, infra, folderName)
	templateId := CreatePamTemplate(t, ctx, infra, prefix+"-template", client.CreatePamAccountTemplateJSONBodyTypePostgres)

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
				Port:                  float32(pgPort),
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
	return folderName, accountName
}

func startPostgresPamAccess(t *testing.T, ctx context.Context, infra *PAMTestInfra, folderName, accountName string) (*helpers.Command, int) {
	freePort := helpers.GetFreePort()
	pamCmd := &helpers.Command{
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
		EnsureCmdRunning: pamCmd,
		Condition: func() helpers.ConditionResult {
			if strings.Contains(pamCmd.Stdout(), "Proxy Session Started") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	if result != helpers.WaitSuccess {
		infra.DumpOutput(pamCmd)
	}
	require.Equal(t, helpers.WaitSuccess, result, "Database proxy should start successfully")
	return pamCmd, freePort
}

func connectPostgresProxy(t *testing.T, ctx context.Context, infra *PAMTestInfra, pamCmd *helpers.Command, port int) *pgx.Conn {
	proxyConnStr := fmt.Sprintf("postgres://%s@127.0.0.1:%d/%s?sslmode=disable", pgUser, port, pgDatabase)
	var proxyConn *pgx.Conn
	connectResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: pamCmd,
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
		infra.DumpOutput(pamCmd)
	}
	require.Equal(t, helpers.WaitSuccess, connectResult, "Should connect to database through proxy")
	return proxyConn
}

func runQueries(t *testing.T, ctx context.Context, conn *pgx.Conn, queries []recordedQuery) {
	for _, query := range queries {
		_, err := conn.Exec(ctx, query.Input)
		require.NoError(t, err)
	}
}

func requirePostgresRecording(t *testing.T, ctx context.Context, infra *PAMTestInfra, sessionId string, expected []recordedQuery) {
	playback := WaitForSessionRecording(t, ctx, infra, sessionId)
	require.Equal(t, "postgres", playback.StorageBackend)
	recorded := ReadSessionRecording[recordedQuery](t, ctx, infra, sessionId, playback)
	require.Equal(t, expected, recorded)
	slog.Info("Postgres session recording verified", "sessionId", sessionId, "entries", len(recorded))
}

func TestPAM_Postgres_ConnectToDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)
	pgHost, pgPort := startPostgresTarget(t, ctx)
	folderName, accountName := createPostgresPamAccount(t, ctx, infra, "pg", pgHost, pgPort)
	LoginUser(t, ctx, infra)
	pamCmd, proxyPort := startPostgresPamAccess(t, ctx, infra, folderName, accountName)
	proxyConn := connectPostgresProxy(t, ctx, infra, pamCmd, proxyPort)
	defer proxyConn.Close(ctx)

	var proxyResult int
	err := proxyConn.QueryRow(ctx, "SELECT 1").Scan(&proxyResult)
	require.NoError(t, err)
	require.Equal(t, 1, proxyResult)
	slog.Info("SELECT 1 through PAM proxy succeeded")

	queries := []recordedQuery{
		{Input: "CREATE TABLE pam_recording (note text)", Output: "CREATE TABLE"},
		{Input: "INSERT INTO pam_recording VALUES ('recorded through pam')", Output: "INSERT 0 1"},
		{Input: "SELECT note FROM pam_recording", Output: "SELECT 1"},
	}
	runQueries(t, ctx, proxyConn, queries)

	sessionId := FindPamSessionId(t, ctx, infra, accountName)

	// The gateway keeps the encrypted recording on disk until the session ends and it is uploaded.
	recordingGlob := filepath.Join(infra.RecordingPath, fmt.Sprintf("pam_session_%s_postgres_expires_*.enc", sessionId))
	fileResult := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  30 * time.Second,
		Interval: time.Second,
		Condition: func() helpers.ConditionResult {
			files, _ := filepath.Glob(recordingGlob)
			if len(files) != 1 {
				return helpers.ConditionWait
			}
			if info, statErr := os.Stat(files[0]); statErr != nil || info.Size() == 0 {
				return helpers.ConditionWait
			}
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, fileResult, "gateway should write the session recording under %s", infra.RecordingPath)

	require.NoError(t, proxyConn.Close(ctx))
	EndPamAccess(t, infra, pamCmd)

	requirePostgresRecording(t, ctx, infra, sessionId,
		append([]recordedQuery{{Input: "SELECT 1", Output: "SELECT 1"}}, queries...))
}

func TestPAM_Postgres_RecordingSurvivesGatewayCrash(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)
	pgHost, pgPort := startPostgresTarget(t, ctx)
	folderName, accountName := createPostgresPamAccount(t, ctx, infra, "pg-crash", pgHost, pgPort)
	LoginUser(t, ctx, infra)
	pamCmd, proxyPort := startPostgresPamAccess(t, ctx, infra, folderName, accountName)
	proxyConn := connectPostgresProxy(t, ctx, infra, pamCmd, proxyPort)
	sessionId := FindPamSessionId(t, ctx, infra, accountName)

	uploaded := []recordedQuery{
		{Input: "CREATE TABLE crash_recording (note text)", Output: "CREATE TABLE"},
		{Input: "INSERT INTO crash_recording VALUES ('uploaded before the crash')", Output: "INSERT 0 1"},
	}
	runQueries(t, ctx, proxyConn, uploaded)
	waitForPlayback(t, ctx, infra, sessionId, func(p SessionPlayback) bool { return len(p.Chunks) > 0 })

	// Written to disk but not uploaded when the gateway dies, so the restarted gateway has to send it.
	onDisk := []recordedQuery{
		{Input: "INSERT INTO crash_recording VALUES ('on disk when the gateway died')", Output: "INSERT 0 1"},
	}
	runQueries(t, ctx, proxyConn, onDisk)

	CrashAndRestartGateway(t, ctx, infra)
	_ = proxyConn.Close(ctx) // the crash already dropped it

	proxyConn = connectPostgresProxy(t, ctx, infra, pamCmd, proxyPort)
	afterRestart := []recordedQuery{
		{Input: "SELECT note FROM crash_recording", Output: "SELECT 2"},
	}
	runQueries(t, ctx, proxyConn, afterRestart)
	require.NoError(t, proxyConn.Close(ctx))
	EndPamAccess(t, infra, pamCmd)

	requirePostgresRecording(t, ctx, infra, sessionId, slices.Concat(uploaded, onDisk, afterRestart))
}

func TestPAM_Postgres_RecordingSurvivesRateLimiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx, WithGatewayAPIProxy())
	pgHost, pgPort := startPostgresTarget(t, ctx)
	folderName, accountName := createPostgresPamAccount(t, ctx, infra, "pg-throttle", pgHost, pgPort)
	LoginUser(t, ctx, infra)
	pamCmd, proxyPort := startPostgresPamAccess(t, ctx, infra, folderName, accountName)
	proxyConn := connectPostgresProxy(t, ctx, infra, pamCmd, proxyPort)
	sessionId := FindPamSessionId(t, ctx, infra, accountName)

	infra.GatewayAPI.ThrottleChunkUploads(true)
	throttled := []recordedQuery{
		{Input: "CREATE TABLE throttled_recording (note text)", Output: "CREATE TABLE"},
		{Input: "INSERT INTO throttled_recording VALUES ('first upload was rate limited')", Output: "INSERT 0 1"},
	}
	runQueries(t, ctx, proxyConn, throttled)
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  30 * time.Second,
		Interval: time.Second,
		Condition: func() helpers.ConditionResult {
			if infra.GatewayAPI.RejectedChunkUploads() == 0 {
				return helpers.ConditionWait
			}
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "gateway should try to upload the recording while the session is open")
	infra.GatewayAPI.ThrottleChunkUploads(false)

	afterThrottle := []recordedQuery{
		{Input: "SELECT note FROM throttled_recording", Output: "SELECT 1"},
	}
	runQueries(t, ctx, proxyConn, afterThrottle)
	require.NoError(t, proxyConn.Close(ctx))
	EndPamAccess(t, infra, pamCmd)

	requirePostgresRecording(t, ctx, infra, sessionId, slices.Concat(throttled, afterThrottle))
}
