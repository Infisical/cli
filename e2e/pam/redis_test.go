package pam

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
	openapitypes "github.com/oapi-codegen/runtime/types"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func startRedisContainer(t *testing.T, ctx context.Context, opts ...testcontainers.ContainerCustomizer) *tcredis.RedisContainer {
	container, err := tcredis.Run(ctx, "redis:8.4.0", opts...)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate Redis container: %v", err)
		}
	})
	return container
}

// createRedisPamAccount creates a Redis account in the given folder/template. There is no generated
// client method for Redis on this branch (the account type isn't wired into the backend yet), so the
// request is a raw authenticated POST. Account creation runs a connection test through the gateway,
// so it is retried while things settle.
func createRedisPamAccount(t *testing.T, ctx context.Context, infra *PAMTestInfra, folderId, templateId openapitypes.UUID, name, host string, port int, sslEnabled bool, sslCertificate, username, password *string) {
	gatewayId := infra.GatewayId

	connectionDetails := map[string]interface{}{
		"host":                  host,
		"port":                  port,
		"sslEnabled":            sslEnabled,
		"sslRejectUnauthorized": false,
	}
	if sslCertificate != nil {
		connectionDetails["sslCertificate"] = *sslCertificate
	}
	credentials := map[string]interface{}{}
	if username != nil {
		credentials["username"] = *username
	}
	if password != nil {
		credentials["password"] = *password
	}

	body, err := json.Marshal(map[string]interface{}{
		"folderId":          folderId.String(),
		"templateId":        templateId.String(),
		"gatewayId":         gatewayId.String(),
		"name":              name,
		"connectionDetails": connectionDetails,
		"credentials":       credentials,
	})
	require.NoError(t, err)

	url := fmt.Sprintf("%s/api/v1/pam/accounts/redis", infra.Infisical.ApiUrl(t))
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		Timeout:  90 * time.Second,
		Interval: 3 * time.Second,
		Condition: func() helpers.ConditionResult {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if reqErr != nil {
				slog.Warn("Redis PAM account request build failed, retrying...", "error", reqErr)
				return helpers.ConditionWait
			}
			req.Header.Set("Authorization", "Bearer "+infra.ProvisionResult.Token)
			req.Header.Set("Content-Type", "application/json")

			resp, callErr := http.DefaultClient.Do(req)
			if callErr != nil {
				slog.Warn("Redis PAM account creation attempt failed, retrying...", "error", callErr)
				return helpers.ConditionWait
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				buf := new(bytes.Buffer)
				_, _ = buf.ReadFrom(resp.Body)
				slog.Warn("Redis PAM account creation returned non-200, retrying...", "status", resp.StatusCode, "body", buf.String())
				return helpers.ConditionWait
			}
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, result, "Redis PAM account creation should succeed for %s", name)
	slog.Info("Created Redis PAM account", "name", name)
}

func startRedisProxy(t *testing.T, ctx context.Context, infra *PAMTestInfra, folderName, accountName string) (int, *helpers.Command) {
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

	// The Redis proxy prints its banner to stderr.
	result := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: &pamCmd,
		Condition: func() helpers.ConditionResult {
			if strings.Contains(pamCmd.Stderr(), "Redis Proxy Session Started") {
				return helpers.ConditionSuccess
			}
			return helpers.ConditionWait
		},
	})
	if result != helpers.WaitSuccess {
		pamCmd.DumpOutput()
	}
	require.Equal(t, helpers.WaitSuccess, result, "Redis proxy should start successfully")

	return freePort, &pamCmd
}

func verifyRedisThroughProxy(t *testing.T, ctx context.Context, pamCmd *helpers.Command, proxyAddr, testKey, testValue string) {
	var rdb *redis.Client
	connectResult := helpers.WaitFor(t, helpers.WaitForOptions{
		EnsureCmdRunning: pamCmd,
		Interval:         2 * time.Second,
		Timeout:          30 * time.Second,
		Condition: func() helpers.ConditionResult {
			rdb = redis.NewClient(&redis.Options{Addr: proxyAddr})
			_, err := rdb.Ping(ctx).Result()
			if err != nil {
				rdb.Close()
				slog.Warn("Redis proxy connection attempt failed, retrying...", "error", err)
				return helpers.ConditionWait
			}
			return helpers.ConditionSuccess
		},
	})
	require.Equal(t, helpers.WaitSuccess, connectResult, "Should connect to Redis through proxy")
	t.Cleanup(func() { rdb.Close() })

	err := rdb.Set(ctx, testKey, testValue, 0).Err()
	require.NoError(t, err)
	slog.Info("SET through proxy succeeded", "key", testKey)

	got, err := rdb.Get(ctx, testKey).Result()
	require.NoError(t, err)
	require.Equal(t, testValue, got)
	slog.Info("GET through proxy succeeded", "key", testKey, "value", got)
}

// generateSelfSignedCert creates a self-signed CA and server certificate for TLS tests.
// Returns the CA PEM, and writes the server cert + key to the given directory.
func generateSelfSignedCert(t *testing.T, host, certDir string) (caPEM string) {
	// Generate CA key and certificate.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "e2e-test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Generate server key and certificate signed by the CA.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host, "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})

	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	// Write files to cert directory.
	require.NoError(t, os.WriteFile(filepath.Join(certDir, "ca.crt"), caCertPEM, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(certDir, "server.crt"), serverCertPEM, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(certDir, "server.key"), serverKeyPEM, 0600))

	return string(caCertPEM)
}

func TestPAM_Redis(t *testing.T) {
	// Redis PAM support is not wired into the backend on this branch (no Redis account type), so there
	// is no create-account endpoint yet. This test is written against the new folder/template/account
	// model as if Redis were available; remove the skip once the Redis feature lands.
	t.Skip("Redis PAM not available on this branch; remove skip once the Redis feature lands")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)
	LoginUser(t, ctx, infra)

	folderName := "redis-folder"
	folderId := CreatePamFolder(t, ctx, infra, folderName)
	templateId := CreatePamTemplate(t, ctx, infra, "redis-template", client.CreatePamAccountTemplateJSONBodyTypeRedis)

	defaultUser := "default"

	t.Run("no-auth", func(t *testing.T) {
		container := startRedisContainer(t, ctx)

		redisHost, err := container.Host(ctx)
		require.NoError(t, err)
		redisPort, err := container.MappedPort(ctx, "6379")
		require.NoError(t, err)

		// Verify Redis is accessible directly.
		rdb := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%d", redisHost, redisPort.Int())})
		pong, err := rdb.Ping(ctx).Result()
		require.NoError(t, err)
		require.Equal(t, "PONG", pong)
		rdb.Close()

		accountName := "redis-noauth-account"
		createRedisPamAccount(t, ctx, infra, folderId, templateId, accountName, redisHost, redisPort.Int(), false, nil, &defaultUser, nil)

		proxyPort, pamCmd := startRedisProxy(t, ctx, infra, folderName, accountName)
		verifyRedisThroughProxy(t, ctx, pamCmd, fmt.Sprintf("localhost:%d", proxyPort), "e2e-noauth-key", "e2e-noauth-value")
	})

	t.Run("acl-user-password", func(t *testing.T) {
		const (
			aclUser = "pamuser"
			aclPass = "pampassword"
		)

		confDir := t.TempDir()
		redisConf := fmt.Sprintf(`user default off
user %s on >%s ~* +@all -@dangerous
`, aclUser, aclPass)
		confPath := filepath.Join(confDir, "redis.conf")
		require.NoError(t, os.WriteFile(confPath, []byte(redisConf), 0644))

		container := startRedisContainer(t, ctx, tcredis.WithConfigFile(confPath))

		redisHost, err := container.Host(ctx)
		require.NoError(t, err)
		redisPort, err := container.MappedPort(ctx, "6379")
		require.NoError(t, err)

		// Verify Redis is accessible with ACL credentials directly.
		rdb := redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%d", redisHost, redisPort.Int()),
			Username: aclUser,
			Password: aclPass,
		})
		pong, err := rdb.Ping(ctx).Result()
		require.NoError(t, err)
		require.Equal(t, "PONG", pong)
		rdb.Close()

		accountName := "redis-acl-account"
		username := aclUser
		password := aclPass
		createRedisPamAccount(t, ctx, infra, folderId, templateId, accountName, redisHost, redisPort.Int(), false, nil, &username, &password)

		proxyPort, pamCmd := startRedisProxy(t, ctx, infra, folderName, accountName)
		proxyAddr := fmt.Sprintf("localhost:%d", proxyPort)
		verifyRedisThroughProxy(t, ctx, pamCmd, proxyAddr, "e2e-acl-key", "e2e-acl-value")

		// ACL permissions are enforced: FLUSHALL is @dangerous and must be denied.
		proxyClient := redis.NewClient(&redis.Options{Addr: proxyAddr})
		t.Cleanup(func() { proxyClient.Close() })
		err = proxyClient.FlushAll(ctx).Err()
		require.Error(t, err, "FLUSHALL should be denied for the ACL user")
		slog.Info("FLUSHALL correctly denied through proxy", "error", err)
	})

	t.Run("acl-over-ssl", func(t *testing.T) {
		const (
			aclUser = "pamuser"
			aclPass = "pampassword"
		)

		certDir := t.TempDir()
		caPEM := generateSelfSignedCert(t, "localhost", certDir)

		redisConf := fmt.Sprintf(`tls-port 6379
port 0
tls-cert-file /tls/server.crt
tls-key-file /tls/server.key
tls-ca-cert-file /tls/ca.crt
tls-auth-clients no

user default off
user %s on >%s ~* +@all -@dangerous
`, aclUser, aclPass)
		confPath := filepath.Join(certDir, "redis-ssl.conf")
		require.NoError(t, os.WriteFile(confPath, []byte(redisConf), 0644))

		container := startRedisContainer(t, ctx,
			tcredis.WithConfigFile(confPath),
			testcontainers.WithFiles(testcontainers.ContainerFile{
				HostFilePath:      filepath.Join(certDir, "ca.crt"),
				ContainerFilePath: "/tls/ca.crt",
				FileMode:          0644,
			}),
			testcontainers.WithFiles(testcontainers.ContainerFile{
				HostFilePath:      filepath.Join(certDir, "server.crt"),
				ContainerFilePath: "/tls/server.crt",
				FileMode:          0644,
			}),
			testcontainers.WithFiles(testcontainers.ContainerFile{
				HostFilePath:      filepath.Join(certDir, "server.key"),
				ContainerFilePath: "/tls/server.key",
				FileMode:          0644,
			}),
		)

		redisHost, err := container.Host(ctx)
		require.NoError(t, err)
		redisPort, err := container.MappedPort(ctx, "6379")
		require.NoError(t, err)

		// Verify Redis is accessible directly with TLS + ACL.
		rdb := redis.NewClient(&redis.Options{
			Addr:      fmt.Sprintf("%s:%d", redisHost, redisPort.Int()),
			Username:  aclUser,
			Password:  aclPass,
			TLSConfig: &tls.Config{InsecureSkipVerify: true},
		})
		pong, err := rdb.Ping(ctx).Result()
		require.NoError(t, err)
		require.Equal(t, "PONG", pong)
		rdb.Close()

		accountName := "redis-ssl-account"
		username := aclUser
		password := aclPass
		createRedisPamAccount(t, ctx, infra, folderId, templateId, accountName, redisHost, redisPort.Int(), true, &caPEM, &username, &password)

		proxyPort, pamCmd := startRedisProxy(t, ctx, infra, folderName, accountName)
		verifyRedisThroughProxy(t, ctx, pamCmd, fmt.Sprintf("localhost:%d", proxyPort), "e2e-ssl-key", "e2e-ssl-value")
	})

	t.Run("multiple-concurrent-connections", func(t *testing.T) {
		container := startRedisContainer(t, ctx)

		redisHost, err := container.Host(ctx)
		require.NoError(t, err)
		redisPort, err := container.MappedPort(ctx, "6379")
		require.NoError(t, err)

		accountName := "redis-concurrent-account"
		createRedisPamAccount(t, ctx, infra, folderId, templateId, accountName, redisHost, redisPort.Int(), false, nil, &defaultUser, nil)

		proxyPort, _ := startRedisProxy(t, ctx, infra, folderName, accountName)
		proxyAddr := fmt.Sprintf("localhost:%d", proxyPort)

		const numClients = 5
		var wg sync.WaitGroup
		errs := make([]error, numClients)

		for i := 0; i < numClients; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				rdb := redis.NewClient(&redis.Options{Addr: proxyAddr})
				defer rdb.Close()

				key := fmt.Sprintf("e2e-concurrent-key-%d", idx)
				value := fmt.Sprintf("e2e-concurrent-value-%d", idx)

				if err := rdb.Set(ctx, key, value, 0).Err(); err != nil {
					errs[idx] = fmt.Errorf("SET failed for client %d: %w", idx, err)
					return
				}
				got, err := rdb.Get(ctx, key).Result()
				if err != nil {
					errs[idx] = fmt.Errorf("GET failed for client %d: %w", idx, err)
					return
				}
				if got != value {
					errs[idx] = fmt.Errorf("client %d: expected %q, got %q", idx, value, got)
				}
			}(i)
		}

		wg.Wait()
		for i, err := range errs {
			require.NoError(t, err, "concurrent client %d should succeed", i)
		}
		slog.Info("All concurrent connections succeeded", "numClients", numClients)
	})
}
