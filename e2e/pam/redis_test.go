package pam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/google/uuid"
	"github.com/infisical/cli/e2e-tests/packages/client"
	helpers "github.com/infisical/cli/e2e-tests/util"
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

func createRedisPamResource(t *testing.T, ctx context.Context, infra *PAMTestInfra, name, host string, port int, sslEnabled bool, sslCertificate *string) uuid.UUID {
	resp, err := infra.ApiClient.CreateRedisPamResourceWithResponse(
		ctx,
		client.CreateRedisPamResourceJSONRequestBody{
			ProjectId: uuid.MustParse(infra.ProjectId),
			GatewayId: infra.GatewayId,
			Name:      name,
			ConnectionDetails: struct {
				Host                  string  `json:"host"`
				Port                  float32 `json:"port"`
				SslCertificate        *string `json:"sslCertificate,omitempty"`
				SslEnabled            bool    `json:"sslEnabled"`
				SslRejectUnauthorized bool    `json:"sslRejectUnauthorized"`
			}{
				Host:                  host,
				Port:                  float32(port),
				SslEnabled:            sslEnabled,
				SslCertificate:        sslCertificate,
				SslRejectUnauthorized: false,
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode())
	slog.Info("Created Redis PAM resource", "resourceId", resp.JSON200.Resource.Id, "name", name)
	return resp.JSON200.Resource.Id
}

func createRedisPamAccount(t *testing.T, ctx context.Context, infra *PAMTestInfra, resourceId uuid.UUID, name string, username, password *string) {
	resp, err := infra.ApiClient.CreateRedisPamAccountWithResponse(
		ctx,
		client.CreateRedisPamAccountJSONRequestBody{
			ResourceId: resourceId,
			Name:       name,
			Credentials: struct {
				Password *string `json:"password,omitempty"`
				Username *string `json:"username,omitempty"`
			}{
				Username: username,
				Password: password,
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode())
	slog.Info("Created Redis PAM account", "name", name)
}

func startRedisProxy(t *testing.T, ctx context.Context, infra *PAMTestInfra, resourceName, accountName string) (int, *helpers.Command) {
	freePort := helpers.GetFreePort()
	pamCmd := helpers.Command{
		Test:               t,
		RunMethod:          helpers.RunMethodSubprocess,
		DisableTempHomeDir: true,
		Args: []string{
			"pam", "redis", "access",
			"--resource", resourceName,
			"--account", accountName,
			"--project-id", infra.ProjectId,
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

	// Redis proxy prints the banner to stderr (unlike the Postgres proxy which uses stdout).
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
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	infra := SetupPAMInfra(t, ctx)
	LoginUser(t, ctx, infra)

	t.Run("no-auth", func(t *testing.T) {
		container := startRedisContainer(t, ctx)

		redisHost, err := container.Host(ctx)
		require.NoError(t, err)
		redisPort, err := container.MappedPort(ctx, "6379")
		require.NoError(t, err)
		directAddr := fmt.Sprintf("%s:%d", redisHost, redisPort.Int())

		// Verify Redis is accessible directly.
		rdb := redis.NewClient(&redis.Options{Addr: directAddr})
		pong, err := rdb.Ping(ctx).Result()
		require.NoError(t, err)
		require.Equal(t, "PONG", pong)
		rdb.Close()
		slog.Info("Verified Redis is accessible directly")

		resourceName := "redis-noauth-resource"
		resourceId := createRedisPamResource(t, ctx, infra, resourceName, redisHost, redisPort.Int(), false, nil)
		createRedisPamAccount(t, ctx, infra, resourceId, "redis-noauth-account", nil, nil)

		proxyPort, pamCmd := startRedisProxy(t, ctx, infra, resourceName, "redis-noauth-account")
		proxyAddr := fmt.Sprintf("localhost:%d", proxyPort)

		testKey := "e2e-noauth-key"
		testValue := "e2e-noauth-value"

		verifyRedisThroughProxy(t, ctx, pamCmd, proxyAddr, testKey, testValue)
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
		directAddr := fmt.Sprintf("%s:%d", redisHost, redisPort.Int())

		// Verify Redis is accessible with ACL credentials directly.
		rdb := redis.NewClient(&redis.Options{
			Addr:     directAddr,
			Username: aclUser,
			Password: aclPass,
		})
		pong, err := rdb.Ping(ctx).Result()
		require.NoError(t, err)
		require.Equal(t, "PONG", pong)
		rdb.Close()
		slog.Info("Verified Redis is accessible directly with ACL credentials")

		resourceName := "redis-acl-resource"
		resourceId := createRedisPamResource(t, ctx, infra, resourceName, redisHost, redisPort.Int(), false, nil)
		username := aclUser
		password := aclPass
		createRedisPamAccount(t, ctx, infra, resourceId, "redis-acl-account", &username, &password)

		proxyPort, pamCmd := startRedisProxy(t, ctx, infra, resourceName, "redis-acl-account")
		proxyAddr := fmt.Sprintf("localhost:%d", proxyPort)

		testKey := "e2e-acl-key"
		testValue := "e2e-acl-value"

		verifyRedisThroughProxy(t, ctx, pamCmd, proxyAddr, testKey, testValue)

		// Verify ACL permissions are enforced: FLUSHALL should be denied
		// because the ACL user does not have @dangerous commands.
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

		// Generate self-signed certs at test time.
		certDir := t.TempDir()
		caPEM := generateSelfSignedCert(t, "localhost", certDir)

		// Write a Redis config that enables TLS and sets up the ACL user.
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

		// Start Redis with TLS config and mounted certs.
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
		directAddr := fmt.Sprintf("%s:%d", redisHost, redisPort.Int())

		// Verify Redis is accessible directly with TLS + ACL.
		rdb := redis.NewClient(&redis.Options{
			Addr:     directAddr,
			Username: aclUser,
			Password: aclPass,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		})
		pong, err := rdb.Ping(ctx).Result()
		require.NoError(t, err)
		require.Equal(t, "PONG", pong)
		rdb.Close()
		slog.Info("Verified Redis is accessible directly with TLS + ACL")

		resourceName := "redis-ssl-resource"
		resourceId := createRedisPamResource(t, ctx, infra, resourceName, redisHost, redisPort.Int(), true, &caPEM)
		username := aclUser
		password := aclPass
		createRedisPamAccount(t, ctx, infra, resourceId, "redis-ssl-account", &username, &password)

		proxyPort, pamCmd := startRedisProxy(t, ctx, infra, resourceName, "redis-ssl-account")
		proxyAddr := fmt.Sprintf("localhost:%d", proxyPort)

		testKey := "e2e-ssl-key"
		testValue := "e2e-ssl-value"

		verifyRedisThroughProxy(t, ctx, pamCmd, proxyAddr, testKey, testValue)
	})

	t.Run("multiple-concurrent-connections", func(t *testing.T) {
		container := startRedisContainer(t, ctx)

		redisHost, err := container.Host(ctx)
		require.NoError(t, err)
		redisPort, err := container.MappedPort(ctx, "6379")
		require.NoError(t, err)
		directAddr := fmt.Sprintf("%s:%d", redisHost, redisPort.Int())

		// Verify Redis is accessible directly.
		rdb := redis.NewClient(&redis.Options{Addr: directAddr})
		pong, err := rdb.Ping(ctx).Result()
		require.NoError(t, err)
		require.Equal(t, "PONG", pong)
		rdb.Close()
		slog.Info("Verified Redis is accessible directly")

		resourceName := "redis-concurrent-resource"
		resourceId := createRedisPamResource(t, ctx, infra, resourceName, redisHost, redisPort.Int(), false, nil)
		createRedisPamAccount(t, ctx, infra, resourceId, "redis-concurrent-account", nil, nil)

		proxyPort, _ := startRedisProxy(t, ctx, infra, resourceName, "redis-concurrent-account")
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
