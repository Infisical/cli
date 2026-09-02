package gatewayv2

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"
)

// fakeRedis answers one AUTH with the supplied reply, then closes.
func fakeRedis(t *testing.T, authReply string) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if len(line) > 0 && line[0] == '*' {
						continue
					}
					if _, err := conn.Write([]byte(authReply + "\r\n")); err != nil {
						return
					}
					return
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestRedisProbePhases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("rejected password is auth", func(t *testing.T) {
		port := fakeRedis(t, "-WRONGPASS invalid username-password pair")
		err := doRedisConnectionTest(ctx, "127.0.0.1", port, redisTestParams{Password: "nope"})
		if got := classifyTestConnFailure(err); got != failureKindAuth {
			t.Fatalf("got %q (%v), want %q", got, err, failureKindAuth)
		}
	})

	t.Run("unreachable target is transport", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve port: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()

		err = doRedisConnectionTest(ctx, "127.0.0.1", port, redisTestParams{Password: "pw"})
		if got := classifyTestConnFailure(err); got != failureKindTransport {
			t.Fatalf("got %q (%v), want %q", got, err, failureKindTransport)
		}
	})
}

func TestTCPProbeIsAlwaysTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	err = doTCPReachabilityTest(context.Background(), "127.0.0.1", port)
	if got := classifyTestConnFailure(err); got != failureKindTransport {
		t.Fatalf("got %q (%v), want %q", got, err, failureKindTransport)
	}
}

// Every failure a probe returns has to name its phase. An untagged one reaches the control plane as
// "unclassified", which it treats as a rejected credential and stops checking the account for.
func TestConfigFailuresAreNotReadAsRejectedCredentials(t *testing.T) {
	ctx := liveCtxShort(t)
	const badCA = "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----"

	cases := []struct {
		name string
		run  func() error
	}{
		{"sql/unsupported dialect", func() error {
			port := reachablePort(t)
			return doSQLConnectionTest(ctx, "127.0.0.1", port, sqlTestParams{Dialect: "oracle", Username: "u"})
		}},
		{"sql/unparseable CA", func() error {
			port := reachablePort(t)
			return doSQLConnectionTest(ctx, "127.0.0.1", port, sqlTestParams{
				Dialect: "postgres", Username: "u", SslEnabled: true, SslCertificate: badCA,
			})
		}},
		{"mongo/unparseable CA", func() error {
			return doMongoConnectionTest(ctx, "127.0.0.1", reachablePort(t), mongoTestParams{
				Username: "u", SslEnabled: true, SslCertificate: badCA,
			})
		}},
		{"redis/unparseable CA", func() error {
			return doRedisConnectionTest(ctx, "127.0.0.1", reachablePort(t), redisTestParams{
				Password: "pw", SslEnabled: true, SslCertificate: badCA,
			})
		}},
		{"ldap/unparseable CA", func() error {
			return doLdapConnectionTest(ctx, "127.0.0.1", reachablePort(t), ldapTestParams{
				Username: "cn=admin", Password: "pw", UseLdaps: true, LdapCaCert: badCA,
			})
		}},
		{"kubernetes/unparseable CA", func() error {
			return doKubernetesConnectionTest(ctx, "127.0.0.1", reachablePort(t), kubernetesTestParams{
				Token: "t", SslCertificate: badCA,
			})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("expected a failure")
			}
			if got := classifyTestConnFailure(err); got == failureKindUnknown {
				t.Fatalf("got %q, which the control plane reads as a rejected credential (err: %v)", got, err)
			}
		})
	}
}

// reachablePort accepts connections and hangs up, so the probe's reachability dial passes and the failure
// under test is the one the case is about.
func reachablePort(t *testing.T) int {
	t.Helper()
	return hangupPort(t)
}

func liveCtxShort(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
