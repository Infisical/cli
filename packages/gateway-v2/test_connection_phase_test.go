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
