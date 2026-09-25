package clickhouse

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// runClient drives the real clickhouse-client against the session's port, which is the only way to cover
// revision pinning, the addendum and block framing as a real driver produces them.
func runClient(t *testing.T, port string, sql string, extra ...string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	args := []string{
		"run", "--rm", "-i", "clickhouse/clickhouse-server:24.8", "clickhouse-client",
		"--host", envOr("PAM_CLICKHOUSE_CLIENT_HOST", "host.docker.internal"),
		"--port", port,
		// Deliberately wrong: the gateway replaces them with the account's.
		"--user", "not-the-account", "--password", "not-the-password",
		"--multiquery",
	}
	args = append(args, extra...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = strings.NewReader(sql)

	out, err := cmd.CombinedOutput()
	return string(out), err
}

// postStatementE is the non-asserting form. require.* calls t.FailNow, which is illegal off the test
// goroutine, so anything running in parallel has to report failures over a channel instead.
func postStatementE(addr string, sql string) (int, string, error) {
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/", strings.NewReader(sql))
	if err != nil {
		return 0, "", err
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

func postGET(t *testing.T, addr string, path string) (int, string) {
	t.Helper()

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Get("http://" + addr + path)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func postGzipped(t *testing.T, addr string, sql string) (int, string) {
	t.Helper()

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write([]byte(sql))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/", &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func urlEscape(v string) string { return url.QueryEscape(v) }
