package clickhouse

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPythonClickHouseDriver(t *testing.T) {
	if os.Getenv("PAM_CLICKHOUSE_NATIVE_IT") != "1" {
		t.Skip("set PAM_CLICKHOUSE_NATIVE_IT=1 to run")
	}

	port := startProxy(t, baseConfig(&recordingLogger{}))

	script := `
import clickhouse_driver, sys
c = clickhouse_driver.Client(host=sys.argv[1], port=int(sys.argv[2]), user='wrong', password='wrong', database='ignored')
print("currentUser:", c.execute("SELECT currentUser()")[0][0])
print("count:", c.execute("SELECT count() FROM users")[0][0])
print("exotic:", c.execute("SELECT map('a', 1::UInt64), tuple('p', 2)")[0])
print("multi:", c.execute("SELECT 1")[0][0], c.execute("SELECT 2")[0][0])
`
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "python:3.12-slim", "bash", "-lc",
		"pip install --quiet clickhouse-driver >/dev/null 2>&1 && python -c \""+strings.ReplaceAll(script, `"`, `\"`)+"\" "+
			envOr("PAM_CLICKHOUSE_CLIENT_HOST", "host.docker.internal")+" "+port)

	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("clickhouse-driver failed: %v", err)
	}
	for _, want := range []string{"currentUser: default", "count: 250", "multi: 1 2"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("expected %q in output", want)
		}
	}
}
