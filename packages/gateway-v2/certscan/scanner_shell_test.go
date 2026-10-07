package certscan

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type shellRunner struct {
	mu       sync.Mutex
	commands []string
}

func (r *shellRunner) Run(ctx context.Context, command string, outputLimit int) (RunResult, error) {
	r.mu.Lock()
	r.commands = append(r.commands, command)
	r.mu.Unlock()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := RunResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if len(res.Stdout) > outputLimit {
		res.Stdout, res.Truncated = res.Stdout[:outputLimit], true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, err
}

func TestScanReadsRealFilesThroughTheHostShell(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the scan commands target Linux hosts")
	}
	p := newTestPKI(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw})
	dir := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cert := write("a.pem", leafPEM, 0o644)
	quoted := write("it's a cert.pem", leafPEM, 0o644)
	big := write("big.pem", bytes.Repeat([]byte{'x'}, 2048), 0o644)
	denied := write("denied.pem", leafPEM, 0o000)
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(cert, link); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.pem")

	runner := &shellRunner{}
	resp, err := normalizedScan(t, context.Background(), runner, Request{
		FilePaths:        []string{cert, quoted, big, denied, link, missing},
		MaxFileSizeBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]FileResult{}
	for _, f := range resp.Files {
		byPath[f.Path] = f
	}
	want := map[string]FileStatus{cert: StatusOK, quoted: StatusOK, big: StatusTooLarge, missing: StatusNotFound}
	if os.Geteuid() != 0 {
		want[denied] = StatusAccessDenied
	}
	for path, status := range want {
		if byPath[path].Status != status {
			t.Fatalf("expected %s for %s, got %+v", status, path, byPath[path])
		}
	}
	if byPath[cert].RealPath != cert || len(byPath[cert].Chains) == 0 {
		t.Fatalf("unexpected result %+v", byPath[cert])
	}
	if _, ok := byPath[link]; ok {
		t.Fatal("a symlink to a file already reported must not be reported again")
	}
	for _, c := range runner.commands {
		if strings.Contains(c, "readlink -f -- '") {
			t.Fatalf("expected the batch read to cover every readable file, got a per-file read %q", c)
		}
	}
}
