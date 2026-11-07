package webapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

type Options struct {
	Image         string
	EgressNetwork string
	Memory        string
	CPUs          string
	SpoolMaxBytes int64
	MaxSessions   int
	Seccomp       string
}

func DefaultOptions() Options {
	return Options{EgressNetwork: "bridge", Memory: "1g", CPUs: "1.0", SpoolMaxBytes: 2 << 30, MaxSessions: 4}
}

type RuntimeStatus struct {
	Image         string    `json:"image"`
	Chromium      string    `json:"chromium"`
	LastCheckedAt time.Time `json:"lastCheckedAt"`
	Error         string    `json:"error,omitempty"`
}

var runtimeReady atomic.Bool
var runtimeStatus atomic.Pointer[RuntimeStatus]

func Ready() bool { return runtimeReady.Load() }
func Status() RuntimeStatus {
	if s := runtimeStatus.Load(); s != nil {
		status := *s
		status.Error = truncate(status.Error, 500)
		return status
	}
	return RuntimeStatus{}
}

type Docker interface {
	Command(context.Context, ...string) (string, error)
	Start(context.Context, string) (*worker, error)
}

type dockerCLI struct{}

func (dockerCLI) Command(ctx context.Context, args ...string) (string, error) {
	timeout := 10 * time.Second
	if len(args) > 0 && (args[0] == "build" || args[0] == "pull") {
		timeout = 10 * time.Minute
	} else if len(args) > 0 && args[0] == "run" && slices.Contains(args, "--probe") {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr boundedBuffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return string(b) + "\n" + stderr.String(), fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(b)), nil
}

type worker struct {
	stderr *boundedBuffer

	id    string
	mux   *Mux
	cdp   *cdpClient
	done  chan struct{}
	input io.WriteCloser
	cmd   *exec.Cmd
	err   error
}

func (dockerCLI) Start(ctx context.Context, id string) (*worker, error) {
	cmd := exec.CommandContext(ctx, "docker", "start", "--attach", "--interactive", id)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	var stderr boundedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		in.Close()
		return nil, err
	}
	w := &worker{id: id, mux: NewMux(out, in), done: make(chan struct{}), input: in, cmd: cmd, stderr: &stderr}
	w.cdp = newCDP(w.mux)
	go func() {
		err := cmd.Wait()
		if err != nil {
			w.err = fmt.Errorf("worker exited: %w: %s", err, stderr.String())
		}
		close(w.done)
	}()
	return w, nil
}

type boundedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.Len() < 64<<10 {
		_, _ = b.Buffer.Write(p[:min(n, (64<<10)-b.Len())])
	}
	return n, nil
}
func (b *boundedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.Buffer.String() }

func (w *worker) control(ctx context.Context, msg any) error {
	result := make(chan error, 1)
	go func() { result <- w.mux.Control(msg) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return errors.New("worker stopped")
	}
}

func (w *worker) ready(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-w.done:
		return "", fmt.Errorf("worker stopped before ready: %w", w.err)
	case raw := <-w.cdp.controls:
		var message struct {
			C        string `json:"c"`
			Chromium string `json:"chromium"`
		}
		if json.Unmarshal(raw, &message) != nil || message.C != "ready" {
			return "", errors.New("worker did not report ready")
		}
		return message.Chromium, nil
	}
}

func containerArgs(options Options, gatewayID, id, volume, role string, gen uint32, expiry, lease time.Time, width, height int) []string {
	args := []string{"create", "--interactive", "--log-driver", "none", "--name", "pam-" + id + "-" + role, "--read-only", "--tmpfs", "/tmp:size=256m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--label", "infisical.pam.gateway=" + gatewayID, "--label", "infisical.pam.session=" + id, "--label", "infisical.pam.alloc=" + strconv.FormatUint(uint64(gen), 10)}
	if role == "browser" {
		// Only loopback exists in this namespace; the Unix connector socket is the sole egress path.
		args = append(args, "--network", "none", "--tmpfs", "/home/worker:size=512m,uid=10001,gid=10001", "--security-opt", "seccomp="+options.Seccomp, "--pids-limit", "512", "--memory", options.Memory, "--cpus", options.CPUs, "--volume", volume+":/run/pam:ro", options.Image, "pam", "browser-shim")
	} else {
		args = append(args, "--network", options.EgressNetwork, "--pids-limit", "128", "--memory", "256m", "--volume", volume+":/run/pam:rw", options.Image, "pam", "browser-connector")
	}
	args = append(args, "--hard-expiry", strconv.FormatInt(expiry.UnixMilli(), 10), "--lease-until", strconv.FormatInt(lease.UnixMilli(), 10), "--lease-seconds", strconv.Itoa(max(0, int(time.Until(lease)/time.Second))))
	if role == "browser" {
		args = append(args, "--width", strconv.Itoa(width), "--height", strconv.Itoa(height))
	}
	return args
}

func CheckRuntime(ctx context.Context, options *Options, gatewayID string) (err error) {
	runtimeReady.Store(false)
	status := RuntimeStatus{Image: options.Image, LastCheckedAt: time.Now()}
	defer func() {
		if err != nil {
			status.Error = truncate(err.Error(), 500)
		}
		runtimeStatus.Store(&status)
		runtimeReady.Store(err == nil)
	}()
	if options.Image == "" {
		return errors.New("configure --pam-browser-image with a qualified worker image")
	}
	if options.MaxSessions < 1 || options.SpoolMaxBytes < 1 {
		return errors.New("invalid browser capacity or spool limit")
	}
	if _, err := strconv.ParseFloat(options.CPUs, 64); err != nil {
		return err
	}
	d := dockerCLI{}
	if _, err = d.Command(ctx, "info", "--format", "{{.ServerVersion}}"); err != nil {
		return err
	}
	image, inspectErr := d.Command(ctx, "image", "inspect", "--format", "{{.Id}}", options.Image)
	if inspectErr != nil {
		if _, err = d.Command(ctx, "pull", options.Image); err != nil {
			return err
		}
		image, err = d.Command(ctx, "image", "inspect", "--format", "{{.Id}}", options.Image)
		if err != nil {
			return err
		}
	}
	if !strings.HasPrefix(image, "sha256:") {
		return errors.New("image digest missing")
	}
	options.Image = image
	status.Image = image
	if err = os.MkdirAll(filepath.Join(session.GetSessionRecordingDir(), "webapp"), 0700); err != nil {
		return err
	}
	probe, err := os.CreateTemp(filepath.Join(session.GetSessionRecordingDir(), "webapp"), "write-probe-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	_, err = probe.Write([]byte("probe"))
	if err == nil {
		err = probe.Sync()
	}
	probe.Close()
	os.Remove(name)
	if err != nil {
		return err
	}
	if options.Seccomp == "" {
		options.Seccomp = filepath.Join(session.GetSessionRecordingDir(), "webapp", "pam-browser-seccomp.json")
		if err = session.AtomicWrite(options.Seccomp, []byte(seccompProfile)); err != nil {
			return err
		}
	}
	id := "self-test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	args := containerArgs(*options, gatewayID, id, "pam-"+id, "browser", 0, time.Now().Add(15*time.Second), time.Now().Add(10*time.Second), 1280, 720)
	// Self-test has no egress socket or volume; it must qualify the fully isolated runtime.
	for i := 0; i < len(args); i++ {
		if args[i] == "--volume" {
			args = append(args[:i], args[i+2:]...)
			break
		}
	}
	args = append(args, "--self-test")
	containerID, err := d.Command(ctx, args...)
	if err != nil {
		return err
	}
	defer d.Command(context.Background(), "rm", "--force", containerID)
	output, err := d.Command(ctx, "start", "--attach", containerID)
	if err != nil {
		return err
	}
	m := NewMux(bytes.NewReader([]byte(output)), io.Discard)
	ch, b, err := m.Read()
	if err != nil || ch != MuxControl {
		return errors.New("self-test did not return framed readiness")
	}
	var ready struct {
		C        string `json:"c"`
		Chromium string `json:"chromium"`
		Network  string `json:"network"`
	}
	if json.Unmarshal(b, &ready) != nil || ready.C != "ready" || ready.Network != "unreachable" || !supportedBrowser(ready.Chromium) {
		return errors.New("hardened browser self-test failed")
	}
	status.Chromium = ready.Chromium
	return nil
}
