package cdp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	defaultWindowWidth  = 1280
	defaultWindowHeight = 800
	launchTimeout       = 30 * time.Second
	stopTimeout         = 5 * time.Second
	stderrCaptureBytes  = 4096
)

type Launcher interface {
	Launch(ctx context.Context, opts LaunchOptions) (*Instance, error)
}

type LaunchOptions struct {
	WindowWidth  int
	WindowHeight int
}

type Instance struct {
	CDPURL string

	done     <-chan struct{}
	stop     func()
	stopOnce sync.Once
}

func (i *Instance) Done() <-chan struct{} {
	return i.done
}

func (i *Instance) Stop() {
	i.stopOnce.Do(i.stop)
}

type ExecLauncherConfig struct {
	BinaryPath string
	// Empty means the system temp dir.
	ProfileRoot string
	// Demos only, as a non-root user.
	NoSandbox bool
}

type ExecLauncher struct {
	config ExecLauncherConfig
}

func NewExecLauncher(config ExecLauncherConfig) *ExecLauncher {
	return &ExecLauncher{config: config}
}

func (l *ExecLauncher) Launch(ctx context.Context, opts LaunchOptions) (*Instance, error) {
	if l.config.ProfileRoot != "" {
		if err := os.MkdirAll(l.config.ProfileRoot, 0o700); err != nil {
			return nil, fmt.Errorf("failed to create browser profile root: %w", err)
		}
	}
	profileDir, err := os.MkdirTemp(l.config.ProfileRoot, "profile-")
	if err != nil {
		return nil, fmt.Errorf("failed to create browser profile: %w", err)
	}

	stderr := &headBuffer{limit: stderrCaptureBytes}
	cmd := exec.Command(l.config.BinaryPath, l.args(profileDir, opts)...)
	cmd.Env = browserEnv(profileDir)
	cmd.Stderr = stderr
	// Renderers inherit stderr; don't let one that outlives the browser hold Wait open.
	cmd.WaitDelay = time.Second
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(profileDir)
		return nil, fmt.Errorf("failed to start browser: %w", err)
	}

	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	stop := func() {
		// Once the browser has exited its pid may be reused, so only signal a live one.
		select {
		case <-done:
		default:
			killProcessGroup(cmd)
		}
		select {
		case <-done:
		case <-time.After(stopTimeout):
			log.Warn().Int("pid", cmd.Process.Pid).Msg("Browser did not exit after being killed")
		}
		if err := os.RemoveAll(profileDir); err != nil {
			log.Warn().Err(err).Str("profileDir", profileDir).Msg("Failed to remove browser profile")
		}
	}

	cdpURL, err := waitForDevTools(ctx, profileDir, done)
	if err != nil {
		stop()
		if output := stderr.String(); output != "" {
			return nil, fmt.Errorf("%w; browser output: %s", err, output)
		}
		return nil, err
	}

	log.Debug().Int("pid", cmd.Process.Pid).Str("profileDir", profileDir).Msg("Browser launched")
	return &Instance{CDPURL: cdpURL, done: done, stop: stop}, nil
}

func (l *ExecLauncher) args(profileDir string, opts LaunchOptions) []string {
	width, height := opts.WindowWidth, opts.WindowHeight
	if width <= 0 || height <= 0 {
		width, height = defaultWindowWidth, defaultWindowHeight
	}
	args := []string{
		"--remote-debugging-port=0",
		"--user-data-dir=" + profileDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--renderer-process-limit=1",
		"--disable-extensions",
		"--disable-background-networking",
		"--disable-sync",
		"--js-flags=--max-old-space-size=256",
		fmt.Sprintf("--window-size=%d,%d", width, height),
	}
	// The headless shell is always headless; full Chromium has to be asked.
	if !strings.Contains(filepath.Base(l.config.BinaryPath), "headless") {
		args = append(args, "--headless=new")
	}
	// Chromium refuses to start with --no-zygote while its sandbox is on.
	if l.config.NoSandbox {
		args = append(args, "--no-sandbox", "--no-zygote")
	}
	return append(args, "about:blank")
}

// Not the gateway's environment, which holds its credentials.
func browserEnv(profileDir string) []string {
	env := []string{"HOME=" + profileDir}
	for _, name := range []string{"PATH", "LD_LIBRARY_PATH", "LANG", "LC_ALL", "TZ", "FONTCONFIG_PATH", "SYSTEMROOT"} {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// Chromium writes its port, then the browser target's path, once DevTools is listening.
func waitForDevTools(ctx context.Context, profileDir string, exited <-chan struct{}) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, launchTimeout)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	portFile := filepath.Join(profileDir, "DevToolsActivePort")
	for {
		if data, err := os.ReadFile(portFile); err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) == 2 {
				port, err := strconv.Atoi(strings.TrimSpace(lines[0]))
				path := strings.TrimSpace(lines[1])
				if err == nil && port > 0 && strings.HasPrefix(path, "/devtools/browser/") {
					return fmt.Sprintf("ws://127.0.0.1:%d%s", port, path), nil
				}
			}
		}
		select {
		case <-exited:
			return "", errors.New("browser exited before its DevTools endpoint came up")
		case <-ctx.Done():
			return "", fmt.Errorf("browser DevTools endpoint did not come up: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

type headBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (b *headBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.limit - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *headBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(b.buf.String())
}
