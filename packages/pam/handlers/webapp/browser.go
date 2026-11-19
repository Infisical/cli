package webapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

const (
	browserPathEnv        = "INFISICAL_PAM_BROWSER_PATH"
	browserNoSandboxEnv   = "INFISICAL_PAM_BROWSER_NO_SANDBOX"
	browserMaxSessionsEnv = "INFISICAL_PAM_BROWSER_MAX_SESSIONS"

	defaultMaxBrowserSessions = 5
)

var browserBinaryNames = []string{"chromium-headless-shell", "chromium", "google-chrome"}

// The browser process gets only these variables, so the gateway's own credentials never reach it.
var browserEnvPassthrough = []string{
	"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ",
	"FONTCONFIG_PATH", "FONTCONFIG_FILE",
	"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR",
}

var errRootWithSandbox = errors.New("refusing to start a browser as root: set " + browserNoSandboxEnv + "=true to run it without its sandbox")

// FindBrowserPath returns the browser binary sessions use, or "" when there is none.
func FindBrowserPath() string {
	if path := os.Getenv(browserPathEnv); path != "" {
		if isExecutable(path) {
			return path
		}
		return ""
	}
	for _, name := range browserBinaryNames {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	// Windows has no execute permission bits.
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o111 != 0
}

// IsSupported reports whether this gateway can run web app sessions.
func IsSupported() bool {
	if FindBrowserPath() == "" {
		return false
	}
	_, err := sandboxDisabled(os.Geteuid(), os.Getenv(browserNoSandboxEnv))
	return err == nil
}

// sandboxDisabled decides whether the browser runs without its sandbox. Chromium cannot sandbox
// itself as root, and chromedp would then add --no-sandbox silently, so root needs an explicit opt-in.
func sandboxDisabled(euid int, noSandboxEnv string) (bool, error) {
	disabled := noSandboxEnv == "true"
	if euid == 0 && !disabled {
		return false, errRootWithSandbox
	}
	return disabled, nil
}

func maxBrowserSessions(value string) int {
	if n, err := strconv.Atoi(value); err == nil && n > 0 {
		return n
	}
	return defaultMaxBrowserSessions
}

type sessionLimiter struct {
	mu     sync.Mutex
	active int
}

var browserSessions sessionLimiter

func (l *sessionLimiter) acquire(limit int) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= limit {
		return nil, false
	}
	l.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.active--
			l.mu.Unlock()
		})
	}, true
}

func (l *sessionLimiter) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active
}

type browserConfig struct {
	execPath          string
	noSandbox         bool
	hostResolverRules string
	width, height     int64
	// listener receives every event of the tab, in order, on the tab's message loop.
	listener func(ev any)
	// browserListener receives the events of the browser, such as downloads.
	browserListener func(ev any)
}

type browserInstance struct {
	// ctx is the tab's context. It ends when the browser is lost.
	ctx         context.Context
	cancelTab   context.CancelFunc
	cancelAlloc context.CancelFunc
}

func browserAllocatorOptions(cfg browserConfig) []chromedp.ExecAllocatorOption {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(cfg.execPath),
		chromedp.Flag("headless", true),
		chromedp.Flag("remote-debugging-pipe", true),
		chromedp.Flag("host-resolver-rules", cfg.hostResolverRules),
		chromedp.Flag("block-new-web-contents", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("mute-audio", true),
		chromedp.WindowSize(int(cfg.width), int(cfg.height)),
		chromedp.NoInheritEnv,
		chromedp.Env(passthroughEnv()...),
	}
	// chromedp adds --no-sandbox as root unless the flag is set, so set it either way.
	opts = append(opts, chromedp.Flag("no-sandbox", cfg.noSandbox))
	return opts
}

func passthroughEnv() []string {
	var env []string
	for _, name := range browserEnvPassthrough {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// launchBrowser starts a browser with a fresh profile and attaches to its first tab. chromedp
// creates the profile in a temporary directory and removes it once the process has exited.
func launchBrowser(ctx context.Context, cfg browserConfig) (*browserInstance, error) {
	if cfg.noSandbox {
		log.Warn().Msg("Starting a PAM web app browser without its sandbox, so sessions are not isolated from each other")
	}
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, browserAllocatorOptions(cfg)...)
	tabCtx, cancelTab := chromedp.NewContext(allocCtx, chromedp.WithListener(cfg.listener))
	b := &browserInstance{ctx: tabCtx, cancelTab: cancelTab, cancelAlloc: cancelAlloc}

	if err := chromedp.Do(tabCtx); err != nil {
		b.close()
		return nil, fmt.Errorf("start browser: %w", err)
	}
	if cfg.browserListener != nil {
		if err := chromedp.ListenBrowser(tabCtx, cfg.browserListener); err != nil {
			b.close()
			return nil, fmt.Errorf("listen to browser events: %w", err)
		}
	}
	return b, nil
}

// pid is the browser's process id, or 0 when it is not known.
func (b *browserInstance) pid() int {
	if c := chromedp.FromContext(b.ctx); c != nil && c.Browser != nil {
		if p := c.Browser.Process(); p != nil {
			return p.Pid
		}
	}
	return 0
}

// close kills the browser and waits until its profile directory is removed.
func (b *browserInstance) close() {
	b.cancelTab()
	b.cancelAlloc()
}
