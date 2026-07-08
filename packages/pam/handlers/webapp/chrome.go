package webapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// chromeCandidates lists binary names/paths tried, in order, to locate a
// Chromium-family browser on the gateway host. CHROME_PATH overrides all of them when set.
var chromeCandidates = []string{
	"google-chrome-stable",
	"google-chrome",
	"chromium",
	"chromium-browser",
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
}

func findChromeBinary() (string, error) {
	if p := os.Getenv("CHROME_PATH"); p != "" {
		return p, nil
	}
	for _, candidate := range chromeCandidates {
		if strings.Contains(candidate, "/") {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
			continue
		}
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("no Chromium-family browser found on this gateway host; set CHROME_PATH or install google-chrome/chromium")
}

type chromeInstance struct {
	cmd         *exec.Cmd
	userDataDir string
	debugPort   int
}

// launchChrome starts a headless Chromium subprocess for a single session,
// with its own throwaway profile directory and its devtools port bound to
// loopback only. proxyAddr points Chromium's network stack at the per-session
// egress allowlist proxy (see egress_proxy.go).
func launchChrome(ctx context.Context, sessionID string, proxyAddr string) (*chromeInstance, error) {
	binary, err := findChromeBinary()
	if err != nil {
		return nil, err
	}

	userDataDir, err := os.MkdirTemp("", "infisical-pam-webapp-"+sessionID+"-")
	if err != nil {
		return nil, fmt.Errorf("failed to create chrome profile dir: %w", err)
	}

	port, err := freeLoopbackPort()
	if err != nil {
		_ = os.RemoveAll(userDataDir)
		return nil, fmt.Errorf("failed to allocate debug port: %w", err)
	}

	args := []string{
		"--headless=new",
		"--disable-gpu",
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--remote-debugging-address=127.0.0.1",
		"--user-data-dir=" + userDataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-background-networking",
		"--proxy-server=" + proxyAddr,
		"--proxy-bypass-list=<-loopback>",
		"about:blank",
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(userDataDir)
		return nil, fmt.Errorf("failed to start chrome: %w", err)
	}

	return &chromeInstance{cmd: cmd, userDataDir: userDataDir, debugPort: port}, nil
}

func (c *chromeInstance) Close() {
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	_ = c.cmd.Wait()
	_ = os.RemoveAll(c.userDataDir)
}

func freeLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

type cdpTarget struct {
	Type                 string `json:"type"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// waitForCDPPageWebSocketURL polls Chromium's devtools HTTP endpoint until it
// comes up, then returns the WebSocket URL of its single initial page target.
func waitForCDPPageWebSocketURL(ctx context.Context, port int) (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	listURL := fmt.Sprintf("http://127.0.0.1:%d/json/list", port)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		resp, err := client.Get(listURL)
		if err == nil {
			var targets []cdpTarget
			decodeErr := json.NewDecoder(resp.Body).Decode(&targets)
			_ = resp.Body.Close()
			if decodeErr == nil {
				for _, t := range targets {
					if t.Type == "page" && t.WebSocketDebuggerURL != "" {
						return t.WebSocketDebuggerURL, nil
					}
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return "", fmt.Errorf("timed out waiting for chrome devtools page target on port %d", port)
}
