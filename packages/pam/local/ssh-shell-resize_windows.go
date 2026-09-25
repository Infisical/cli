package pam

import (
	"time"

	"golang.org/x/crypto/ssh"
)

const terminalResizePollInterval = 250 * time.Millisecond

// Windows has no SIGWINCH, so the size is polled
func watchTerminalResize(session *ssh.Session) (stop func()) {
	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(terminalResizePollInterval)
		defer ticker.Stop()

		width, height := terminalSize()
		for {
			select {
			case <-ticker.C:
				currentWidth, currentHeight := terminalSize()
				if currentWidth == width && currentHeight == height {
					continue
				}
				width, height = currentWidth, currentHeight
				_ = session.WindowChange(height, width)
			case <-done:
				return
			}
		}
	}()

	return func() { close(done) }
}
