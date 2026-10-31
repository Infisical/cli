//go:build !windows

package pam

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
)

func watchTerminalResize(session *ssh.Session) (stop func()) {
	resized := make(chan os.Signal, 1)
	signal.Notify(resized, syscall.SIGWINCH)

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-resized:
				width, height := terminalSize()
				_ = session.WindowChange(height, width)
			case <-done:
				return
			}
		}
	}()

	return func() {
		signal.Stop(resized)
		close(done)
	}
}
