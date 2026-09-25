package util

import (
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHKeepalive sends an SSH keepalive request and waits up to timeout for a response
func SSHKeepalive(conn ssh.Conn, timeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
		errCh <- err
	}()
	select {
	case err := <-errCh:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("no keepalive response within %v", timeout)
	}
}
