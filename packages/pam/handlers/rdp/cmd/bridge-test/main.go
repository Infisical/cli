// Standalone test harness for the Go bridge wrapper.
//
// Mirrors the Rust test binary's behavior but exercises the full
// Rust -> C ABI -> CGo -> Go path:
//
//  1. Bind a loopback TCP listener
//  2. Accept one RDP client connection
//  3. Hand it to rdp.StartWithConn
//  4. Block on bridge.Wait until the session ends
//  5. Exit
//
// Build with `-tags rdp` from the cli repo root:
//
//	go run -tags rdp ./packages/pam/handlers/rdp/cmd/bridge-test -- \
//	  -listen 127.0.0.1:3390 \
//	  -target <windows-host>:3389 \
//	  -user <windows-user> \
//	  -pass <windows-pass>
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Infisical/infisical-merge/packages/pam/handlers/rdp"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:3390", "loopback address to accept the RDP client on")
	target := flag.String("target", "", "target Windows server as host:port (port defaults to 3389)")
	username := flag.String("user", "", "username to inject on the outbound connection")
	password := flag.String("pass", "", "password to inject on the outbound connection")
	flag.Parse()

	if *target == "" || *username == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "--target, --user, and --pass are required")
		flag.Usage()
		os.Exit(2)
	}

	host, port, err := splitHostPort(*target)
	if err != nil {
		log.Fatalf("parse target: %v", err)
	}

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("bind %s: %v", *listenAddr, err)
	}
	log.Printf("bridge ready; listening on %s, target %s:%d", *listenAddr, host, port)

	// Accept one connection, then stop listening.
	conn, err := listener.Accept()
	if err != nil {
		log.Fatalf("accept: %v", err)
	}
	_ = listener.Close()
	log.Printf("inbound connection from %s; starting MITM", conn.RemoteAddr())

	bridge, err := rdp.StartWithConn(conn, host, port, *username, *password)
	if err != nil {
		_ = conn.Close()
		log.Fatalf("start bridge: %v", err)
	}
	// The bridge has its own dup of the fd; close the Go-side conn so we
	// don't accidentally keep it alive.
	_ = conn.Close()

	// If the user Ctrl-C's, cancel the session gracefully and let Wait
	// return so Close can run.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigc
		log.Printf("received %s; cancelling session", sig)
		if err := bridge.Cancel(); err != nil {
			log.Printf("cancel: %v", err)
		}
	}()

	waitErr := bridge.Wait()
	switch {
	case waitErr == nil:
		log.Printf("session ended cleanly")
	case errors.Is(waitErr, rdp.ErrSessionFailed):
		log.Printf("session ended with error")
	default:
		log.Printf("wait: %v", waitErr)
	}

	if err := bridge.Close(); err != nil {
		log.Printf("close: %v", err)
	}

	if waitErr != nil && !errors.Is(waitErr, rdp.ErrInvalidHandle) {
		os.Exit(1)
	}
}

// splitHostPort accepts "host", "host:port", or "[ipv6]:port" and returns
// host + port, defaulting port to 3389 if omitted.
func splitHostPort(s string) (string, uint16, error) {
	// If no colon, it's just a host.
	if !strings.Contains(s, ":") {
		return s, 3389, nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parse port %q: %w", portStr, err)
	}
	return host, uint16(port), nil
}
