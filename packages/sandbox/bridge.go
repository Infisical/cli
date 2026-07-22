//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// RunSupervisor is the entry point for the hidden `__sandbox-supervisor` subcommand. It runs INSIDE
// the bwrap network namespace (re-exec'd by the bwrap argv on the hard-fence path). It brings loopback
// up, starts a TCP->unix bridge so the child's HTTP(S)_PROXY (127.0.0.1:port) reaches the parent's
// proxy unix socket, then execs the agent as its child and forwards signals / propagates exit code.
//
// probe=true is the capability check used by Preflight: bring loopback up and return the result
// without starting a bridge or agent.
func RunSupervisor(probe bool, port int, socket string, argv []string) int {
	if err := bringLoopbackUp(); err != nil {
		if probe {
			return 1
		}
		fmt.Fprintf(os.Stderr, "sandbox supervisor: failed to bring up loopback: %v\n", err)
		return 1
	}
	if probe {
		return 0
	}

	if port == 0 || socket == "" || len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "sandbox supervisor: --port, --socket and a command are required")
		return 1
	}

	// Fail-loud bind: if we cannot own the loopback proxy port, abort rather than let the agent's
	// traffic flow to whatever is already there (a same-namespace MITM risk).
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandbox supervisor: failed to bind loopback proxy port %d: %v\n", port, err)
		return 1
	}
	go runBridge(ln, socket)

	// #nosec G204 -- the wrapped command is provided directly by the operator running the CLI
	agent := exec.Command(argv[0], argv[1:]...)
	agent.Stdin = os.Stdin
	agent.Stdout = os.Stdout
	agent.Stderr = os.Stderr
	agent.Env = os.Environ()

	if err := agent.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox supervisor: failed to start the agent: %v\n", err)
		return 1
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh)
	go func() {
		for sig := range sigCh {
			if agent.Process != nil {
				_ = agent.Process.Signal(sig)
			}
		}
	}()

	err = agent.Wait()
	signal.Stop(sigCh)
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			return ws.ExitStatus()
		}
	}
	fmt.Fprintf(os.Stderr, "sandbox supervisor: agent error: %v\n", err)
	return 1
}

// runBridge accepts loopback TCP connections and forwards each to the parent's proxy unix socket,
// copying bytes both directions. The socket must be a pathname socket (bind-mounted in); abstract
// sockets are network-namespace-scoped and would be unreachable.
func runBridge(ln net.Listener, socket string) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go bridgeConn(conn, socket)
	}
}

func bridgeConn(client net.Conn, socket string) {
	defer client.Close()
	upstream, err := net.Dial("unix", socket)
	if err != nil {
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// bringLoopbackUp sets the loopback interface UP inside the current network namespace. An empty netns
// starts with lo DOWN, so nothing (not even 127.0.0.1) works until this runs.
func bringLoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	// Set IFF_UP | IFF_RUNNING on the interface flags.
	flags := ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING
	ifr.SetUint16(flags)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
