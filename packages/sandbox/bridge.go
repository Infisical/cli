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

// RunSupervisor runs inside the bwrap netns on the hard-fence path: it brings loopback up, bridges
// 127.0.0.1:port to the parent's proxy unix socket, then execs the agent. probe=true is Preflight's
// capability check: bring loopback up and return without bridging or exec'ing.
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

	// Fail loud: if the port is already taken, abort rather than route the agent's traffic to it.
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

// runBridge forwards each loopback TCP connection to the proxy's unix socket. The socket must be a
// pathname socket (abstract sockets are netns-scoped and unreachable).
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

// bringLoopbackUp brings lo UP; an empty netns starts with it DOWN, so 127.0.0.1 is dead until then.
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
	flags := ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING
	ifr.SetUint16(flags)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
