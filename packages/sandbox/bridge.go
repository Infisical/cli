//go:build linux

package sandbox

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"

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

	agent := newInheritedCmd(argv, os.Environ())
	if err := agent.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox supervisor: failed to start the agent: %v\n", err)
		return 1
	}

	stopForwarding := ForwardTerminationSignals(agent)
	err = agent.Wait()
	stopForwarding()

	code, ok := WaitExitCode(err)
	if !ok {
		fmt.Fprintf(os.Stderr, "sandbox supervisor: agent error: %v\n", err)
	}
	return code
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

	// Wait for BOTH directions. Tearing down as soon as either copy finished would truncate a response
	// still streaming back to a client that had already half-closed its request side.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyThenCloseWrite(upstream, client) }()
	go func() { defer wg.Done(); copyThenCloseWrite(client, upstream) }()
	wg.Wait()
}

// copyThenCloseWrite copies src into dst, then half-closes dst's write side so the peer sees EOF for
// this direction while the opposite direction keeps flowing. Both *net.TCPConn and *net.UnixConn
// implement CloseWrite; anything else just relies on the deferred Close.
func copyThenCloseWrite(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// bringLoopbackUp ensures lo is UP so 127.0.0.1 is reachable inside the netns. bwrap already brings
// loopback up when it creates the new network namespace, so in practice lo is UP by the time we get
// here; we still check and, only if it is down, try to raise it. The SIOCSIFFLAGS write is refused
// with EPERM in bwrap's user-namespaced netns even with CAP_NET_ADMIN, so treating that failure as
// fatal would force every Linux run to fall back to the weaker shared-net path. We therefore return
// success whenever lo is already UP, and surface the error only when it is genuinely still down.
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
	if ifr.Uint16()&unix.IFF_UP != 0 {
		return nil
	}
	flags := ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		// Re-read: some kernels refuse the write yet lo is up anyway. Trust the observed state.
		if unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr) == nil && ifr.Uint16()&unix.IFF_UP != 0 {
			return nil
		}
		return err
	}
	return nil
}
