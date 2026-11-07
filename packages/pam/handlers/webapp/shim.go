package webapp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var SupportedChromiumMajors = []int{156}

func supportedBrowser(version string) bool {
	_, number, ok := strings.Cut(version, "/")
	if !ok {
		number = version
	}
	major, _, _ := strings.Cut(number, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return false
	}
	for _, supported := range SupportedChromiumMajors {
		if supported == n {
			return true
		}
	}
	return false
}

func browserFlags(width, height int) []string {
	return []string{"--headless=new", "--remote-debugging-pipe", "--user-data-dir=/home/worker/profile", "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-sync", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-quic", "--proxy-server=http://127.0.0.1:3128", "--proxy-bypass-list=<-loopback>", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "--webrtc-ip-handling-policy=disable_non_proxied_udp", "--force-webrtc-ip-handling-policy", "--disable-features=WebRtcHideLocalIpsWithMdns,DialMediaRouteProvider", fmt.Sprintf("--window-size=%d,%d", width, height), "about:blank"}
}

func networkProbe(ctx context.Context) error {
	for _, target := range []string{"192.168.65.254:80", "169.254.169.254:80", "8.8.8.8:53"} {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", target)
		if conn != nil {
			conn.Close()
		}
		if !errors.Is(err, syscall.ENETUNREACH) {
			return fmt.Errorf("probe %s: expected network unreachable, got %v", target, err)
		}
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "udp", "8.8.8.8:53")
	}}
	_, err := resolver.LookupIPAddr(ctx, "pam-self-test.invalid")
	if err == nil || !strings.Contains(err.Error(), "network is unreachable") {
		return fmt.Errorf("DNS probe: expected network unreachable, got %v", err)
	}
	return nil
}

func RunShim(ctx context.Context, mux *Mux, hard, until time.Time, width, height int, selfTest bool) error {
	if width < 320 || width > 3840 || height < 240 || height > 2400 {
		return errors.New("invalid viewport")
	}
	toChrome, parentWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer toChrome.Close()
	defer parentWrite.Close()
	parentRead, fromChrome, err := os.Pipe()
	if err != nil {
		return err
	}
	defer parentRead.Close()
	defer fromChrome.Close()
	flags := browserFlags(width, height)
	if selfTest {
		profile, err := os.MkdirTemp("/tmp", "pam-browser-probe-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(profile)
		for i, flag := range flags {
			if strings.HasPrefix(flag, "--user-data-dir=") {
				flags[i] = "--user-data-dir=" + profile
			}
		}
	}
	cmd := exec.Command("/usr/bin/chromium", flags...)
	cmd.ExtraFiles = []*os.File{toChrome, fromChrome}
	cmd.Stderr = os.Stderr
	isolateProcess(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	toChrome.Close()
	fromChrome.Close()
	clock := newLeaseClock(hard, until, 5*time.Second)
	defer clock.Stop()
	stopped := make(chan struct{})
	defer func() { killProcess(cmd); _ = cmd.Wait(); close(stopped) }()
	go func() {
		select {
		case <-ctx.Done():
			killProcess(cmd)
		case <-clock.done:
			killProcess(cmd)
		case <-stopped:
		}
	}()
	if err := writeFull(parentWrite, []byte("{\"id\":1,\"method\":\"Browser.getVersion\"}\x00")); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(parentRead, 64<<10)
	readJSON := func() ([]byte, error) {
		var b []byte
		for {
			fragment, err := reader.ReadSlice(0)
			b = append(b, fragment...)
			if len(b) > 16<<20 {
				return nil, errors.New("CDP pipe message too large")
			}
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				return nil, err
			}
			return b[:len(b)-1], nil
		}
	}
	var version string
	for version == "" {
		b, err := readJSON()
		if err != nil {
			return err
		}
		var response struct {
			ID     int `json:"id"`
			Result struct {
				Product string `json:"product"`
			} `json:"result"`
		}
		if json.Unmarshal(b, &response) != nil {
			return errors.New("invalid CDP version")
		}
		if response.ID == 1 {
			version = response.Result.Product
		}
	}
	if !supportedBrowser(version) {
		return fmt.Errorf("unsupported-browser: %s", version)
	}
	if selfTest {
		if err := networkProbe(ctx); err != nil {
			return err
		}
		return mux.Control(map[string]any{"c": "ready", "chromium": version, "network": "unreachable"})
	}
	listener, err := net.Listen("tcp", "127.0.0.1:3128")
	if err != nil {
		return err
	}
	defer listener.Close()
	var connections sync.Map
	defer func() { connections.Range(func(key, value any) bool { key.(net.Conn).Close(); return true }) }()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Store(conn, true)
			go func() {
				defer conn.Close()
				defer connections.Delete(conn)
				upstream, err := net.DialTimeout("unix", "/run/pam/connector.sock", 2*time.Second)
				if err != nil {
					fmt.Fprintf(os.Stderr, "PAM connector socket: %v\n", err)
					return
				}
				connections.Store(upstream, true)
				defer connections.Delete(upstream)
				defer upstream.Close()
				copyTunnel(conn, upstream, conn)
			}()
		}
	}()
	if err := mux.Control(map[string]string{"c": "ready", "chromium": version}); err != nil {
		return err
	}
	errorsCh := make(chan error, 3)
	commands := make(chan []byte, 32)
	var commandBytes atomic.Int64
	go func() {
		for {
			select {
			case b := <-commands:
				err := writeFull(parentWrite, append(b, 0))
				commandBytes.Add(-int64(len(b)))
				if err != nil {
					errorsCh <- err
					return
				}
			case <-stopped:
				return
			}
		}
	}()
	go func() {
		for {
			b, err := readJSON()
			if err != nil {
				errorsCh <- err
				return
			}
			if err = mux.Write(MuxCDP, b); err != nil {
				errorsCh <- err
				return
			}
		}
	}()
	go func() {
		for {
			ch, b, err := mux.Read()
			if err != nil {
				errorsCh <- err
				return
			}
			if ch == MuxCDP {
				if !json.Valid(b) {
					errorsCh <- errors.New("invalid CDP")
					return
				}
				if commandBytes.Add(int64(len(b))) > 32<<20 {
					errorsCh <- errors.New("CDP command queue full")
					return
				}
				select {
				case commands <- b:
				default:
					errorsCh <- errors.New("CDP command queue full")
					return
				}
				continue
			}
			var control struct {
				C            string `json:"c"`
				LeaseSeconds *int   `json:"leaseSeconds"`
			}
			if json.Unmarshal(b, &control) != nil {
				errorsCh <- errors.New("invalid shim control")
				return
			}
			switch control.C {
			case "lease":
				if control.LeaseSeconds == nil || *control.LeaseSeconds < 0 || *control.LeaseSeconds > 45 {
					errorsCh <- errors.New("invalid relative lease")
					return
				}
				clock.Renew(time.Now().Add(time.Duration(*control.LeaseSeconds) * time.Second))
			case "stop":
				errorsCh <- io.EOF
				return
			default:
				errorsCh <- errors.New("unexpected shim control")
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case <-clock.done:
		return nil
	case err := <-errorsCh:
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
}
