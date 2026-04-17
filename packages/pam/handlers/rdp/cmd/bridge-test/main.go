// Standalone Go test harness for the RDP bridge FFI.
//
// Drives the native Rust bridge end-to-end from Go: starts a bridge,
// polls events, logs what arrives. Equivalent to the `proxy` mode of
// the Rust spike binary but driven through CGo.
//
// Run (after `cargo build --release` in ../../native/):
//
//   go run ./cmd/bridge-test \
//     -target <host:port> -user <user> -pass <pass> -listen 127.0.0.1:3389
//
// Then point a client at localhost:3389 (see proxy mode docs).
package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	rdp "github.com/Infisical/infisical-merge/packages/pam/handlers/rdp"
)

func main() {
	target := flag.String("target", "", "target RDP server as host:port")
	user := flag.String("user", "", "username to inject")
	pass := flag.String("pass", "", "password to inject")
	listen := flag.String("listen", "127.0.0.1:3389", "local address to listen on")
	flag.Parse()

	if *target == "" || *user == "" || *pass == "" {
		flag.Usage()
		os.Exit(2)
	}

	host, port, err := splitHostPort(*target)
	if err != nil {
		log.Fatalf("parse target: %v", err)
	}

	log.Printf("starting bridge: listen=%s -> target=%s:%d user=%s", *listen, host, port, *user)
	bridge, err := rdp.Start(host, port, *user, *pass, *listen)
	if err != nil {
		log.Fatalf("rdp.Start: %v", err)
	}
	defer bridge.Close()

	// Clean shutdown on SIGINT.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Printf("signal received; closing bridge")
		_ = bridge.Close()
	}()

	var (
		kbCount    int
		mouseCount int
		frameCount int
	)

	for {
		ev, err := bridge.PollEvent(500)
		if err != nil {
			if errors.Is(err, rdp.ErrSessionEnded) {
				log.Printf("bridge ended")
				break
			}
			if errors.Is(err, rdp.ErrInvalidHandle) {
				log.Printf("bridge closed")
				break
			}
			log.Fatalf("poll: %v", err)
		}
		if ev == nil {
			continue // timeout; keep polling
		}

		switch ev.Type {
		case rdp.EventKeyboard:
			kbCount++
			log.Printf("KEY  scancode=%d flags=0x%02x t=%dus",
				ev.ValueA, ev.Flags, ev.ElapsedNS/1000)
		case rdp.EventUnicode:
			kbCount++
			log.Printf("UNI  code=%d flags=0x%02x t=%dus",
				ev.ValueA, ev.Flags, ev.ElapsedNS/1000)
		case rdp.EventMouse:
			mouseCount++
			// Mouse is noisy; log every 50th.
			if mouseCount%50 == 1 {
				log.Printf("MOUSE x=%d y=%d flags=0x%04x wheel=%d t=%dus (#%d)",
					ev.ValueA, ev.ValueB, ev.Flags, ev.WheelDelta, ev.ElapsedNS/1000, mouseCount)
			}
		case rdp.EventTargetFrame:
			frameCount++
			action := "X224"
			if ev.Action == rdp.ActionFastPath {
				action = "FastPath"
			}
			if frameCount%20 == 1 {
				log.Printf("FRAME %s bytes=%d t=%dus (#%d)",
					action, ev.ValueA, ev.ElapsedNS/1000, frameCount)
			}
		default:
			log.Printf("unknown event type=%d", ev.Type)
		}
	}

	log.Printf("summary: keys=%d mouse=%d frames=%d", kbCount, mouseCount, frameCount)
}

func splitHostPort(hp string) (string, uint16, error) {
	idx := strings.LastIndex(hp, ":")
	if idx < 0 {
		return "", 0, errors.New("target must be host:port")
	}
	host := hp[:idx]
	portStr := hp[idx+1:]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(port), nil
}
