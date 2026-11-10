package agentvault

import (
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Fails its first Accept the way a process out of file descriptors does.
type emfileOnceListener struct {
	net.Listener
	failed atomic.Bool
}

func (l *emfileOnceListener) Accept() (net.Conn, error) {
	if l.failed.CompareAndSwap(false, true) {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
	}
	return l.Listener.Accept()
}

func TestTheDoorKeepsAcceptingAfterRunningOutOfFileDescriptors(t *testing.T) {
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inner := &emfileOnceListener{Listener: ln}
	door := newDoorListener(inner, proxyDoorTLSConfig(newCaManager(key, cert)), time.Second)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	go func() { _ = srv.Serve(door) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("a request after EMFILE: %v", err)
	}
	resp.Body.Close()
	if !inner.failed.Load() || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("failed=%v status=%d, want the EMFILE seen and then a 204", inner.failed.Load(), resp.StatusCode)
	}
}
