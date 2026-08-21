package winrm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

// innerTransport unwraps the serialization wrapper so a test can assert on the transport the scheme
// actually selected.
func innerTransport(t *testing.T, client *winrm.Client) winrm.Transporter {
	t.Helper()
	wrapped, ok := client.Parameters.TransportDecorator().(*serializedTransport)
	if !ok {
		t.Fatalf("expected the transport to be wrapped for serialization, got %T", client.Parameters.TransportDecorator())
	}
	return wrapped.Transporter
}

// TestNewClientTransportByScheme locks in the transport split: HTTP uses NTLM message encryption
// (*winrm.Encryption), HTTPS uses NTLM auth over TLS (*winrm.ClientNTLM).
func TestNewClientTransportByScheme(t *testing.T) {
	winrm.DefaultParameters.TransportDecorator = nil

	httpClient, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p"}, nil)
	if err != nil {
		t.Fatalf("newClient(http): %v", err)
	}
	if inner := innerTransport(t, httpClient); !isType[*winrm.Encryption](inner) {
		t.Errorf("HTTP: expected *winrm.Encryption, got %T", inner)
	}

	httpsClient, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5986, Username: "u", Password: "p", UseHTTPS: true}, nil)
	if err != nil {
		t.Fatalf("newClient(https): %v", err)
	}
	if inner := innerTransport(t, httpsClient); !isType[*winrm.ClientNTLM](inner) {
		t.Errorf("HTTPS: expected *winrm.ClientNTLM, got %T", inner)
	}
}

func isType[T any](v any) bool {
	_, ok := v.(T)
	return ok
}

// concurrencyProbe records whether two Post calls were ever in flight at once.
type concurrencyProbe struct {
	inFlight atomic.Int32
	overlap  atomic.Bool
	calls    atomic.Int32
}

func (p *concurrencyProbe) Post(*winrm.Client, *soap.SoapMessage) (string, error) {
	if p.inFlight.Add(1) > 1 {
		p.overlap.Store(true)
	}
	time.Sleep(time.Millisecond)
	p.calls.Add(1)
	p.inFlight.Add(-1)
	return "", nil
}

func (p *concurrencyProbe) Transport(*winrm.Endpoint) error { return nil }

func hammer(tr winrm.Transporter) *sync.WaitGroup {
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = tr.Post(nil, nil)
		}()
	}
	return &wg
}

// TestSerializedTransportPreventsOverlappingPosts is the whole point of the wrapper: NTLM sealing is
// RC4 with a sequence counter, so two goroutines sealing at once corrupt the keystream and the host
// answers "checksum does not match".
func TestSerializedTransportPreventsOverlappingPosts(t *testing.T) {
	probe := &concurrencyProbe{}
	tr := &serializedTransport{Transporter: probe}

	hammer(tr).Wait()

	if probe.overlap.Load() {
		t.Fatal("two Post calls overlapped despite the serialization wrapper")
	}
	if got := probe.calls.Load(); got != 16 {
		t.Fatalf("expected all 16 calls to complete, got %d", got)
	}
}

// TestConcurrencyProbeDetectsOverlapWithoutTheWrapper keeps the test above honest: without the
// wrapper the same probe must see overlap, otherwise it would pass for the wrong reason.
func TestConcurrencyProbeDetectsOverlapWithoutTheWrapper(t *testing.T) {
	probe := &concurrencyProbe{}

	hammer(probe).Wait()

	if !probe.overlap.Load() {
		t.Fatal("probe saw no overlap unwrapped, so it cannot prove the wrapper does anything")
	}
}

// The output poll is released by the bootstrap's ready sentinel, not by a shortened timeout. A short
// one would also apply to shell creation and the Send, neither of which retries on a timeout fault.
func TestClientKeepsTheDefaultOperationTimeout(t *testing.T) {
	winrm.DefaultParameters.TransportDecorator = nil

	client, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p"}, nil)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	if client.Parameters.Timeout != "PT60S" {
		t.Fatalf("Timeout = %q, want the PT60S default", client.Parameters.Timeout)
	}
}

// TestNewClientDoesNotMutateGlobalParameters guards the pointer-alias fix: newClient must not write
// TransportDecorator back onto the shared winrm.DefaultParameters global.
func TestNewClientDoesNotMutateGlobalParameters(t *testing.T) {
	winrm.DefaultParameters.TransportDecorator = nil
	if _, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p"}, nil); err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if winrm.DefaultParameters.TransportDecorator != nil {
		t.Fatal("newClient mutated the shared winrm.DefaultParameters global (pointer-alias regression)")
	}
}

// TestNewClientConcurrent builds clients across both transports concurrently; run with -race it
// guards against the shared-DefaultParameters data race.
func TestNewClientConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(https bool) {
			defer wg.Done()
			c, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p", UseHTTPS: https}, nil)
			if err != nil || c == nil {
				t.Errorf("newClient(useHTTPS=%v): client=%v err=%v", https, c, err)
			}
		}(i%2 == 0)
	}
	wg.Wait()
}

// recordingTransport notes the order requests reach the wire.
type recordingTransport struct {
	mu    sync.Mutex
	order []string
}

func (r *recordingTransport) Post(_ *winrm.Client, m *soap.SoapMessage) (string, error) {
	kind := "other"
	switch body := m.String(); {
	case strings.Contains(body, winrmStdinEOFAttr):
		kind = "stdin-eof"
	case strings.Contains(body, winrmReceiveAction):
		kind = "receive"
	}
	r.mu.Lock()
	r.order = append(r.order, kind)
	r.mu.Unlock()
	return "", nil
}

func (r *recordingTransport) Transport(*winrm.Endpoint) error { return nil }

func (r *recordingTransport) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.order...)
}

func receiveMessage() *soap.SoapMessage {
	return winrm.NewGetOutputRequest("http://h/wsman", "shell", "cmd", "stdout stderr", winrm.DefaultParameters)
}

func stdinMessage(eof bool) *soap.SoapMessage {
	return winrm.NewSendInputRequest("http://h/wsman", "shell", "cmd", []byte("x"), eof, winrm.DefaultParameters)
}

// The output poll must not reach the wire until stdin is closed. PowerShell stays blocked in
// ReadToEnd until the EOF message arrives, so a poll that gets the transport lock first waits for
// output that cannot exist and starves the very message that would produce it.
func TestStdinGateHoldsTheOutputPollUntilStdinIsClosed(t *testing.T) {
	probe := &recordingTransport{}
	tr := &serializedTransport{Transporter: probe, ctx: context.Background(), gate: newStdinGate()}

	receiveReturned := make(chan struct{})
	go func() {
		defer close(receiveReturned)
		_, _ = tr.Post(nil, receiveMessage())
	}()

	// The poll must still be parked; nothing has closed stdin.
	select {
	case <-receiveReturned:
		t.Fatal("the output poll reached the wire before stdin was closed")
	case <-time.After(50 * time.Millisecond):
	}

	if _, err := tr.Post(nil, stdinMessage(false)); err != nil {
		t.Fatalf("payload send: %v", err)
	}
	select {
	case <-receiveReturned:
		t.Fatal("the payload alone released the poll; only the EOF message may")
	case <-time.After(50 * time.Millisecond):
	}

	if _, err := tr.Post(nil, stdinMessage(true)); err != nil {
		t.Fatalf("eof send: %v", err)
	}
	select {
	case <-receiveReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("the poll never resumed after stdin was closed")
	}

	if got := probe.seen(); len(got) < 3 || got[0] != "other" && got[0] != "stdin-eof" {
		t.Logf("wire order: %v", got)
	}
	order := probe.seen()
	if order[len(order)-1] != "receive" {
		t.Fatalf("the poll should reach the wire last, got %v", order)
	}
}

// Without a gate (every operation except RunCommand) nothing is held back.
func TestNoGateLetsTheOutputPollThrough(t *testing.T) {
	probe := &recordingTransport{}
	tr := &serializedTransport{Transporter: probe, ctx: context.Background()}

	done := make(chan struct{})
	go func() { defer close(done); _, _ = tr.Post(nil, receiveMessage()) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("an ungated poll was blocked")
	}
}

// A cancelled context must release a parked poll, or a stdin write that never completes would hang
// the command past its own deadline.
func TestStdinGateReleasesOnContextCancellation(t *testing.T) {
	probe := &recordingTransport{}
	ctx, cancel := context.WithCancel(context.Background())
	tr := &serializedTransport{Transporter: probe, ctx: ctx, gate: newStdinGate()}

	done := make(chan struct{})
	go func() { defer close(done); _, _ = tr.Post(nil, receiveMessage()) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the context did not release the parked poll")
	}
}

// A failed EOF send must still open the gate, or the poll parks forever.
func TestStdinGateOpensEvenIfTheEofSendFails(t *testing.T) {
	tr := &serializedTransport{Transporter: failingTransport{}, ctx: context.Background(), gate: newStdinGate()}

	done := make(chan struct{})
	go func() { defer close(done); _, _ = tr.Post(nil, receiveMessage()) }()

	_, _ = tr.Post(nil, stdinMessage(true))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a failed EOF send stranded the poll behind the gate")
	}
}

type failingTransport struct{}

func (failingTransport) Post(*winrm.Client, *soap.SoapMessage) (string, error) {
	return "", errors.New("boom")
}
func (failingTransport) Transport(*winrm.Endpoint) error { return nil }
