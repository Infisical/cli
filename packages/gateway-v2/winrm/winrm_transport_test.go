package winrm

import (
	"context"
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

	httpClient, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("newClient(http): %v", err)
	}
	if inner := innerTransport(t, httpClient); !isType[*winrm.Encryption](inner) {
		t.Errorf("HTTP: expected *winrm.Encryption, got %T", inner)
	}

	httpsClient, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5986, Username: "u", Password: "p", UseHTTPS: true})
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

	client, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p"})
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
	if _, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p"}); err != nil {
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
			c, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p", UseHTTPS: https})
			if err != nil || c == nil {
				t.Errorf("newClient(useHTTPS=%v): client=%v err=%v", https, c, err)
			}
		}(i%2 == 0)
	}
	wg.Wait()
}
