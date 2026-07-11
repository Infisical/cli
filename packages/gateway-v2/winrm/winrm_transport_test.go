package winrm

import (
	"context"
	"sync"
	"testing"

	"github.com/masterzen/winrm"
)

// TestNewClientUsesHTTPSTransport locks in the HTTPS-only decision: newClient must always build the
// NTLM-over-HTTPS transport, never the plain-HTTP encryption transport (which can fail open).
func TestNewClientUsesHTTPSTransport(t *testing.T) {
	winrm.DefaultParameters.TransportDecorator = nil
	client, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5986, Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if _, ok := client.Parameters.TransportDecorator().(*winrm.ClientNTLM); !ok {
		t.Errorf("expected *winrm.ClientNTLM transport, got %T", client.Parameters.TransportDecorator())
	}
}

// TestNewClientDoesNotMutateGlobalParameters guards the pointer-alias fix: newClient must not write
// TransportDecorator back onto the shared winrm.DefaultParameters global.
func TestNewClientDoesNotMutateGlobalParameters(t *testing.T) {
	winrm.DefaultParameters.TransportDecorator = nil
	if _, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5986, Username: "u", Password: "p"}); err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if winrm.DefaultParameters.TransportDecorator != nil {
		t.Fatal("newClient mutated the shared winrm.DefaultParameters global (pointer-alias regression)")
	}
}

// TestNewClientConcurrent builds clients concurrently; run with -race it guards against the
// shared-DefaultParameters data race.
func TestNewClientConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5986, Username: "u", Password: "p"})
			if err != nil || c == nil {
				t.Errorf("newClient: client=%v err=%v", c, err)
			}
		}()
	}
	wg.Wait()
}
