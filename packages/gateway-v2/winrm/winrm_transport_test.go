package winrm

import (
	"sync"
	"testing"

	"github.com/masterzen/winrm"
)

// TestTransportDecorator locks in the transport split: NTLM message encryption over HTTP, plain NTLM auth over HTTPS.
func TestTransportDecorator(t *testing.T) {
	httpDec, err := transportDecorator(false)
	if err != nil {
		t.Fatalf("transportDecorator(false): %v", err)
	}
	if _, ok := httpDec().(*winrm.Encryption); !ok {
		t.Errorf("HTTP: expected *winrm.Encryption, got %T", httpDec())
	}

	httpsDec, err := transportDecorator(true)
	if err != nil {
		t.Fatalf("transportDecorator(true): %v", err)
	}
	if _, ok := httpsDec().(*winrm.ClientNTLM); !ok {
		t.Errorf("HTTPS: expected *winrm.ClientNTLM, got %T", httpsDec())
	}
}

// TestNewClientDoesNotMutateGlobalParameters guards the pointer-alias fix: newClient must not write
// TransportDecorator back onto the shared winrm.DefaultParameters global.
func TestNewClientDoesNotMutateGlobalParameters(t *testing.T) {
	winrm.DefaultParameters.TransportDecorator = nil
	if _, err := newClient(Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p"}); err != nil {
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
		go func(i int) {
			defer wg.Done()
			creds := Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p", UseHTTPS: i%2 == 1}
			c, err := newClient(creds)
			if err != nil || c == nil {
				t.Errorf("newClient(useHTTPS=%v): client=%v err=%v", creds.UseHTTPS, c, err)
			}
		}(i)
	}
	wg.Wait()
}
