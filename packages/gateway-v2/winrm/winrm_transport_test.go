package winrm

import (
	"context"
	"sync"
	"testing"

	"github.com/masterzen/winrm"
)

// TestNewClientTransportByScheme locks in the transport split: HTTP uses NTLM message encryption
// (*winrm.Encryption), HTTPS uses NTLM auth over TLS (*winrm.ClientNTLM).
func TestNewClientTransportByScheme(t *testing.T) {
	winrm.DefaultParameters.TransportDecorator = nil

	httpClient, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5985, Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("newClient(http): %v", err)
	}
	if _, ok := httpClient.Parameters.TransportDecorator().(*winrm.Encryption); !ok {
		t.Errorf("HTTP: expected *winrm.Encryption, got %T", httpClient.Parameters.TransportDecorator())
	}

	httpsClient, err := newClient(context.Background(), Credentials{Host: "127.0.0.1", Port: 5986, Username: "u", Password: "p", UseHTTPS: true})
	if err != nil {
		t.Fatalf("newClient(https): %v", err)
	}
	if _, ok := httpsClient.Parameters.TransportDecorator().(*winrm.ClientNTLM); !ok {
		t.Errorf("HTTPS: expected *winrm.ClientNTLM, got %T", httpsClient.Parameters.TransportDecorator())
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
