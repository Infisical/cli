package winrm

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// streamBody writes `total` bytes to the client in 64KB chunks, stopping early if the client goes away.
func streamBody(w http.ResponseWriter, total int64) {
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	chunk := make([]byte, 64*1024)
	var n int64
	for n < total {
		m, err := w.Write(chunk)
		n += int64(m)
		if err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// TestResponseCapScopedToWsmanPath checks the cap bounds an oversized body on /wsman but not on other paths.
func TestResponseCapScopedToWsmanPath(t *testing.T) {
	InstallHTTPResponseCap()

	oversized := int64(maxWinRMReadBytes) + 4*1024*1024
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		streamBody(w, oversized)
	}))
	defer srv.Close()
	defer srv.CloseClientConnections()

	t.Run("wsman is capped", func(t *testing.T) {
		resp, err := http.Get(srv.URL + winrmSOAPPath)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		n, err := io.Copy(io.Discard, resp.Body)
		if err == nil {
			t.Fatalf("expected a capped read to fail, read %d bytes with no error", n)
		}
		if n > maxWinRMReadBytes {
			t.Fatalf("read %d bytes, past the %d cap", n, maxWinRMReadBytes)
		}
	})

	t.Run("other paths are not capped", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/some/large/download")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		n, err := io.Copy(io.Discard, resp.Body)
		if err != nil {
			t.Fatalf("non-/wsman read should not be capped, got error after %d bytes: %v", n, err)
		}
		if n != oversized {
			t.Fatalf("expected full %d bytes on a non-/wsman path, read %d", oversized, n)
		}
	})
}
