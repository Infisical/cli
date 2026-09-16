package agentvault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

// These swap the config.INFISICAL_URL global, so they cannot run in parallel with each other or with the
// other API-level tests in this package.

func TestTheChunkPostCarriesTheProxyTokenAndTheBucketPutDoesNot(t *testing.T) {
	var (
		mu         sync.Mutex
		postAuth   string
		putAuth    string
		putLength  string
		putType    string
		putBody    []byte
		postedPath string
	)

	bucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		putAuth = r.Header.Get("Authorization")
		putLength = r.Header.Get("Content-Length")
		putType = r.Header.Get("Content-Type")
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		putBody = buf
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer bucket.Close()

	infisical := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		postAuth = r.Header.Get("Authorization")
		postedPath = r.URL.Path
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"chunkId":"01K5ABCDEFGHJKMNPQRSTVWXYZ","uploadUrl":"` + bucket.URL + `/object","expiresInSeconds":300}`))
	}))
	defer infisical.Close()

	old := config.INFISICAL_URL
	config.INFISICAL_URL = infisical.URL + "/api"
	defer func() { config.INFISICAL_URL = old }()

	shipper, err := newActivityShipper(func() string { return "proxy-token" })
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := []byte("sealed-bytes")
	res, err := shipper.createChunk(false, "sess-1", api.CreateAgentVaultActivityChunkRequest{
		ChunkID:         "01K5ABCDEFGHJKMNPQRSTVWXYZ",
		RecordCount:     1,
		CiphertextBytes: len(ciphertext),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := shipper.putObject(context.Background(), res.UploadURL, ciphertext); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()

	if postAuth != "Bearer proxy-token" {
		t.Fatalf("Infisical saw Authorization %q", postAuth)
	}
	if postedPath != "/api/v1/agent-vault/proxy/sessions/sess-1/activity/chunks" {
		t.Fatalf("posted to %q", postedPath)
	}
	// The presigned URL is itself the authorization. Sending the proxy's bearer token to a customer's
	// bucket would hand a third party a working Infisical credential.
	if putAuth != "" {
		t.Fatalf("the bucket saw an Authorization header: %q", putAuth)
	}
	// The presign signs Content-Length in, so a mismatch is refused by S3.
	if putLength != strconv.Itoa(len(ciphertext)) {
		t.Fatalf("the upload declared Content-Length %q for %d bytes", putLength, len(ciphertext))
	}
	if putType != "application/octet-stream" {
		t.Fatalf("the upload declared Content-Type %q", putType)
	}
	if string(putBody) != string(ciphertext) {
		t.Fatalf("the bucket received %q", string(putBody))
	}
}

func TestABucketRefusalIsAnErrorThatNamesNoURL(t *testing.T) {
	bucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<Error><Code>AccessDenied</Code></Error>"))
	}))
	defer bucket.Close()

	shipper, err := newActivityShipper(func() string { return "proxy-token" })
	if err != nil {
		t.Fatal(err)
	}

	err = shipper.putObject(context.Background(), bucket.URL+"/object?X-Amz-Signature=secret", []byte("bytes"))
	if err == nil {
		t.Fatal("a 403 from the bucket was treated as a successful upload")
	}
	// A presigned URL carries a working signature, so it must never reach a log line.
	if got := err.Error(); strings.Contains(got, "X-Amz-Signature") || strings.Contains(got, bucket.URL) {
		t.Fatalf("the error names the signed url: %q", got)
	}
}
