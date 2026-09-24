package agentvault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
)

func TestTheChunkPostCarriesTheProxyTokenAndTheBucketPutDoesNot(t *testing.T) {
	var (
		mu         sync.Mutex
		postAuth   string
		putAuth    string
		putLength  string
		putType    string
		putIfNone  string
		putBody    []byte
		postedPath string
	)

	bucket := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		putAuth = r.Header.Get("Authorization")
		putLength = r.Header.Get("Content-Length")
		putType = r.Header.Get("Content-Type")
		putIfNone = r.Header.Get("If-None-Match")
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
	shipper.put.Transport = bucket.Client().Transport

	ciphertext := []byte("sealed-bytes")
	res, err := shipper.createChunk(context.Background(), false, "sess-1", api.CreateAgentVaultActivityChunkRequest{
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
	if putAuth != "" {
		t.Fatalf("the bucket saw an Authorization header: %q", putAuth)
	}
	if putLength != strconv.Itoa(len(ciphertext)) {
		t.Fatalf("the upload declared Content-Length %q for %d bytes", putLength, len(ciphertext))
	}
	if putType != "application/octet-stream" {
		t.Fatalf("the upload declared Content-Type %q", putType)
	}
	if putIfNone != "*" {
		t.Fatalf("the upload sent If-None-Match %q; it must be create-only", putIfNone)
	}
	if string(putBody) != string(ciphertext) {
		t.Fatalf("the bucket received %q", string(putBody))
	}
}

func TestABucketRefusalIsAnErrorThatNamesNoURL(t *testing.T) {
	bucket := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<Error><Code>AccessDenied</Code></Error>"))
	}))
	defer bucket.Close()

	shipper, err := newActivityShipper(func() string { return "proxy-token" })
	if err != nil {
		t.Fatal(err)
	}
	shipper.put.Transport = bucket.Client().Transport

	err = shipper.putObject(context.Background(), bucket.URL+"/object?X-Amz-Signature=secret", []byte("bytes"))
	if err == nil {
		t.Fatal("a 403 from the bucket was treated as a successful upload")
	}
	if got := err.Error(); strings.Contains(got, "X-Amz-Signature") || strings.Contains(got, bucket.URL) {
		t.Fatalf("the error names the signed url: %q", got)
	}
}

func TestAnUploadLinkThatIsNotHttpsIsRefused(t *testing.T) {
	var hits atomic.Int32
	bucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer bucket.Close()

	shipper, err := newActivityShipper(func() string { return "proxy-token" })
	if err != nil {
		t.Fatal(err)
	}

	if err := shipper.putObject(context.Background(), bucket.URL+"/object", []byte("bytes")); err == nil {
		t.Fatal("an http upload link was accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("the proxy sent the chunk to a link that is not https")
	}
}

func TestARedirectFromTheBucketIsNotFollowed(t *testing.T) {
	var followed atomic.Int32
	bucket := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer bucket.Close()

	shipper, err := newActivityShipper(func() string { return "proxy-token" })
	if err != nil {
		t.Fatal(err)
	}
	shipper.put.Transport = bucket.Client().Transport

	if err := shipper.putObject(context.Background(), bucket.URL+"/object", []byte("bytes")); err == nil {
		t.Fatal("a redirect was treated as a successful upload")
	}
	if followed.Load() != 0 {
		t.Fatal("the upload followed a redirect")
	}
}

func TestAnUnreachableBucketIsAnErrorThatNamesNoSignature(t *testing.T) {
	bucket := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	target := bucket.URL + "/object?X-Amz-Signature=secret"
	bucket.Close()

	shipper, err := newActivityShipper(func() string { return "proxy-token" })
	if err != nil {
		t.Fatal(err)
	}

	err = shipper.putObject(context.Background(), target, []byte("bytes"))
	if err == nil {
		t.Fatal("an upload to a closed server succeeded")
	}
	if strings.Contains(err.Error(), "X-Amz-Signature") {
		t.Fatalf("the error names the signed url: %q", err.Error())
	}
}

func TestAChunkAlreadyStoredCountsAsUploaded(t *testing.T) {
	bucket := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
	}))
	defer bucket.Close()

	shipper, err := newActivityShipper(func() string { return "proxy-token" })
	if err != nil {
		t.Fatal(err)
	}
	shipper.put.Transport = bucket.Client().Transport

	if err := shipper.putObject(context.Background(), bucket.URL+"/object", []byte("bytes")); err != nil {
		t.Fatalf("a chunk that is already stored was treated as a failed upload: %v", err)
	}
}
