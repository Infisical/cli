package agentvault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
)

// isActivityErrorNamed matches the two named refusals the backend raises for activity. Both mean "stop
// asking for a while" rather than "this chunk is bad".
func isActivityErrorNamed(err error, name string) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.Name == name
}

// isPoisonChunk is a 4xx the server will never accept: a schema failure or a chunk whose own numbers
// contradict each other. Retrying one costs the spool behind it, so it is dropped instead.
//
// 401, 404 and the two named refusals are handled before this is reached, and 429 is deliberately not
// here: it is a "later", not a refusal.
func isPoisonChunk(err error) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.StatusCode == http.StatusTooManyRequests {
		return false
	}
	return apiErr.StatusCode >= 400 && apiErr.StatusCode < 500
}

// activityShipperClient carries three clients because the three calls want three different policies.
type activityShipperClient struct {
	steady *resty.Client
	final  *resty.Client
	put    *http.Client
}

func newActivityShipper(proxyToken func() string) (*activityShipperClient, error) {
	// No retries on the steady path: a failed create is retried by the next tick, which is the same
	// backoff with none of the risk of piling requests onto a struggling control plane.
	steady, err := util.GetRestyClientWithPolicy(util.RetryPolicy{})
	if err != nil {
		return nil, err
	}
	steady.SetAuthToken(proxyToken()).SetTimeout(controlPlaneTimeout)

	// Shutdown gets one retry and a short deadline: there is no next tick, and creating a chunk is
	// idempotent by chunk id, so a replay cannot double-write.
	finalPolicy := util.BestEffortRetryPolicy()
	finalPolicy.ReplaySafe = true
	final, err := util.GetRestyClientWithPolicy(finalPolicy)
	if err != nil {
		return nil, err
	}
	final.SetAuthToken(proxyToken()).SetTimeout(activityFinalTimeout)

	return &activityShipperClient{
		steady: steady,
		final:  final,
		// Deliberately not a resty client: this one talks to the customer's bucket with a presigned URL
		// and must never carry the Infisical Authorization header those two set.
		put: &http.Client{
			Timeout:   activityPutTimeout,
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
			// A presigned URL only works on the host it was signed for, so a redirect can never lead to a
			// successful upload. Following one could only send the chunk somewhere it was not meant to go.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Every presigned S3 upload link is https. Any other link did not come from S3.
var errInsecureUploadURL = errors.New("agent-vault: refusing to upload activity to a link that is not https")

// scrubURLError drops the URL from a request error. net/http writes the whole URL into the message, and for a
// presigned upload that is a working signature, which the caller logs on every timeout.
func scrubURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("agent-vault: could not reach the bucket: %w", urlErr.Err)
	}
	return err
}

func (c *activityShipperClient) createChunk(final bool, sessionID string, req api.CreateAgentVaultActivityChunkRequest) (api.CreateAgentVaultActivityChunkResponse, error) {
	client := c.steady
	if final {
		client = c.final
	}
	return api.CallCreateAgentVaultActivityChunk(client, sessionID, req)
}

func (c *activityShipperClient) putObject(ctx context.Context, uploadURL string, ciphertext []byte) error {
	target, err := url.Parse(uploadURL)
	if err != nil {
		return scrubURLError(err)
	}
	if target.Scheme != "https" {
		return errInsecureUploadURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(ciphertext))
	if err != nil {
		return scrubURLError(err)
	}
	// The presign signs Content-Length in, so it has to match the body exactly.
	req.ContentLength = int64(len(ciphertext))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(ciphertext)))
	// Signed in too: the link is create-only, so it can finish an upload but never replace a stored chunk.
	req.Header.Set("If-None-Match", "*")

	res, err := c.put.Do(req)
	if err != nil {
		return scrubURLError(err)
	}
	defer res.Body.Close()

	// The object is already there: an earlier PUT landed but its response never arrived. The chunk is stored,
	// which is all a retry wanted.
	if res.StatusCode == http.StatusPreconditionFailed {
		return nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// The body can carry an S3 error document; the status is enough to decide, and the URL is signed
		// so it never goes in a log line.
		return fmt.Errorf("agent-vault: the bucket refused the upload with status %d", res.StatusCode)
	}
	return nil
}
