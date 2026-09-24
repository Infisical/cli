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

func isActivityErrorNamed(err error, name string) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.Name == name
}

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

type activityShipperClient struct {
	steady *resty.Client
	final  *resty.Client
	put    *http.Client
}

func newActivityShipper(proxyToken func() string) (*activityShipperClient, error) {
	steady, err := util.GetRestyClientWithPolicy(util.RetryPolicy{})
	if err != nil {
		return nil, err
	}
	steady.SetAuthToken(proxyToken()).SetTimeout(controlPlaneTimeout)

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
		// Not resty: this goes to the customer's bucket and must never carry the Infisical auth token.
		put: &http.Client{
			Timeout:       activityPutTimeout,
			Transport:     http.DefaultTransport.(*http.Transport).Clone(),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

var errInsecureUploadURL = errors.New("agent-vault: refusing to upload activity to a link that is not https")

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
	req.ContentLength = int64(len(ciphertext))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(ciphertext)))
	req.Header.Set("If-None-Match", "*")

	res, err := c.put.Do(req)
	if err != nil {
		return scrubURLError(err)
	}
	defer res.Body.Close()

	// If-None-Match hit: an earlier PUT stored this chunk but its response was lost.
	if res.StatusCode == http.StatusPreconditionFailed {
		return nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("agent-vault: the bucket refused the upload with status %d", res.StatusCode)
	}
	return nil
}
