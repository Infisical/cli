package agentvault

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/go-resty/resty/v2"
)

func isSessionLogErrorNamed(err error, name string) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.Name == name
}

func isPoisonChunk(err error) bool {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	// Infisical's own NotFound is caught earlier as a gone session, so a 404 here is a route miss, as during a rollback.
	if apiErr.StatusCode == http.StatusRequestTimeout || apiErr.StatusCode == http.StatusTooManyRequests ||
		apiErr.StatusCode == http.StatusNotFound {
		return false
	}
	return apiErr.StatusCode >= 400 && apiErr.StatusCode < 500
}

type sessionLogShipperClient struct {
	steady *resty.Client
	final  *resty.Client
	put    *http.Client
}

func newSessionLogShipper(proxyToken func() string) (*sessionLogShipperClient, error) {
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
	final.SetAuthToken(proxyToken()).SetTimeout(sessionLogFinalTimeout)

	return &sessionLogShipperClient{
		steady: steady,
		final:  final,
		// Not resty: this goes to the customer's bucket and must never carry the Infisical auth token.
		put: &http.Client{
			Timeout:       sessionLogPutTimeout,
			Transport:     http.DefaultTransport.(*http.Transport).Clone(),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

var errInsecureUploadURL = errors.New("agent-vault: refusing to upload session logs to a link that is not https")

func scrubURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("agent-vault: could not reach the bucket: %w", urlErr.Err)
	}
	return err
}

func (c *sessionLogShipperClient) createChunk(ctx context.Context, final bool, sessionID string, req api.CreateAgentVaultSessionLogChunkRequest) (api.CreateAgentVaultSessionLogChunkResponse, error) {
	client := c.steady
	if final {
		client = c.final
	}
	return api.CallCreateAgentVaultSessionLogChunk(ctx, client, sessionID, req)
}

func (c *sessionLogShipperClient) putObject(ctx context.Context, uploadURL string, ciphertext []byte) error {
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
	// Signed into the link, so S3 refuses any body whose digest isn't the one Infisical recorded.
	req.Header.Set("X-Amz-Checksum-Sha256", sessionLogPaddedSHA256(ciphertext))

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
		if code := s3ErrorCode(res.Body); code != "" {
			return fmt.Errorf("agent-vault: the bucket refused the upload with status %d (%s)", res.StatusCode, code)
		}
		return fmt.Errorf("agent-vault: the bucket refused the upload with status %d", res.StatusCode)
	}
	return nil
}

var s3ErrorCodePattern = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// Only the code: S3's Message can quote the signed request.
func s3ErrorCode(body io.Reader) string {
	var parsed struct {
		Code string `xml:"Code"`
	}
	if err := xml.NewDecoder(io.LimitReader(body, 4<<10)).Decode(&parsed); err != nil {
		return ""
	}
	if !s3ErrorCodePattern.MatchString(parsed.Code) {
		return ""
	}
	return parsed.Code
}
