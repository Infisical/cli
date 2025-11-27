package api

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/util"
)

type GenericRequestError struct {
	err       error
	operation string
}

func (e *GenericRequestError) Error() string {
	return fmt.Sprintf("%s: Unable to complete api request [err=%v]", e.operation, e.err)
}

func NewGenericRequestError(operation string, err error) *GenericRequestError {
	return &GenericRequestError{err: err, operation: operation}
}

// APIError represents an error response from the API
type APIError struct {
	AdditionalContext string   `json:"additionalContext,omitempty"`
	ExtraMessages     []string `json:"-"`
	Details           any      `json:"details,omitempty"`
	Operation         string   `json:"operation"`
	Method            string   `json:"method"`
	URL               string   `json:"url"`
	StatusCode        int      `json:"statusCode"`
	ErrorMessage      string   `json:"message,omitempty"`
	ReqId             string   `json:"reqId,omitempty"`
}

func (e APIError) Error() string {
	msg := fmt.Sprintf(
		"%s Unsuccessful response [%v %v] [status-code=%v] [request-id=%v]",
		e.Operation,
		e.Method,
		e.URL,
		e.StatusCode,
		e.ReqId,
	)

	if e.ErrorMessage != "" {
		msg = fmt.Sprintf("%s [message=\"%s\"]", msg, e.ErrorMessage)
	}

	if e.AdditionalContext != "" {
		msg = fmt.Sprintf("%s [additional-context=\"%s\"]", msg, e.AdditionalContext)
	}

	if e.Details != nil {
		// Check if details is an empty slice or empty map
		isEmpty := false
		switch v := e.Details.(type) {
		case []string:
			isEmpty = len(v) == 0
		case []any:
			isEmpty = len(v) == 0
		case map[string]any:
			isEmpty = len(v) == 0
		}

		if !isEmpty {
			// Marshal details to JSON for proper display
			if detailsJSON, err := json.Marshal(e.Details); err == nil {
				msg = fmt.Sprintf("%s [details=%s]", msg, string(detailsJSON))
			} else {
				msg = fmt.Sprintf("%s [details=\"%v\"]", msg, e.Details)
			}
		}
	}

	return msg
}

func NewAPIErrorWithResponse(operation string, res *resty.Response, additionalContext *string) error {
	errorMessage, details := TryParseErrorBody(res)
	reqId := util.TryExtractReqId(res)

	if res == nil {
		return NewGenericRequestError(operation, fmt.Errorf("response is nil"))
	}

	apiError := &APIError{
		Operation:  operation,
		Method:     res.Request.Method,
		URL:        res.Request.URL,
		StatusCode: res.StatusCode(),
		ReqId:      reqId,
	}

	if additionalContext != nil && *additionalContext != "" {
		apiError.AdditionalContext = *additionalContext
	}

	if errorMessage != "" {
		apiError.ErrorMessage = errorMessage
	}

	if details != nil {
		apiError.Details = details
	}

	if res.StatusCode() == 403 || res.StatusCode() == 401 {
		if apiError.AdditionalContext == "" {
			domainHint := extractDomainHint(res.Request.URL)
			if domainHint != "" {
				apiError.AdditionalContext = fmt.Sprintf("This error often indicates you're using the wrong Infisical instance. Current request is to: %s\n\nTo fix this:\n• Verify you're using the correct domain with --domain flag or INFISICAL_API_URL environment variable\n• For EU region: use --domain https://eu.infisical.com\n• For self-hosted instances: use --domain https://your-instance.com", domainHint)
			}
		}
	}

	return apiError
}

func extractDomainHint(urlStr string) string {
	if urlStr == "" {
		return ""
	}

	if parsedURL, err := url.Parse(urlStr); err == nil && parsedURL.Host != "" {
		return parsedURL.Scheme + "://" + parsedURL.Host
	}

	return ""
}

type errorResponse struct {
	Message string `json:"message"`
	Details any    `json:"details"`
	ReqId   string `json:"reqId"`
}

/*
Instead of changing the signature of the sdk function - let's just keep a one local to this codebase
*/
func TryParseErrorBody(res *resty.Response) (string, any) {
	var details any

	if res == nil || !res.IsError() {
		return "", details
	}

	body := res.String()
	if body == "" {
		return "", details
	}

	// stringify zod body entirely
	if res.StatusCode() == 422 {
		return body, details
	}

	// now we have a string, we need to try to parse it as json
	var errorResponse errorResponse

	err := json.Unmarshal([]byte(body), &errorResponse)

	if err != nil {
		return "", details
	}

	// Check if details is empty and return nil if so
	if errorResponse.Details != nil {
		switch v := errorResponse.Details.(type) {
		case []any:
			if len(v) == 0 {
				return errorResponse.Message, nil
			}
		case []string:
			if len(v) == 0 {
				return errorResponse.Message, nil
			}
		case map[string]any:
			if len(v) == 0 {
				return errorResponse.Message, nil
			}
		case string:
			if v == "" {
				return errorResponse.Message, nil
			}
		}
	}

	return errorResponse.Message, errorResponse.Details
}
