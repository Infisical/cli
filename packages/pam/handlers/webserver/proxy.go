package webserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type WebServerProxyConfig struct {
	TargetURI     string
	Username      string
	Password      string
	TLSConfig     *tls.Config
	SessionID     string
	SessionLogger session.SessionLogger
}

type WebServerProxy struct {
	config    WebServerProxyConfig
	targetURL *url.URL
	client    *http.Client
}

func NewWebServerProxy(config WebServerProxyConfig) (*WebServerProxy, error) {
	targetURL, err := url.Parse(config.TargetURI)
	if err != nil {
		return nil, fmt.Errorf("invalid web server URL: %w", err)
	}
	if targetURL.Host == "" || (targetURL.Scheme != "http" && targetURL.Scheme != "https") {
		return nil, fmt.Errorf("web server URL must include http or https scheme and host")
	}
	if targetURL.User != nil {
		return nil, fmt.Errorf("web server URL must not include user info")
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       config.TLSConfig,
	}

	return &WebServerProxy{
		config:    config,
		targetURL: targetURL,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func joinTargetURL(base, requestURL *url.URL) *url.URL {
	target := *base
	target.Path, target.RawPath = joinURLPath(base, requestURL)
	if target.RawQuery == "" || requestURL.RawQuery == "" {
		target.RawQuery += requestURL.RawQuery
	} else {
		target.RawQuery += "&" + requestURL.RawQuery
	}
	target.Fragment = ""
	return &target
}

func joinURLPath(base, requestURL *url.URL) (string, string) {
	if base.RawPath == "" && requestURL.RawPath == "" {
		baseSlash := strings.HasSuffix(base.Path, "/")
		requestSlash := strings.HasPrefix(requestURL.Path, "/")
		switch {
		case baseSlash && requestSlash:
			return base.Path + requestURL.Path[1:], ""
		case !baseSlash && !requestSlash:
			return base.Path + "/" + requestURL.Path, ""
		default:
			return base.Path + requestURL.Path, ""
		}
	}

	basePath := base.EscapedPath()
	requestPath := requestURL.EscapedPath()
	baseSlash := strings.HasSuffix(basePath, "/")
	requestSlash := strings.HasPrefix(requestPath, "/")
	switch {
	case baseSlash && requestSlash:
		return base.Path + requestURL.Path[1:], basePath + requestPath[1:]
	case !baseSlash && !requestSlash:
		return base.Path + "/" + requestURL.Path, basePath + "/" + requestPath
	default:
		return base.Path + requestURL.Path, basePath + requestPath
	}
}

func sanitizeHeaders(headers http.Header) http.Header {
	sanitized := headers.Clone()
	for _, name := range []string{
		"Authorization",
		"Proxy-Authorization",
		"Cookie",
		"Set-Cookie",
		"X-Api-Key",
		"X-Auth-Token",
	} {
		if _, exists := sanitized[name]; exists {
			sanitized[name] = []string{"[REDACTED]"}
		}
	}
	return sanitized
}

func removeHopByHopHeaders(headers http.Header) {
	connectionHeaders := headers.Values("Connection")
	for _, connectionHeader := range connectionHeaders {
		for _, token := range strings.Split(connectionHeader, ",") {
			if headerName := strings.TrimSpace(token); headerName != "" {
				headers.Del(headerName)
			}
		}
	}

	for _, headerName := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		headers.Del(headerName)
	}
}

func (p *WebServerProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	reader := bufio.NewReader(clientConn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read web server request: %w", err)
		}

		requestID := uuid.NewString()
		targetURL := joinTargetURL(p.targetURL, req.URL)
		if req.Method == http.MethodConnect || req.Header.Get("Upgrade") != "" {
			requestBody := readBufferedRequestBody(req, reader)
			p.logHTTPRequest(requestID, req, targetURL, requestBody)
			return p.writeErrorResponse(clientConn, requestID, http.StatusNotImplemented, []byte("protocol upgrades are not supported\n"))
		}

		if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
			if _, err := io.WriteString(clientConn, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				return fmt.Errorf("failed to write HTTP 100 Continue response: %w", err)
			}
		}

		requestBody, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read web server request body: %w", err)
		}
		if err := req.Body.Close(); err != nil {
			return fmt.Errorf("failed to close web server request body: %w", err)
		}

		p.logHTTPRequest(requestID, req, targetURL, requestBody)

		proxyReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL.String(), bytes.NewReader(requestBody))
		if err != nil {
			return fmt.Errorf("failed to create upstream web server request: %w", err)
		}
		proxyReq.Header = req.Header.Clone()
		removeHopByHopHeaders(proxyReq.Header)
		proxyReq.Header.Del("Authorization")
		proxyReq.Header.Del("Proxy-Authorization")
		proxyReq.Header.Del("Expect")
		proxyReq.SetBasicAuth(p.config.Username, p.config.Password)

		resp, err := p.client.Do(proxyReq)
		if err != nil {
			return p.writeBadGateway(clientConn, requestID)
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			if err := resp.Body.Close(); err != nil {
				log.Error().Err(err).Str("sessionId", p.config.SessionID).Msg("Failed to close upstream web server response body")
			}
			return p.writeBadGateway(clientConn, requestID)
		}

		var responseBody []byte
		var readErr error
		bodyAllowed := responseAllowsBody(req.Method, resp.StatusCode)
		if bodyAllowed {
			responseBody, readErr = io.ReadAll(resp.Body)
		}
		closeErr := resp.Body.Close()
		if readErr != nil {
			return p.writeBadGateway(clientConn, requestID)
		}
		if closeErr != nil {
			log.Error().Err(closeErr).Str("sessionId", p.config.SessionID).Msg("Failed to close upstream web server response body")
		}

		removeHopByHopHeaders(resp.Header)
		resp.Trailer = nil
		p.logHTTPEvent(session.HttpEvent{
			Timestamp: time.Now(),
			EventType: session.HttpEventResponse,
			RequestId: requestID,
			Headers:   sanitizeHeaders(resp.Header),
			Status:    resp.Status,
			Body:      responseBody,
		})

		resp.TransferEncoding = nil
		resp.Header.Del("Transfer-Encoding")
		if bodyAllowed {
			resp.Body = io.NopCloser(bytes.NewReader(responseBody))
			resp.ContentLength = int64(len(responseBody))
			resp.Header.Set("Content-Length", strconv.Itoa(len(responseBody)))
		} else {
			resp.Body = http.NoBody
		}
		if err := writeProxyResponse(clientConn, resp, bodyAllowed); err != nil {
			return fmt.Errorf("failed to write web server response: %w", err)
		}

		if req.Close || resp.Close {
			return nil
		}
	}
}

func readBufferedRequestBody(req *http.Request, reader *bufio.Reader) []byte {
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength <= 0 || req.ContentLength > int64(reader.Buffered()) {
		return nil
	}

	body := make([]byte, int(req.ContentLength))
	n, err := io.ReadFull(req.Body, body)
	if err != nil {
		return body[:n]
	}
	if err := req.Body.Close(); err != nil {
		return body
	}
	return body
}

func responseAllowsBody(method string, statusCode int) bool {
	return method != http.MethodHead && statusCode >= http.StatusOK && statusCode != http.StatusNoContent && statusCode != http.StatusNotModified
}

func writeProxyResponse(writer io.Writer, response *http.Response, bodyAllowed bool) error {
	if bodyAllowed {
		return response.Write(writer)
	}

	statusText := response.Status
	if statusText == "" {
		statusText = http.StatusText(response.StatusCode)
	} else {
		statusText = strings.TrimPrefix(statusText, strconv.Itoa(response.StatusCode)+" ")
	}
	if statusText == "" {
		statusText = "status code " + strconv.Itoa(response.StatusCode)
	}
	if _, err := fmt.Fprintf(writer, "HTTP/%d.%d %03d %s\r\n", response.ProtoMajor, response.ProtoMinor, response.StatusCode, statusText); err != nil {
		return err
	}

	headers := response.Header.Clone()
	if response.Close {
		headers.Set("Connection", "close")
	}
	if err := headers.Write(writer); err != nil {
		return err
	}
	_, err := io.WriteString(writer, "\r\n")
	return err
}

func (p *WebServerProxy) logHTTPRequest(requestID string, req *http.Request, targetURL *url.URL, body []byte) {
	p.logHTTPEvent(session.HttpEvent{
		Timestamp: time.Now(),
		EventType: session.HttpEventRequest,
		RequestId: requestID,
		Headers:   sanitizeHeaders(req.Header),
		Method:    req.Method,
		URL:       targetURL.String(),
		Body:      body,
	})
}

func (p *WebServerProxy) writeBadGateway(clientConn net.Conn, requestID string) error {
	return p.writeErrorResponse(clientConn, requestID, http.StatusBadGateway, []byte("bad gateway\n"))
}

func (p *WebServerProxy) writeErrorResponse(clientConn net.Conn, requestID string, statusCode int, responseBody []byte) error {
	response := &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(len(responseBody)),
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(responseBody)),
	}
	response.Header.Set("Content-Type", "text/plain")
	response.Header.Set("Content-Length", strconv.Itoa(len(responseBody)))
	response.Header.Set("Connection", "close")
	response.Close = true
	p.logHTTPEvent(session.HttpEvent{
		Timestamp: time.Now(),
		EventType: session.HttpEventResponse,
		RequestId: requestID,
		Headers:   sanitizeHeaders(response.Header),
		Status:    response.Status,
		Body:      responseBody,
	})

	if err := response.Write(clientConn); err != nil {
		return fmt.Errorf("failed to write web server error response: %w", err)
	}
	return nil
}

func (p *WebServerProxy) logHTTPEvent(event session.HttpEvent) {
	if p.config.SessionLogger == nil {
		return
	}
	if err := p.config.SessionLogger.LogHttpEvent(event); err != nil {
		log.Error().Err(err).Str("sessionId", p.config.SessionID).Msg("Failed to record web server HTTP event")
	}
}
