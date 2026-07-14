package gatewayv2

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

const (
	sshExecConnDeadline    = 90 * time.Second
	sshExecDefaultTimeout  = 20 * time.Second
	maxSshExecRequestBytes = 1 * 1024 * 1024
	maxSshExecOutputBytes  = 4 * 1024 * 1024
)

// sshExecEnvelope is the request body for an SSH exec. Host and port come from the signed gateway certificate
type sshExecEnvelope struct {
	Command     string `json:"command"`
	AuthMethod  string `json:"authMethod"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	PrivateKey  string `json:"privateKey"`
	Certificate string `json:"certificate"`
	TimeoutMs   int    `json:"timeoutMs"`
}

type sshExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
}

type sshExecResponse struct {
	Result sshExecResult `json:"result"`
}

type sshExecErrorResponse struct {
	Error sshExecErrorBody `json:"error"`
}

type sshExecErrorBody struct {
	Message string `json:"message"`
}

func buildSSHExecAuth(env sshExecEnvelope) ([]ssh.AuthMethod, error) {
	switch env.AuthMethod {
	case "password":
		return []ssh.AuthMethod{ssh.Password(env.Password)}, nil
	case "public-key":
		signer, err := ssh.ParsePrivateKey([]byte(env.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	case "certificate":
		signer, err := ssh.ParsePrivateKey([]byte(env.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(env.Certificate))
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("parsed key is not a certificate")
		}
		certSigner, err := ssh.NewCertSigner(cert, signer)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate signer: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(certSigner)}, nil
	default:
		return nil, fmt.Errorf("invalid auth method: %s", env.AuthMethod)
	}
}

func doSSHExec(targetHost string, targetPort int, env sshExecEnvelope) (sshExecResult, error) {
	authMethods, err := buildSSHExecAuth(env)
	if err != nil {
		return sshExecResult{}, err
	}

	timeout := time.Duration(env.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = sshExecDefaultTimeout
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort), &ssh.ClientConfig{
		User:            env.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	})
	if err != nil {
		return sshExecResult{}, fmt.Errorf("failed to dial target SSH server: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return sshExecResult{}, fmt.Errorf("failed to open SSH session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &limitedWriter{buf: &stdout, limit: maxSshExecOutputBytes}
	sess.Stderr = &limitedWriter{buf: &stderr, limit: maxSshExecOutputBytes}

	exitCode := 0
	if runErr := sess.Run(env.Command); runErr != nil {
		var exitErr *ssh.ExitError
		if ok := asExitError(runErr, &exitErr); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			return sshExecResult{}, fmt.Errorf("failed to run command: %w", runErr)
		}
	}

	return sshExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitCode}, nil
}

// limitedWriter caps captured output so a hostile or misbehaving target can't exhaust gateway memory
type limitedWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if remaining := w.limit - w.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			w.buf.Write(p[:remaining])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

func asExitError(err error, target **ssh.ExitError) bool {
	return errors.As(err, target)
}

// serveSSHExecOverTLS reads one HTTP request off the TLS relay connection, runs the SSH command against the
// cert-configured target, and writes back a JSON response
func serveSSHExecOverTLS(ctx context.Context, conn *tls.Conn, reader *bufio.Reader, targetHost string, targetPort int) error {
	_ = conn.SetDeadline(time.Now().Add(sshExecConnDeadline))

	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("failed to read HTTP request: %w", err)
	}

	if req.Method != http.MethodPost || req.URL.Path != "/v1/exec" {
		return writeSSHExecJSON(conn, http.StatusNotFound, sshExecErrorResponse{Error: sshExecErrorBody{Message: "Unsupported endpoint"}})
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, maxSshExecRequestBytes))
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	var env sshExecEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return writeSSHExecJSON(conn, http.StatusBadRequest, sshExecErrorResponse{Error: sshExecErrorBody{Message: "Invalid request body"}})
	}

	result, execErr := doSSHExec(targetHost, targetPort, env)
	if execErr != nil {
		return writeSSHExecJSON(conn, http.StatusBadGateway, sshExecErrorResponse{Error: sshExecErrorBody{Message: execErr.Error()}})
	}

	return writeSSHExecJSON(conn, http.StatusOK, sshExecResponse{Result: result})
}

func writeSSHExecJSON(conn net.Conn, status int, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	resp := &http.Response{
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}, "Connection": {"close"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	if err := resp.Write(conn); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	log.Debug().Int("status", status).Msg("ssh-exec: response written")
	return nil
}
