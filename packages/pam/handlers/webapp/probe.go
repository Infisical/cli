package webapp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/google/uuid"
)

type ProbeResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func ProbeDestination(ctx context.Context, address string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return err
	}
	policy, err := newDestinationPolicy(ConnectorPolicy{AllowedDestinations: []api.PAMWebDestination{{Host: host, Port: port, Scheme: "http"}}, HostAddresses: discoverHostAddresses(ctx, nil)})
	if err != nil {
		return err
	}
	c := &connector{policy: policy, connections: map[net.Conn]bool{}}
	defer c.cut()
	conn, err := c.dial(ctx, host, port, "http")
	if err != nil {
		return err
	}
	return conn.Close()
}

func ProbeFromNetwork(ctx context.Context, options Options, gatewayID, host string, port int) error {
	return probeFromNetwork(ctx, dockerCLI{}, options, gatewayID, host, port)
}

func probeFromNetwork(ctx context.Context, docker Docker, options Options, gatewayID, host string, port int) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if options.Image == "" {
		return errors.New("browser runtime unavailable")
	}
	dir := filepath.Join(session.GetSessionRecordingDir(), "webapp")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "probe-*.cid")
	if err != nil {
		return err
	}
	path := f.Name()
	f.Close()
	if err := os.Remove(path); err != nil {
		return err
	}
	defer func() {
		if b, err := os.ReadFile(path); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				_, _ = docker.Command(ctx, "rm", "--force", id)
			}
		}
		_ = os.Remove(path)
	}()
	id := uuid.NewString()
	args := []string{"run", "--rm", "--cidfile", path, "--network", options.EgressNetwork, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "64m", "--pids-limit", "32", "--label", "infisical.pam.gateway=" + gatewayID, "--label", "infisical.pam.session=" + id, "--label", "infisical.pam.probe=1", options.Image, "pam", "browser-connector", "--probe", net.JoinHostPort(host, strconv.Itoa(port))}
	output, runErr := docker.Command(ctx, args...)
	var result ProbeResult
	if err := json.NewDecoder(strings.NewReader(output)).Decode(&result); err != nil {
		if runErr != nil {
			return runErr
		}
		return errors.New("invalid connector probe response")
	}
	if !result.OK {
		if result.Message == "" {
			return errors.New("connector probe failed")
		}
		return errors.New(result.Message)
	}
	return runErr
}
