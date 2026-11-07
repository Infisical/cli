package webapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
)

type allocation struct {
	ContainerNames        map[string]string `json:"containerNames"`
	TerminalEventIncluded bool              `json:"terminalEventIncluded"`
	Gaps                  []api.PAMWebGap   `json:"gaps"`
	DroppedCaptureFrames  uint64            `json:"droppedCaptureFrames"`
	DroppedMoves          uint64            `json:"droppedMoves"`
	EndReason             string            `json:"endReason"`
	ReportedState         string            `json:"reportedState"`
	LastRefusedReport     uint64            `json:"lastRefusedReport,omitzero"`
	LastReportStatus      int               `json:"lastReportStatus,omitzero"`

	RecordingFailed bool                     `json:"recordingFailed"`
	AllocationGen   uint32                   `json:"allocationGen"`
	GatewayID       string                   `json:"gatewayId"`
	State           string                   `json:"state"`
	LeaseUntil      time.Time                `json:"leaseUntil"`
	HardExpiry      time.Time                `json:"hardExpiry"`
	CreatedAt       time.Time                `json:"createdAt"`
	ContainerIDs    map[string]string        `json:"containerIds"`
	Volume          string                   `json:"volume"`
	ReportSeq       uint64                   `json:"reportSeq"`
	PendingReports  []api.PAMWebStateRequest `json:"pendingReports"`
}

type Registry struct {
	reportRecoveries map[string]bool
	lastSweep        time.Time
	mu               sync.Mutex
	sessions         map[string]*Supervisor
	GatewayID        string
	Options          Options
	Docker           Docker
	Client           *resty.Client
	Credentials      *session.CredentialsManager
	Register         func(string, func()) func()
}

func NewRegistry(gatewayID string, options Options, client *resty.Client, credentials *session.CredentialsManager) *Registry {
	return &Registry{sessions: map[string]*Supervisor{}, reportRecoveries: map[string]bool{}, GatewayID: gatewayID, Options: options, Docker: dockerCLI{}, Client: client, Credentials: credentials}
}

func allocPath(id string) string {
	return filepath.Join(session.GetSessionRecordingDir(), "webapp", id+".alloc")
}
func tombPath(id string) string {
	return filepath.Join(session.GetSessionRecordingDir(), "webapp", id+".tomb")
}

func (r *Registry) Cancel(id string) bool {
	if _, err := uuid.Parse(id); err != nil {
		return false
	}
	err := session.AtomicWrite(tombPath(id), []byte(time.Now().UTC().Format(time.RFC3339Nano)))
	r.mu.Lock()
	s := r.sessions[id]
	r.mu.Unlock()
	if s != nil {
		go s.End("terminated")
	}
	return err == nil
}

func (r *Registry) GetOrCreate(id string, gen uint32, credentials *session.PAMCredentials) (*Supervisor, error) {
	if _, err := uuid.Parse(id); err != nil || gen == 0 {
		return nil, errors.New("invalid session allocation")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := r.sessions[id]; s != nil {
		if s.alloc.AllocationGen != gen {
			return nil, errors.New("allocation-lost")
		}
		return s, nil
	}
	if _, err := os.Stat(tombPath(id)); err == nil {
		return nil, errors.New("session cancelled")
	}
	if _, err := os.Stat(allocPath(id)); err == nil {
		var a allocation
		if b, err := os.ReadFile(allocPath(id)); err == nil && json.Unmarshal(b, &a) == nil && a.GatewayID == r.GatewayID && a.AllocationGen == gen && a.State != "stopped" {
			r.recoverLocked(id, a)
		}
		return nil, errors.New("allocation-lost")
	}
	if len(r.sessions) >= r.Options.MaxSessions {
		return nil, errors.New("capacity")
	}
	if credentials.WebConnection == nil || credentials.WebPolicy == nil || credentials.ExpiresAt.IsZero() || credentials.LeaseUntil.IsZero() || !time.Now().Before(credentials.ExpiresAt) || credentials.LeaseSeconds <= 0 || credentials.LeaseSeconds > 45 || !time.Now().Before(credentials.LeaseDeadline) || credentials.LeaseUntil.After(credentials.ExpiresAt) || credentials.LeaseUntil.After(time.Now().Add(60*time.Second)) {
		return nil, errors.New("invalid browser credentials or deadlines")
	}
	if credentials.AuthMethod != "none" && credentials.AuthMethod != "basic-auth" {
		return nil, errors.New("unsupported browser authentication")
	}
	if _, err := newDestinationPolicy(ConnectorPolicy{AllowedDestinations: credentials.WebConnection.AllowedDestinations, DenyCIDRs: credentials.WebConnection.ExtraDenyCIDRs}); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(allocPath(id)), 0700); err != nil {
		return nil, err
	}
	a := allocation{ContainerNames: map[string]string{"browser": "pam-" + id + "-browser", "connector": "pam-" + id + "-connector"}, AllocationGen: gen, GatewayID: r.GatewayID, State: "creating", LeaseUntil: credentials.LeaseDeadline, HardExpiry: credentials.ExpiresAt, CreatedAt: time.Now(), ContainerIDs: map[string]string{}, Volume: "pam-" + id}
	b, _ := json.Marshal(a)
	f, err := os.OpenFile(allocPath(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("allocation-lost: %w", err)
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	dir, err := os.Open(filepath.Dir(allocPath(id)))
	if err != nil {
		return nil, err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return nil, err
	}
	s := newSupervisor(r, id, a, credentials)
	r.sessions[id] = s
	if r.Register != nil {
		s.deregister = r.Register(id, func() { r.Cancel(id) })
	}
	go s.reportLoop()
	go s.run()
	return s, nil
}

func (r *Registry) recoverLocked(id string, a allocation) {
	if r.sessions[id] != nil {
		return
	}
	creds := &session.PAMCredentials{ExpiresAt: a.HardExpiry, LeaseUntil: a.LeaseUntil, LeaseDeadline: a.LeaseUntil, WebPolicy: &api.PAMWebPolicy{}, WebConnection: &api.PAMWebConnectionDetails{}}
	s := newSupervisor(r, id, a, creds)
	s.ending = true
	r.sessions[id] = s
	go s.reportLoop()
	go func() { s.queueReport("failed", "worker-lost"); s.End("worker-lost") }()
}

func (r *Registry) recoverStoppedLocked(id string, a allocation) {
	if r.reportRecoveries[id] || r.sessions[id] != nil {
		return
	}
	if r.reportRecoveries == nil {
		r.reportRecoveries = map[string]bool{}
	}
	r.reportRecoveries[id] = true
	s := newSupervisor(r, id, a, &session.PAMCredentials{ExpiresAt: a.HardExpiry, LeaseDeadline: a.LeaseUntil})
	s.ending = true
	go s.reportLoop()
	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.reportRecoveries, id)
			r.mu.Unlock()
		}()
		<-s.reportDone
		final := api.PAMWebFinal{RecordingFailed: a.RecordingFailed, TerminalEventIncluded: a.TerminalEventIncluded, Gaps: a.Gaps, DroppedCaptureFrames: a.DroppedCaptureFrames, DroppedMoves: a.DroppedMoves}
		recorder, err := session.RecoverWebRecording(id, r.Credentials, r.Client, final, a.EndReason)
		if err == nil && recorder != nil {
			<-recorder.Done()
		}
	}()
}

func (r *Registry) Stop() {
	r.mu.Lock()
	var sessions []*Supervisor
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	for _, s := range sessions {
		go s.End("gateway-stopping")
	}
}

func (r *Registry) Reap(ctx context.Context) error {
	r.sweepExpiredAllocations()
	entries, readErr := os.ReadDir(filepath.Join(session.GetSessionRecordingDir(), "webapp"))
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".alloc")
		if !ok {
			continue
		}
		if _, err := uuid.Parse(id); err != nil {
			continue
		}
		b, err := os.ReadFile(allocPath(id))
		if err != nil {
			return err
		}
		var a allocation
		if json.Unmarshal(b, &a) != nil {
			continue
		}
		if a.GatewayID != r.GatewayID {
			continue
		}
		if a.State == "stopped" {
			r.mu.Lock()
			r.recoverStoppedLocked(id, a)
			r.mu.Unlock()
		} else if !time.Now().Before(a.LeaseUntil) || !time.Now().Before(a.HardExpiry) {
			r.mu.Lock()
			r.recoverLocked(id, a)
			r.mu.Unlock()
		}
	}
	output, err := r.Docker.Command(ctx, "ps", "--all", "--filter", "label=infisical.pam.gateway="+r.GatewayID, "--format", "{{.ID}} {{.Label \"infisical.pam.session\"}} {{.Label \"infisical.pam.probe\"}}")
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || len(fields) > 3 || len(fields) == 3 && fields[2] == "1" {
			continue
		}
		id := fields[1]
		if _, err := uuid.Parse(id); err != nil {
			continue
		}
		r.mu.Lock()
		live := r.sessions[id] != nil
		r.mu.Unlock()
		if live {
			continue
		}
		var a allocation
		b, err := os.ReadFile(allocPath(id))
		if err == nil {
			if err = json.Unmarshal(b, &a); err != nil {
				return err
			}
		}
		if err == nil && a.GatewayID != r.GatewayID {
			continue
		}
		if err == nil && time.Now().Before(a.LeaseUntil) && time.Now().Before(a.HardExpiry) {
			continue
		}
		if err := session.AtomicWrite(tombPath(id), []byte("worker-lost")); err != nil {
			return err
		}
		_, _ = r.Docker.Command(ctx, "kill", fields[0])
		if _, err := r.Docker.Command(ctx, "rm", "--force", fields[0]); err != nil {
			return err
		}
		volume := "pam-" + id
		if a.Volume != "" {
			volume = a.Volume
		}
		_, _ = r.Docker.Command(ctx, "volume", "rm", volume)
	}
	return nil
}

func (r *Registry) sweepExpiredAllocations() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastSweep) < 24*time.Hour {
		return
	}
	r.lastSweep = time.Now()
	entries, _ := os.ReadDir(filepath.Join(session.GetSessionRecordingDir(), "webapp"))
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".alloc")
		if !ok || r.sessions[id] != nil || r.reportRecoveries[id] {
			continue
		}
		b, err := os.ReadFile(allocPath(id))
		var a allocation
		if err != nil || json.Unmarshal(b, &a) != nil || a.GatewayID != r.GatewayID || a.HardExpiry.IsZero() || time.Now().Before(a.HardExpiry.Add(7*24*time.Hour)) {
			continue
		}
		_ = os.Remove(tombPath(id))
		_ = os.Remove(allocPath(id))
	}
}
