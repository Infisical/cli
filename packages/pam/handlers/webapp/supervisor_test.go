package webapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
)

func TestFirstFrameAfterSurfaceChangeIsNotThrottled(t *testing.T) {
	s, recording, _ := supervisorFixture(t)
	var jpegBytes bytes.Buffer
	if err := jpeg.Encode(&jpegBytes, image.NewRGBA(image.Rect(0, 0, 16, 16)), nil); err != nil {
		t.Fatal(err)
	}
	data := base64.StdEncoding.EncodeToString(jpegBytes.Bytes())
	if err := s.storeFrame("page", data, false); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.surfaces[2] = &surface{Seq: 2, session: "popup", ready: true}
	s.active = 2
	s.viewportGen++
	s.frameViewportGen = 0
	s.mu.Unlock()
	if err := s.storeFrame("popup", data, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		recording.mu.Lock()
		seen := len(recording.events) == 2
		recording.mu.Unlock()
		if seen {
			break
		}
		time.Sleep(time.Millisecond)
	}
	recording.mu.Lock()
	defer recording.mu.Unlock()
	if len(recording.events) != 2 || recording.events[1]["surfaceSeq"] != float64(2) {
		t.Fatalf("first popup frame was dropped: %+v", recording.events)
	}
}

type recordingSpy struct {
	mu       sync.Mutex
	events   []map[string]any
	closed   bool
	failNext bool
	final    api.PAMWebFinal
	finished chan struct{}
}

func (r *recordingSpy) LogSessionEvent(e session.SessionEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("write after close")
	}
	if r.failNext {
		r.failNext = false
		return errors.New("injected fsync failure")
	}
	var v map[string]any
	if err := json.Unmarshal(e.Data, &v); err != nil {
		return err
	}
	r.events = append(r.events, v)
	return nil
}
func (r *recordingSpy) Done() <-chan struct{} { return r.finished }
func (r *recordingSpy) Close() error          { r.mu.Lock(); defer r.mu.Unlock(); r.closed = true; return nil }
func (r *recordingSpy) ChunkCount() int       { return 0 }
func (r *recordingSpy) Finish(f api.PAMWebFinal, _ string) error {
	r.mu.Lock()
	r.final = f
	r.mu.Unlock()
	close(r.finished)
	return nil
}

type dockerSpy struct {
	mu             sync.Mutex
	commands       [][]string
	inspectFailure bool
}

func (d *dockerSpy) Command(ctx context.Context, args ...string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.commands = append(d.commands, append([]string{}, args...))
	if args[0] == "inspect" {
		if d.inspectFailure {
			return "daemon unavailable", errors.New("daemon unavailable")
		}
		return "error: no such object", errors.New("absent")
	}
	return "resource-id", nil
}
func (d *dockerSpy) Start(context.Context, string) (*worker, error) {
	return nil, errors.New("unexpected worker creation")
}

func supervisorFixture(t *testing.T) (*Supervisor, *recordingSpy, *dockerSpy) {
	t.Helper()
	prior := session.GetSessionRecordingDir()
	session.SetSessionRecordingPath(t.TempDir())
	t.Cleanup(func() { session.SetSessionRecordingPath(prior) })
	id := uuid.NewString()
	expiry := time.Now().Add(time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.PAMWebStateResponse{ExpiresAt: expiry, LeaseUntil: time.Now().Add(30 * time.Second), LeaseSeconds: 30})
	}))
	t.Cleanup(server.Close)
	oldURL := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL
	t.Cleanup(func() { config.INFISICAL_URL = oldURL })
	client := resty.New().SetTimeout(time.Second)
	cm := session.NewCredentialsManager(client)
	t.Cleanup(cm.Shutdown)
	r := NewRegistry("test-gateway", DefaultOptions(), client, cm)
	d := &dockerSpy{}
	r.Docker = d
	credentials := &session.PAMCredentials{ExpiresAt: expiry, LeaseUntil: time.Now().Add(30 * time.Second), LeaseSeconds: 30, LeaseDeadline: time.Now().Add(30 * time.Second), WebPolicy: &api.PAMWebPolicy{ReconnectGraceSeconds: 60}, WebConnection: &api.PAMWebConnectionDetails{}}
	a := allocation{AllocationGen: 1, GatewayID: r.GatewayID, HardExpiry: expiry, LeaseUntil: credentials.LeaseUntil, ContainerIDs: map[string]string{"browser": "browser-id", "connector": "connector-id"}, Volume: "volume-id"}
	s := newSupervisor(r, id, a, credentials)
	spy := &recordingSpy{finished: make(chan struct{})}
	s.recorder = spy
	s.active = 1
	s.startSurface = 1
	s.surfaces[1] = &surface{Seq: 1, session: "page"}
	s.ready = true
	s.frameViewportGen = 1
	r.sessions[id] = s
	if err := session.AtomicWrite(allocPath(id), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	go s.reportLoop()
	t.Cleanup(func() {
		s.End("test-cleanup")
		select {
		case <-s.terminalDone:
			<-s.reportDone
		case <-time.After(3 * time.Second):
			t.Error("supervisor cleanup timed out")
		}
	})
	return s, spy, d
}

func TestEndActionTerminalOrdering(t *testing.T) {
	s, recording, docker := supervisorFixture(t)
	server, client := net.Pipe()
	defer client.Close()
	v := newStream(server, server, 1)
	defer v.close()
	s.controller = v
	s.controllerGen = 1
	go io.Copy(io.Discard, client)
	go s.dispatchLoop()
	s.actions <- queuedAction{stream: v, message: message{T: "end", Seq: 1}}
	select {
	case <-recording.finished:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal recording not finalized")
	}
	recording.mu.Lock()
	defer recording.mu.Unlock()
	var order []string
	for _, e := range recording.events {
		if e["type"] == "action" {
			order = append(order, "action:"+e["t"].(string))
		}
		if e["type"] == "lifecycle" {
			order = append(order, "lifecycle:"+e["phase"].(string))
		}
	}
	if strings.Join(order, ",") != "action:end,lifecycle:ending,lifecycle:ended" {
		t.Fatalf("terminal order %v", order)
	}
	docker.mu.Lock()
	defer docker.mu.Unlock()
	if len(docker.commands) < 5 || docker.commands[0][0] != "kill" {
		t.Fatal("execution was not stopped before verification")
	}
}

func TestRecordingFailureIsDurableAndTerminal(t *testing.T) {
	s, recording, _ := supervisorFixture(t)
	recording.failNext = true
	if err := s.record(map[string]any{"type": "input", "text": "typed"}); err == nil {
		t.Fatal("write failure hidden")
	}
	select {
	case <-recording.finished:
	case <-time.After(3 * time.Second):
		t.Fatal("recording failure did not end session")
	}
	b, err := os.ReadFile(allocPath(s.id))
	if err != nil {
		t.Fatal(err)
	}
	var a allocation
	if json.Unmarshal(b, &a) != nil || !a.RecordingFailed {
		t.Fatal("recording failure not persisted")
	}
	recording.mu.Lock()
	defer recording.mu.Unlock()
	if !recording.final.RecordingFailed || len(recording.final.Gaps) == 0 {
		t.Fatal("failure omitted from terminal report")
	}
}

func TestAllocationTombstoneLostAndCapacity(t *testing.T) {
	prior := session.GetSessionRecordingDir()
	session.SetSessionRecordingPath(t.TempDir())
	t.Cleanup(func() { session.SetSessionRecordingPath(prior) })
	r := NewRegistry("gateway", DefaultOptions(), resty.New(), session.NewCredentialsManager(resty.New()))
	id := uuid.NewString()
	if !r.Cancel(id) {
		t.Fatal("cancellation tombstone failed")
	}
	if _, err := r.GetOrCreate(id, 1, nil); err == nil {
		t.Fatal("cancelled allocation created")
	}
	id = uuid.NewString()
	if err := session.AtomicWrite(allocPath(id), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetOrCreate(id, 1, nil); err == nil || err.Error() != "allocation-lost" {
		t.Fatalf("old allocation recreated: %v", err)
	}
	r.Options.MaxSessions = 1
	r.sessions["occupied"] = &Supervisor{}
	if _, err := r.GetOrCreate(uuid.NewString(), 1, nil); err == nil || err.Error() != "capacity" {
		t.Fatalf("capacity not enforced: %v", err)
	}
}

type cancellationDocker struct {
	*dockerSpy
	registry  *Registry
	id        string
	t         *testing.T
	sawIntent bool
}

func (d *cancellationDocker) Command(ctx context.Context, args ...string) (string, error) {
	if len(args) > 1 && args[0] == "volume" && args[1] == "create" {
		b, err := os.ReadFile(allocPath(d.id))
		if err != nil {
			d.t.Error("Docker ran before durable allocation")
		}
		var a allocation
		if json.Unmarshal(b, &a) != nil || a.State != "creating" || a.GatewayID != d.registry.GatewayID {
			d.t.Error("allocation intent missing")
		}
		d.sawIntent = true
		d.registry.Cancel(d.id)
	}
	return d.dockerSpy.Command(ctx, args...)
}

func TestCancellationDuringAllocationNeverStartsWorker(t *testing.T) {
	s, _, base := supervisorFixture(t)
	s.End("unused-fixture")
	<-s.ended
	r := s.registry
	id := uuid.NewString()
	docker := &cancellationDocker{dockerSpy: base, registry: r, id: id, t: t}
	r.Docker = docker
	credentials := &session.PAMCredentials{AuthMethod: "none", ExpiresAt: time.Now().Add(time.Minute), LeaseUntil: time.Now().Add(30 * time.Second), LeaseSeconds: 30, LeaseDeadline: time.Now().Add(30 * time.Second), WebConnection: &api.PAMWebConnectionDetails{AllowedDestinations: []api.PAMWebDestination{{Host: "app.example", Port: 80, Scheme: "http"}}}, WebPolicy: &api.PAMWebPolicy{}}
	created, err := r.GetOrCreate(id, 1, credentials)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-created.terminalDone:
		<-created.reportDone
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled allocation did not stop")
	}
	if !docker.sawIntent {
		t.Fatal("allocation did not reach creation")
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	for _, args := range base.commands {
		if args[0] == "create" {
			t.Fatalf("worker created after tombstone: %v", args)
		}
	}
}

func TestPendingReportsDoNotPersistUploadToken(t *testing.T) {
	s, _, _ := supervisorFixture(t)
	s.allocMu.Lock()
	s.alloc.PendingReports = []api.PAMWebStateRequest{{ReportSeq: 1, UploadToken: "recording-secret-should-stay-encrypted"}}
	if err := s.saveAllocLocked(); err != nil {
		t.Fatal(err)
	}
	s.alloc.PendingReports = nil
	s.allocMu.Unlock()
	b, err := os.ReadFile(allocPath(s.id))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "recording-secret-should-stay-encrypted") {
		t.Fatal("upload token persisted in plaintext allocation")
	}
}

func TestDispatchDropsOldControllerAndStaleCoordinates(t *testing.T) {
	s, recording, _ := supervisorFixture(t)
	clientR, serverW := io.Pipe()
	serverR, clientW := io.Pipe()
	defer clientR.Close()
	defer clientW.Close()
	defer serverR.Close()
	defer serverW.Close()
	s.cdp = newCDP(NewMux(clientR, clientW))
	remote := NewMux(serverR, serverW)
	go func() {
		for {
			_, b, err := remote.Read()
			if err != nil {
				return
			}
			var m cdpMessage
			if json.Unmarshal(b, &m) != nil {
				return
			}
			response, _ := json.Marshal(cdpMessage{ID: m.ID, Result: json.RawMessage(`{}`)})
			if remote.Write(MuxCDP, response) != nil {
				return
			}
		}
	}()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	old := newStream(a, a, 1)
	defer old.close()
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	current := newStream(c, c, 2)
	defer current.close()
	s.controller = current
	s.controllerGen = 2
	s.actions <- queuedAction{stream: old, input: true, message: message{Seq: 1, SurfaceSeq: 1, ViewportGen: 1, Kind: "text", Text: "stale", Source: "type"}}
	s.actions <- queuedAction{stream: current, input: true, message: message{Seq: 2, SurfaceSeq: 2, ViewportGen: 1, Kind: "text", Text: "wrong-surface", Source: "type"}}
	s.actions <- queuedAction{stream: current, input: true, message: message{Seq: 3, SurfaceSeq: 1, ViewportGen: 2, Kind: "text", Text: "wrong-viewport", Source: "type"}}
	s.actions <- queuedAction{stream: current, input: true, message: message{Seq: 4, SurfaceSeq: 1, ViewportGen: 1, Kind: "text", Text: "dispatched", Source: "type"}}
	go s.dispatchLoop()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		recording.mu.Lock()
		n := len(recording.events)
		recording.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	recording.mu.Lock()
	if len(recording.events) != 1 || recording.events[0]["text"] != "dispatched" {
		t.Fatalf("stale input dispatched: %+v", recording.events)
	}
	recording.mu.Unlock()
	s.mu.Lock()
	if s.droppedInputs != 3 {
		t.Errorf("drop accounting %d", s.droppedInputs)
	}
	s.mu.Unlock()
}

func TestPermanentReportRefusalDoesNotWedgeFinalization(t *testing.T) {
	for _, dropped := range []string{"provisioning", "stopped"} {
		t.Run(dropped, func(t *testing.T) {
			prior := session.GetSessionRecordingDir()
			session.SetSessionRecordingPath(t.TempDir())
			t.Cleanup(func() { session.SetSessionRecordingPath(prior) })
			id := uuid.NewString()
			expiry := time.Now().Add(time.Minute)
			platform := newStrictPlatform(t, id, []byte("12345678901234567890123456789012"), expiry)
			platform.reject[dropped] = 409
			oldURL := config.INFISICAL_URL
			config.INFISICAL_URL = platform.server.URL
			t.Cleanup(func() { config.INFISICAL_URL = oldURL })
			client := resty.New().SetTimeout(time.Second)
			cm := session.NewCredentialsManager(client)
			t.Cleanup(cm.Shutdown)
			creds, err := cm.GetPAMSessionCredentials(id, expiry)
			if err != nil {
				t.Fatal(err)
			}
			cm.InvalidateSessionCredentials(id)
			if _, err := cm.GetPAMSessionCredentials(id, expiry); err != nil {
				t.Fatalf("empty later upload token was not restored: %v", err)
			}
			r := NewRegistry("report-test", DefaultOptions(), client, cm)
			r.Docker = &dockerSpy{}
			a := allocation{GatewayID: r.GatewayID, AllocationGen: 1, HardExpiry: expiry, LeaseUntil: creds.LeaseDeadline, CreatedAt: time.Now(), ContainerIDs: map[string]string{}, Volume: "test-volume"}
			s := newSupervisor(r, id, a, creds)
			r.sessions[id] = s
			recorder, err := session.NewWebRecording(id, expiry, cm, client)
			if err != nil {
				t.Fatal(err)
			}
			s.recorder = recorder
			go s.reportLoop()
			if err := s.lifecycle("provisioning", ""); err != nil {
				t.Fatal(err)
			}
			first := s.queueReport("provisioning", strings.Repeat("r", 700))
			select {
			case reply := <-first:
				if (dropped == "provisioning") != reply.refused {
					t.Fatal("incorrect report disposition")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("refused report waiter blocked")
			}
			if dropped == "provisioning" {
				select {
				case reply := <-s.queueReport("provisioned", ""):
					if reply.refused {
						t.Fatal("later report did not advance")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("report queue wedged")
				}
			}
			s.End("user-ended")
			select {
			case <-s.terminalDone:
			case <-time.After(15 * time.Second):
				t.Fatal("terminal sequence wedged")
			}
			<-s.reportDone
			platform.mu.Lock()
			status, refusals := platform.manifestStatus, platform.refusedCounts[dropped]
			platform.mu.Unlock()
			want := "complete"
			if dropped == "stopped" {
				want = "incomplete"
			}
			if status != want || refusals != 1 {
				t.Fatalf("status=%q want=%q refusals=%d", status, want, refusals)
			}
			if _, err := os.Stat(allocPath(id)); !os.IsNotExist(err) {
				t.Fatal("terminal allocation retained")
			}
		})
	}
}
