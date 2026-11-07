package webapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
)

func reviewJPEG(t *testing.T, width, height int) string {
	t.Helper()
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, width, height)), nil); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(encoded.Bytes())
}
func reviewCDP(t *testing.T, s *Supervisor, handle func(cdpMessage) json.RawMessage) {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { local.Close(); remote.Close() })
	s.cdp = newCDP(NewMux(local, local))
	mux := NewMux(remote, remote)
	go func() {
		for {
			_, raw, err := mux.Read()
			if err != nil {
				return
			}
			var command cdpMessage
			if json.Unmarshal(raw, &command) != nil {
				return
			}
			result := handle(command)
			if result == nil {
				result = json.RawMessage(`{}`)
			}
			response, _ := json.Marshal(cdpMessage{ID: command.ID, SessionID: command.SessionID, Result: result})
			if mux.Write(MuxCDP, response) != nil {
				return
			}
		}
	}()
}
func TestPreResizeScreenshotCannotUnlockNewViewport(t *testing.T) {
	s, _, _ := supervisorFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	jpegData := reviewJPEG(t, 1280, 720)
	reviewCDP(t, s, func(command cdpMessage) json.RawMessage {
		if command.Method == "Page.captureScreenshot" {
			close(started)
			<-release
			b, _ := json.Marshal(map[string]string{"data": jpegData})
			return b
		}
		return nil
	})
	finished := make(chan error, 1)
	go func() { finished <- s.captureProbe() }()
	<-started
	s.mu.Lock()
	s.width = 1024
	s.height = 768
	s.viewportGen = 2
	s.frameViewportGen = 0
	s.metricsReadyAt = time.Now()
	s.mu.Unlock()
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frameViewportGen != 0 || s.frameSeq != 0 {
		t.Fatal("pre-resize screenshot stamped as current viewport")
	}
}
func TestStaleScreencastCannotUnlockNewViewport(t *testing.T) {
	s, _, _ := supervisorFixture(t)
	ready := time.Now()
	s.width = 1024
	s.height = 768
	s.viewportGen = 2
	s.frameViewportGen = 0
	s.metricsReadyAt = ready
	data := reviewJPEG(t, 1024, 768)
	if err := s.storeScreencast("page", data, 1024, 768, ready.Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := s.storeScreencast("page", data, 1280, 720, ready.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if s.frameViewportGen != 0 {
		t.Fatal("stale screencast unlocked input")
	}
	if err := s.storeScreencast("page", data, 1024, 768, time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.frameViewportGen != 2 {
		t.Fatal("fresh screencast did not unlock input")
	}
}

func TestRateLimitedFrameRetainsLatestTransition(t *testing.T) {
	s, recording, _ := supervisorFixture(t)
	first, latest := reviewJPEG(t, 16, 16), reviewJPEG(t, 32, 16)
	if err := s.storeFrame("page", first, false); err != nil {
		t.Fatal(err)
	}
	if err := s.storeFrame("page", latest, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		recording.mu.Lock()
		for _, event := range recording.events {
			if event["type"] == "frame" && event["jpeg"] == latest {
				recording.mu.Unlock()
				return
			}
		}
		recording.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("stable transition lost after capture rate limit")
}

func TestDialogAnswersUseOwningSurface(t *testing.T) {
	for _, owner := range []uint32{1, 2} {
		for _, accept := range []bool{false, true} {
			t.Run(strings.Join([]string{string(rune('0' + owner)), map[bool]string{false: "cancel", true: "accept"}[accept]}, "-"), func(t *testing.T) {
				s, _, _ := supervisorFixture(t)
				s.surfaces[2] = &surface{Seq: 2, session: "popup", ready: true}
				s.dialogSeq = 7
				s.dialog = map[string]any{"surfaceSeq": owner, "type": "confirm"}
				handled := make(chan cdpMessage, 1)
				data := reviewJPEG(t, 16, 16)
				reviewCDP(t, s, func(command cdpMessage) json.RawMessage {
					if command.Method == "Page.handleJavaScriptDialog" {
						handled <- command
					}
					if command.Method == "Page.captureScreenshot" {
						b, _ := json.Marshal(map[string]string{"data": data})
						return b
					}
					return nil
				})
				server, viewer := net.Pipe()
				defer server.Close()
				defer viewer.Close()
				stream := newStream(server, server, 1)
				defer stream.close()
				s.controller = stream
				s.controllerGen = 1
				go s.dispatchLoop()
				s.actions <- queuedAction{stream: stream, message: message{T: "dialog", Seq: 1, SurfaceSeq: owner, DialogSeq: 7, Accept: accept}}
				select {
				case command := <-handled:
					target := "page"
					if owner == 2 {
						target = "popup"
					}
					if command.SessionID != target {
						t.Fatalf("dialog sent to %s", command.SessionID)
					}
					var params struct {
						Accept bool `json:"accept"`
					}
					_ = json.Unmarshal(command.Params, &params)
					if params.Accept != accept {
						t.Fatal("wrong dialog answer")
					}
				case <-time.After(time.Second):
					t.Fatal("dialog reply discarded")
				}
			})
		}
	}
}

type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetWriteDeadline(time.Time) error { return nil }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return nil }

func TestBusyAttachmentHasRealTimeout(t *testing.T) {
	server, peer := net.Pipe()
	defer peer.Close()
	stream := newStream(noDeadlineConn{server}, server, 2)
	defer stream.close()
	result := make(chan error, 1)
	go func() { result <- stream.waitBusy(100 * time.Millisecond) }()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := ReadFrame(peer, FromGateway, true)
	if err != nil {
		t.Fatal(err)
	}
	var control struct {
		T string `json:"t"`
	}
	if json.Unmarshal(frame[1:], &control) != nil || control.T != "controller_busy" {
		t.Fatalf("wrong busy control: %s", frame)
	}
	select {
	case err := <-result:
		if err == nil || err.Error() != "busy" {
			t.Fatalf("wrong close cause: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("quiet busy attachment survived its timeout")
	}
	select {
	case <-stream.done:
	default:
		t.Fatal("busy relay remained open")
	}
}
func TestBlockedRelayWriteHasRealTimeout(t *testing.T) {
	server, reader := net.Pipe()
	defer reader.Close()
	stream := newStream(noDeadlineConn{server}, server, 1)
	defer stream.close()
	started := time.Now()
	err := stream.writeFrame(ControlFrame(map[string]string{"t": "ping"}), 20*time.Millisecond)
	if err == nil || err.Error() != "slow-reader" {
		t.Fatalf("blocked write: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("write watchdog did not close stalled relay")
	}
	if stream.readError(net.ErrClosed).Error() != "slow-reader" {
		t.Fatal("slow-reader close reason lost")
	}
	select {
	case <-stream.done:
	default:
		t.Fatal("stalled connection remained open")
	}
}

type crashWindowDocker struct {
	dockerSpy
	id                string
	queried           bool
	discoveryFailures int
	discoveryQueries  int
}

func (d *crashWindowDocker) Command(ctx context.Context, args ...string) (string, error) {
	if args[0] == "ps" {
		command := strings.Join(args, " ")
		if strings.Contains(command, "{{.Names}}") {
			d.mu.Lock()
			d.queried = strings.Contains(command, "label=infisical.pam.gateway=crash-gateway") && strings.Contains(command, "label=infisical.pam.session="+d.id)
			d.discoveryQueries++
			if d.discoveryFailures > 0 {
				d.discoveryFailures--
				d.mu.Unlock()
				return "", errors.New("temporary Docker discovery failure")
			}
			d.mu.Unlock()
			return "crashed-container pam-" + d.id + "-browser", nil
		}
		return "crashed-container " + d.id, nil
	}
	return d.dockerSpy.Command(ctx, args...)
}
func TestReapRecoversContainerCreatedBeforeIDPersistence(t *testing.T) {
	testReapRecovery(t, 0)
}
func TestReapRetriesDiscoveryAfterTransientFailure(t *testing.T) {
	testReapRecovery(t, 1)
}
func testReapRecovery(t *testing.T, discoveryFailures int) {
	t.Helper()
	prior := session.GetSessionRecordingDir()
	session.SetSessionRecordingPath(t.TempDir())
	t.Cleanup(func() { session.SetSessionRecordingPath(prior) })
	expiry := time.Now().Add(time.Minute)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.PAMWebStateResponse{ExpiresAt: expiry, LeaseUntil: time.Now().Add(30 * time.Second), LeaseSeconds: 30})
	}))
	defer platform.Close()
	oldURL := config.INFISICAL_URL
	config.INFISICAL_URL = platform.URL
	t.Cleanup(func() { config.INFISICAL_URL = oldURL })
	client := resty.New().SetTimeout(time.Second)
	cm := session.NewCredentialsManager(client)
	t.Cleanup(cm.Shutdown)
	id := uuid.NewString()
	docker := &crashWindowDocker{id: id, discoveryFailures: discoveryFailures}
	registry := NewRegistry("crash-gateway", DefaultOptions(), client, cm)
	registry.Docker = docker
	a := allocation{GatewayID: registry.GatewayID, AllocationGen: 1, State: "creating", CreatedAt: time.Now(), HardExpiry: expiry, LeaseUntil: time.Now().Add(-time.Second), ContainerIDs: map[string]string{}, ContainerNames: map[string]string{"browser": "pam-" + id + "-browser"}, Volume: "pam-" + id}
	b, _ := json.Marshal(a)
	if err := session.AtomicWrite(allocPath(id), b); err != nil {
		t.Fatal(err)
	}
	if err := registry.Reap(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	removed := false
	finished := false
	for time.Now().Before(deadline) {
		docker.mu.Lock()
		for _, command := range docker.commands {
			if strings.Join(command, " ") == "rm --force crashed-container" {
				removed = true
			}
		}
		docker.mu.Unlock()
		registry.mu.Lock()
		finished = registry.sessions[id] == nil && !registry.reportRecoveries[id]
		registry.mu.Unlock()
		if removed && finished {
			break
		}
		time.Sleep(time.Millisecond)
	}
	docker.mu.Lock()
	queried := docker.queried
	queries := docker.discoveryQueries
	docker.mu.Unlock()
	if !removed || !queried || queries <= discoveryFailures || !finished {
		t.Fatal("container in the create/persist crash window was stranded or not label-scoped")
	}
	b, err := os.ReadFile(allocPath(id))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(b, &a) != nil || a.ContainerIDs["browser"] != "crashed-container" {
		t.Fatal("recovered ID was not persisted")
	}
}
