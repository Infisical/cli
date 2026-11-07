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
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
)

func dialogCDP(t *testing.T, s *Supervisor, blockScreenshot bool) (*Mux, *atomic.Int32, <-chan struct{}) {
	t.Helper()
	blocked := 0
	if blockScreenshot {
		blocked = -1
	}
	return probeCDP(t, s, blocked)
}

func probeCDP(t *testing.T, s *Supervisor, blocked int) (*Mux, *atomic.Int32, <-chan struct{}) {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { local.Close(); remote.Close() })
	s.cdp = newCDP(NewMux(local, local))
	mux := NewMux(remote, remote)
	calls := new(atomic.Int32)
	started := make(chan struct{}, 1)
	var jpegData bytes.Buffer
	if err := jpeg.Encode(&jpegData, image.NewRGBA(image.Rect(0, 0, 16, 16)), nil); err != nil {
		t.Fatal(err)
	}
	data := base64.StdEncoding.EncodeToString(jpegData.Bytes())
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
			result := json.RawMessage(`{}`)
			if command.Method == "Page.captureScreenshot" {
				count := calls.Add(1)
				select {
				case started <- struct{}{}:
				default:
				}
				if blocked < 0 || int(count) <= blocked {
					continue
				}
				result, _ = json.Marshal(map[string]string{"data": data})
			}
			response, _ := json.Marshal(cdpMessage{ID: command.ID, SessionID: command.SessionID, Result: result})
			if mux.Write(MuxCDP, response) != nil {
				return
			}
		}
	}()
	go s.browserEvents()
	return mux, calls, started
}

func emitConfirm(t *testing.T, mux *Mux) {
	t.Helper()
	raw, _ := json.Marshal(cdpMessage{Method: "Page.javascriptDialogOpening", SessionID: "page", Params: json.RawMessage(`{"type":"confirm","message":"Confirm fixture?","defaultPrompt":""}`)})
	if err := mux.Write(MuxCDP, raw); err != nil {
		t.Fatal(err)
	}
}

func TestPendingDialogDeliversControlAndSuspendsProbe(t *testing.T) {
	s, recording, _ := supervisorFixture(t)
	mux, calls, started := dialogCDP(t, s, false)
	server, viewer := net.Pipe()
	defer server.Close()
	defer viewer.Close()
	controller := newStream(server, server, 1)
	defer controller.close()
	s.controller = controller
	s.controllerGen = 1
	_ = viewer.SetReadDeadline(time.Now().Add(time.Second))
	emitConfirm(t, mux)
	frame, err := ReadFrame(viewer, FromGateway, true)
	if err != nil {
		t.Fatalf("dialog control was not delivered promptly: %v", err)
	}
	var dialog struct {
		T         string `json:"t"`
		DialogSeq uint32 `json:"dialogSeq"`
	}
	if json.Unmarshal(frame[1:], &dialog) != nil || dialog.T != "dialog" {
		t.Fatalf("wrong control: %s", frame)
	}
	if err := s.captureProbe(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("pending dialog triggered a screenshot")
	}
	s.mu.Lock()
	s.dispatchControl(message{T: "dialog", Seq: 1, SurfaceSeq: 1, DialogSeq: dialog.DialogSeq, Accept: true})
	s.mu.Unlock()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not resume after dialog answer")
	}
	recording.mu.Lock()
	defer recording.mu.Unlock()
	opened, answered := false, false
	for _, event := range recording.events {
		if event["type"] == "dialog" {
			if event["answered"] == nil {
				opened = true
			} else {
				answered = true
			}
		}
	}
	if !opened || !answered {
		t.Fatalf("dialog coverage markers missing: %+v", recording.events)
	}
}

func TestDialogOpeningCancelsInFlightProbeWithoutRecordingFailure(t *testing.T) {
	s, _, _ := supervisorFixture(t)
	mux, _, started := dialogCDP(t, s, true)
	result := make(chan error, 1)
	go func() { result <- s.captureProbe() }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	emitConfirm(t, mux)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("dialog cancellation treated as capture failure: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dialog did not cancel the screenshot probe")
	}
	if s.recordingFailed.Load() {
		t.Fatal("dialog marked recording failed")
	}
}

func TestNavigationInvalidatesAndReissuesOutstandingProbe(t *testing.T) {
	s, recording, _ := supervisorFixture(t)
	mux, calls, started := probeCDP(t, s, 1)
	result := make(chan error, 1)
	go func() { result <- s.captureProbe() }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	raw, _ := json.Marshal(cdpMessage{Method: "Page.frameNavigated", SessionID: "page", Params: json.RawMessage(`{"frame":{"url":"https://app.example/form-result"}}`)})
	if err := mux.Write(MuxCDP, raw); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("navigation treated as capture failure: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("probe was not immediately reissued after navigation")
	}
	if calls.Load() != 2 || s.recordingFailed.Load() {
		t.Fatal("fresh probe did not succeed")
	}
	recording.mu.Lock()
	defer recording.mu.Unlock()
	noted, captured := false, false
	for _, event := range recording.events {
		if event["type"] == "health" && event["probe"] == "invalidated" && event["reason"] == "navigation" {
			noted = true
		}
		if event["type"] == "frame" && event["probe"] == true {
			captured = true
		}
	}
	if !noted || !captured {
		t.Fatal("invalidation note or successful replacement probe missing")
	}
}

func TestStableTargetProbeTimeoutStillFailsRecording(t *testing.T) {
	s, recording, _ := supervisorFixture(t)
	probeCDP(t, s, -1)
	err := s.captureProbe()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stable probe timeout: %v", err)
	}
	s.recordingFailure(err)
	select {
	case <-recording.finished:
	case <-time.After(3 * time.Second):
		t.Fatal("stable capture failure did not end recording")
	}
	if !s.recordingFailed.Load() {
		t.Fatal("stable capture timeout was ignored")
	}
}

func TestRecordingFailedEndFlushesAndFinalizesIncomplete(t *testing.T) {
	prior := session.GetSessionRecordingDir()
	session.SetSessionRecordingPath(t.TempDir())
	t.Cleanup(func() { session.SetSessionRecordingPath(prior) })
	id := uuid.NewString()
	expiry := time.Now().Add(time.Minute)
	platform := newStrictPlatform(t, id, bytes.Repeat([]byte{31}, 32), expiry)
	oldURL := config.INFISICAL_URL
	config.INFISICAL_URL = platform.server.URL
	t.Cleanup(func() { config.INFISICAL_URL = oldURL })
	client := resty.New().SetTimeout(time.Second)
	cm := session.NewCredentialsManager(client)
	t.Cleanup(cm.Shutdown)
	credentials, err := cm.GetPAMSessionCredentials(id, expiry)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry("recording-failure-test", DefaultOptions(), client, cm)
	registry.Docker = &dockerSpy{}
	a := allocation{GatewayID: registry.GatewayID, AllocationGen: 1, HardExpiry: expiry, LeaseUntil: credentials.LeaseDeadline, CreatedAt: time.Now(), ContainerIDs: map[string]string{}, Volume: "test-volume"}
	supervisor := newSupervisor(registry, id, a, credentials)
	registry.sessions[id] = supervisor
	recording, err := session.NewWebRecording(id, expiry, cm, client)
	if err != nil {
		t.Fatal(err)
	}
	supervisor.recorder = recording
	go supervisor.reportLoop()
	if err := supervisor.lifecycle("provisioning", ""); err != nil {
		t.Fatal(err)
	}
	supervisor.recordingFailure(errors.New("injected capture timeout"))
	select {
	case <-supervisor.terminalDone:
	case <-time.After(15 * time.Second):
		t.Fatal("recording-failed End did not finalize")
	}
	<-supervisor.reportDone
	platform.mu.Lock()
	defer platform.mu.Unlock()
	if platform.manifestStatus != "incomplete" || platform.final == nil || !platform.final.RecordingFailed || !platform.final.TerminalEventIncluded || len(platform.chunks) == 0 {
		t.Fatalf("failed capture finalization: status=%s final=%+v chunks=%d", platform.manifestStatus, platform.final, len(platform.chunks))
	}
}
