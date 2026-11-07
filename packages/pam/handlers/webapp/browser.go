package webapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/rs/zerolog/log"
	"image/jpeg"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"time"
)

func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return truncate(u.String(), 2048)
}
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Supervisor) surfacesMessage() map[string]any {
	list := make([]any, 0, len(s.surfaces))
	for _, seq := range slices.Sorted(maps.Keys(s.surfaces)) {
		v := s.surfaces[seq]
		if !v.ready {
			continue
		}
		list = append(list, map[string]any{"surfaceSeq": v.Seq, "url": safeURL(v.URL), "title": truncate(v.Title, 256)})
	}
	return map[string]any{"t": "surfaces", "active": s.active, "list": list}
}

func (s *Supervisor) startCapture(surface *surface) error {
	settings := surface.capture.Load()
	if settings == nil {
		settings = &captureSettings{quality: 60, width: 1920, height: 1200}
	}
	return s.call(surface.session, "Page.startScreencast", map[string]any{"format": "jpeg", "quality": settings.quality, "maxWidth": settings.width, "maxHeight": settings.height, "everyNthFrame": 1}, nil)
}

func (s *Supervisor) configureTarget(event cdpMessage) {
	var p struct {
		SessionID  string `json:"sessionId"`
		TargetInfo struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
			URL      string `json:"url"`
			Title    string `json:"title"`
			OpenerID string `json:"openerId"`
		} `json:"targetInfo"`
	}
	if json.Unmarshal(event.Params, &p) != nil {
		return
	}
	if p.TargetInfo.Type != "page" {
		_ = s.call(p.SessionID, "Runtime.runIfWaitingForDebugger", map[string]any{}, nil)
		return
	}
	s.mu.Lock()
	if len(s.surfaces) >= 16 {
		s.mu.Unlock()
		_ = s.call("", "Target.closeTarget", map[string]any{"targetId": p.TargetInfo.TargetID}, nil)
		return
	}
	s.nextSurface++
	v := &surface{Seq: s.nextSurface, URL: p.TargetInfo.URL, Title: p.TargetInfo.Title, target: p.TargetInfo.TargetID, session: p.SessionID, configured: make(chan struct{})}
	s.surfaces[v.Seq] = v
	width, height, dpr := s.width, s.height, s.dpr
	ready := s.ready
	s.mu.Unlock()
	defer close(v.configured)
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	calls := []struct {
		method string
		params any
	}{
		{"Page.enable", map[string]any{}},
		{"Runtime.enable", map[string]any{}},
		{"Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": height, "deviceScaleFactor": dpr, "mobile": false}},
	}
	if ready && s.credentials.AuthMethod == "basic-auth" {
		calls = append(calls, struct {
			method string
			params any
		}{"Fetch.enable", map[string]any{"patterns": []any{map[string]any{"urlPattern": "*"}}, "handleAuthRequests": true}})
	}
	calls = append(calls, struct {
		method string
		params any
	}{"Runtime.runIfWaitingForDebugger", map[string]any{}})
	var waits []func(any) error
	var configureErr error
	// CDP orders commands within the session; paused popups acknowledge configuration only after resume.
	for _, call := range calls {
		wait, err := s.cdp.begin(ctx, p.SessionID, call.method, call.params)
		if err != nil {
			configureErr = err
			break
		}
		waits = append(waits, wait)
	}
	if configureErr == nil {
		for _, wait := range waits {
			if err := wait(nil); err != nil {
				configureErr = err
				break
			}
		}
	}
	if configureErr != nil {
		if s.ctx.Err() != nil {
			return
		}
		log.Error().Err(configureErr).Msg("PAM browser popup configuration failed")
		_ = s.call("", "Target.closeTarget", map[string]any{"targetId": v.target}, nil)
		s.mu.Lock()
		delete(s.surfaces, v.Seq)
		_ = s.record(map[string]any{"type": "surface", "action": "closed", "surfaceSeq": v.Seq})
		_ = s.record(map[string]any{"type": "policy", "kind": "navigation", "detail": "popup-configuration-failed"})
		s.send(s.surfacesMessage())
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
	v.ready = true
	_ = s.record(map[string]any{"type": "surface", "action": "opened", "surfaceSeq": v.Seq})
	s.send(s.surfacesMessage())
	s.mu.Unlock()

}

func (s *Supervisor) browserEvents() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.cdp.done:
			s.queueReport("failed", "worker-lost")
			go s.End("worker-lost")
			return
		case event := <-s.cdp.events:
			s.cdp.queuedBytes.Add(-event.queuedBytes)
			switch event.Method {
			case "Target.attachedToTarget":
				go s.configureTarget(event)
			case "Page.screencastFrame":
				var p struct {
					Data      string `json:"data"`
					SessionID int    `json:"sessionId"`
					Metadata  struct {
						DeviceWidth  float64 `json:"deviceWidth"`
						DeviceHeight float64 `json:"deviceHeight"`
					} `json:"metadata"`
				}
				if json.Unmarshal(event.Params, &p) != nil {
					go s.End("recording-failed")
					continue
				}
				if err := s.storeScreencast(event.SessionID, p.Data, p.Metadata.DeviceWidth, p.Metadata.DeviceHeight, event.receivedAt); err != nil {
					go s.recordingFailure(err)
				}
				go s.call(event.SessionID, "Page.screencastFrameAck", map[string]any{"sessionId": p.SessionID}, nil)
			case "Fetch.requestPaused":
				var p struct {
					RequestID string `json:"requestId"`
				}
				if json.Unmarshal(event.Params, &p) == nil {
					go s.call(event.SessionID, "Fetch.continueRequest", map[string]any{"requestId": p.RequestID}, nil)
				}
			case "Fetch.authRequired":
				go s.answerAuth(event)
			case "Page.frameNavigated":
				var p struct {
					Frame struct {
						URL      string `json:"url"`
						ParentID string `json:"parentId"`
					} `json:"frame"`
				}
				if json.Unmarshal(event.Params, &p) != nil || p.Frame.ParentID != "" {
					continue
				}
				s.mu.Lock()
				for _, v := range s.surfaces {
					if v.session == event.SessionID {
						if v.Seq == s.active {
							s.invalidateProbeLocked("navigation")
						}
						v.URL = safeURL(p.Frame.URL)
						_ = s.record(map[string]any{"type": "nav", "surfaceSeq": v.Seq, "url": v.URL, "title": v.Title})
						s.send(map[string]any{"t": "nav", "surfaceSeq": v.Seq, "url": v.URL, "loading": false})
						s.send(s.surfacesMessage())
						if v.Seq == s.startSurface && s.ready && !s.appOpened && p.Frame.URL != "about:blank" {
							s.appOpened = true
							_ = s.lifecycle("app-opened", "")
							s.send(map[string]any{"t": "phase", "phase": "ready", "elapsedMs": time.Since(s.started).Milliseconds()})
							state := "detached"
							if s.controller != nil {
								state = "active"
							}
							go s.queueReport(state, "")
						}
						break
					}
				}
				s.mu.Unlock()
			case "Target.targetInfoChanged":
				var p struct {
					TargetInfo struct {
						TargetID string `json:"targetId"`
						URL      string `json:"url"`
						Title    string `json:"title"`
					} `json:"targetInfo"`
				}
				if json.Unmarshal(event.Params, &p) != nil {
					continue
				}
				s.mu.Lock()
				for _, v := range s.surfaces {
					if v.target == p.TargetInfo.TargetID {
						v.URL = safeURL(p.TargetInfo.URL)
						v.Title = truncate(p.TargetInfo.Title, 256)
					}
				}
				s.send(s.surfacesMessage())
				s.mu.Unlock()
			case "Target.detachedFromTarget":
				var p struct {
					SessionID string `json:"sessionId"`
				}
				if json.Unmarshal(event.Params, &p) != nil {
					continue
				}
				s.mu.Lock()
				activeClosed := false
				for seq, v := range s.surfaces {
					if v.session == p.SessionID {
						delete(s.surfaces, seq)
						_ = s.record(map[string]any{"type": "surface", "action": "closed", "surfaceSeq": seq})
						if s.active == seq {
							s.active = 0
							activeClosed = true
						}
					}
				}
				if activeClosed && !s.ending {
					for _, seq := range slices.Sorted(maps.Keys(s.surfaces)) {
						next := s.surfaces[seq]
						if !next.ready {
							continue
						}
						s.active = seq
						s.viewportGen++
						s.frameViewportGen = 0
						_ = s.call("", "Target.activateTarget", map[string]any{"targetId": next.target}, nil)
						_ = s.call(next.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": s.width, "height": s.height, "deviceScaleFactor": s.dpr, "mobile": false}, nil)
						_ = s.startCapture(next)
						_ = s.record(map[string]any{"type": "surface", "action": "activated", "surfaceSeq": seq})
						break
					}
					if s.active == 0 {
						go s.End("all-surfaces-closed")
					} else {
						s.invalidateProbeLocked("surface")
					}
				}
				s.send(s.surfacesMessage())
				s.mu.Unlock()
			case "Page.javascriptDialogOpening":
				var p struct {
					Type          string `json:"type"`
					Message       string `json:"message"`
					DefaultPrompt string `json:"defaultPrompt"`
				}
				if json.Unmarshal(event.Params, &p) != nil {
					continue
				}
				s.mu.Lock()
				for seq, v := range s.surfaces {
					if v.session == event.SessionID {
						s.dialogSeq++
						s.dialog = map[string]any{"t": "dialog", "dialogSeq": s.dialogSeq, "surfaceSeq": seq, "type": p.Type, "message": truncate(p.Message, 4096), "defaultPrompt": truncate(p.DefaultPrompt, 4096)}
						s.invalidateProbeLocked("dialog")
						_ = s.record(map[string]any{"type": "dialog", "dialogSeq": s.dialogSeq, "surfaceSeq": seq, "dialogType": p.Type, "message": truncate(p.Message, 4096), "defaultPrompt": truncate(p.DefaultPrompt, 4096)})
						s.send(s.dialog)
						log.Debug().Str("sessionId", s.id).Uint32("dialogSeq", s.dialogSeq).Uint32("surfaceSeq", seq).Msg("PAM browser dialog queued")
					}
				}
				s.mu.Unlock()
			}
		}
	}
}

func (s *Supervisor) answerAuth(event cdpMessage) {
	var p struct {
		RequestID     string `json:"requestId"`
		AuthChallenge struct {
			Source string `json:"source"`
			Origin string `json:"origin"`
		} `json:"authChallenge"`
	}
	if json.Unmarshal(event.Params, &p) != nil {
		return
	}
	response := map[string]any{"response": "CancelAuth"}
	origin, err := url.Parse(p.AuthChallenge.Origin)
	if err == nil && s.credentials.AuthMethod == "basic-auth" && p.AuthChallenge.Source == "Server" && canonicalOrigin(origin) == s.credentials.WebConnection.StartOrigin {
		response = map[string]any{"response": "ProvideCredentials", "username": s.credentials.Username, "password": s.credentials.Password}
	}
	_ = s.call(event.SessionID, "Fetch.continueWithAuth", map[string]any{"requestId": p.RequestID, "authChallengeResponse": response}, nil)
}

func canonicalOrigin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else if u.Scheme == "http" {
			port = "80"
		}
	}
	return u.Scheme + "://" + u.Hostname() + ":" + port
}

func (s *Supervisor) captureProbe() error {
	if !s.probeMu.TryLock() {
		return nil
	}
	defer s.probeMu.Unlock()
	for {
		s.mu.Lock()
		if s.ending || s.dialog != nil {
			s.mu.Unlock()
			return nil
		}
		v := s.surfaces[s.active]
		if v == nil {
			s.mu.Unlock()
			return errors.New("no active capture surface")
		}
		width, height, dpr := s.width, s.height, s.dpr
		viewport := s.viewportGen
		settings := &captureSettings{quality: 60, width: 1920, height: 1200}
		if v.capture.Load() != nil {
			settings = v.capture.Load()
		}
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		s.probeCancel = cancel
		s.mu.Unlock()
		var result struct {
			Data string `json:"data"`
		}
		err := s.cdp.call(ctx, v.session, "Page.captureScreenshot", map[string]any{"format": "jpeg", "quality": settings.quality, "captureBeyondViewport": false, "clip": map[string]any{"x": 0, "y": 0, "width": width, "height": height, "scale": min(1.0, float64(settings.width)/(float64(width)*max(1, dpr)), float64(settings.height)/(float64(height)*max(1, dpr)))}}, &result)
		cancel()
		s.mu.Lock()
		invalidated := s.probeInvalidated != ""
		s.probeInvalidated = ""
		s.probeCancel = nil
		healthyAt := s.lastFrame
		if healthyAt.IsZero() {
			healthyAt = s.started
		}
		starved := s.probeInvalidations >= 3 && time.Since(healthyAt) >= 30*time.Second
		ending := s.ending
		s.mu.Unlock()
		if ending {
			return nil
		}
		if invalidated {
			if starved {
				return errors.New("capture probe repeatedly invalidated without capture progress")
			}
			continue
		}
		if err != nil {
			return err
		}
		return s.storeCapturedFrame(v.session, result.Data, true, time.Now(), viewport)
	}
}

func (s *Supervisor) invalidateProbeLocked(reason string) {
	if s.probeCancel == nil || s.probeInvalidated != "" {
		return
	}
	s.probeInvalidated = reason
	s.probeInvalidations++
	_ = s.record(map[string]any{"type": "health", "recording": "ok", "egress": "ok", "probe": "invalidated", "reason": reason})
	s.probeCancel()
}

func (s *Supervisor) storeScreencast(target, data string, width, height float64, received time.Time) error {
	s.mu.Lock()
	viewport := s.viewportGen
	valid := !received.Before(s.metricsReadyAt) && width == float64(s.width) && height == float64(s.height)
	if !valid {
		s.droppedCapture++
	}
	s.mu.Unlock()
	if !valid {
		return nil
	}
	return s.storeCapturedFrame(target, data, false, received, viewport)
}

type deferredFrame struct {
	target, data string
	viewport     uint32
	captured     time.Time
}

func (s *Supervisor) storeFrame(target, data string, probe bool) error {
	return s.storeCapturedFrame(target, data, probe, time.Now(), 0)
}

func (s *Supervisor) flushDeferredFrame() {
	s.mu.Lock()
	frame := s.pendingFrame
	s.pendingFrame, s.frameTimer = nil, nil
	valid := frame != nil && frame.viewport == s.viewportGen && !s.ending
	s.mu.Unlock()
	if valid {
		if err := s.storeCapturedFrame(frame.target, frame.data, false, frame.captured, frame.viewport); err != nil {
			s.recordingFailure(err)
		}
	}
}

func (s *Supervisor) storeCapturedFrame(target, data string, probe bool, captured time.Time, expectedViewport uint32) error {
	if len(data) > 16<<20 {
		return errors.New("capture image too large")
	}
	jpegBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return errors.New("invalid capture image")
	}
	config, err := jpeg.DecodeConfig(bytes.NewReader(jpegBytes))
	if err != nil || config.Width > 1920 || config.Height > 1200 {
		return errors.New("capture exceeds fidelity bounds")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.surfaces[s.active]
	if v == nil || v.session != target || s.ending || expectedViewport != 0 && expectedViewport != s.viewportGen {
		return nil
	}
	if !probe && time.Since(s.lastFrame) < time.Second/8 {
		if s.pendingFrame != nil {
			s.droppedCapture++
		}
		s.pendingFrame = &deferredFrame{target: target, data: data, viewport: s.viewportGen, captured: captured}
		if s.frameTimer == nil {
			s.frameTimer = time.AfterFunc(time.Second/8-time.Since(s.lastFrame), s.flushDeferredFrame)
		}
		return nil
	}
	if s.pendingFrame != nil {
		s.pendingFrame = nil
		s.droppedCapture++
	}
	if len(jpegBytes) > maxFrameJPEGBytes {
		sourceWidth, sourceHeight := config.Width, config.Height
		var quality int
		jpegBytes, config.Width, config.Height, quality, err = fitFrameJPEG(jpegBytes)
		if err != nil {
			return err
		}
		data = base64.StdEncoding.EncodeToString(jpegBytes)
		v.capture.Store(&captureSettings{quality: quality, width: config.Width, height: config.Height})
		if err := s.record(map[string]any{"type": "health", "recording": "ok", "egress": "ok", "detail": "frame re-encoded for recording event limit", "surfaceSeq": v.Seq, "sourceWidth": sourceWidth, "sourceHeight": sourceHeight, "width": config.Width, "height": config.Height, "jpegQuality": quality}); err != nil {
			return err
		}
		go s.applyCaptureSettings(v)
	}
	captureElapsed := captured.Sub(s.started).Microseconds()
	s.frameSeq++
	if err := s.record(map[string]any{"type": "frame", "surfaceSeq": s.active, "frameSeq": s.frameSeq, "width": config.Width, "height": config.Height, "viewportGen": s.viewportGen, "controllerGen": s.controllerGen, "captureElapsedUs": captureElapsed, "probe": probe, "jpeg": data}); err != nil {
		return err
	}
	s.lastFrame = time.Now()
	s.probeInvalidations = 0
	b := make([]byte, 29+len(jpegBytes))
	b[0] = Frame
	binary.BigEndian.PutUint32(b[1:], s.active)
	binary.BigEndian.PutUint32(b[5:], s.frameSeq)
	binary.BigEndian.PutUint16(b[9:], uint16(config.Width))
	binary.BigEndian.PutUint16(b[11:], uint16(config.Height))
	binary.BigEndian.PutUint32(b[13:], s.viewportGen)
	binary.BigEndian.PutUint32(b[17:], s.controllerGen)
	binary.BigEndian.PutUint64(b[21:], uint64(captureElapsed))
	copy(b[29:], jpegBytes)
	s.frameViewportGen = s.viewportGen
	s.lastLiveFrame = b
	if s.controller != nil {
		s.controller.enqueue(b, true)
	}
	return nil
}

func (s *Supervisor) connectorEvents() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.connector.cdp.done:
			if s.ctx.Err() == nil {
				s.queueReport("failed", "connector-lost")
				go s.End("connector-lost")
			}
			return
		case b := <-s.connector.cdp.controls:
			var p struct {
				C, Host, Reason string
				Port            int
			}
			if json.Unmarshal(b, &p) != nil {
				go s.End("connector-failed")
				return
			}
			switch p.C {
			case "stopped":
				close(s.connectorStopped)
				return
			case "deny":
				s.mu.Lock()
				_ = s.record(map[string]any{"type": "policy", "kind": "egress", "host": p.Host, "port": p.Port, "detail": p.Reason})
				s.send(map[string]any{"t": "policy_denied", "kind": "egress", "host": p.Host, "port": p.Port, "detail": p.Reason})
				s.mu.Unlock()
			}
		}
	}
}

func urlPort(u *url.URL) int {
	if u.Port() != "" {
		n, _ := strconv.Atoi(u.Port())
		return n
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}
