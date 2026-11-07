package webapp

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/time/rate"
)

type message struct {
	T           string  `json:"t,omitempty"`
	Seq         uint32  `json:"seq"`
	SurfaceSeq  uint32  `json:"surfaceSeq"`
	ViewportGen uint32  `json:"viewportGen"`
	Kind        string  `json:"kind,omitempty"`
	Action      string  `json:"action,omitempty"`
	X           int     `json:"x"`
	Y           int     `json:"y"`
	Button      string  `json:"button,omitempty"`
	Buttons     int     `json:"buttons"`
	Modifiers   int     `json:"modifiers"`
	ClickCount  int     `json:"clickCount"`
	DeltaX      int     `json:"deltaX"`
	DeltaY      int     `json:"deltaY"`
	Key         string  `json:"key,omitempty"`
	Code        string  `json:"code,omitempty"`
	Text        string  `json:"text,omitempty"`
	Source      string  `json:"source,omitempty"`
	URL         string  `json:"url,omitempty"`
	Width       int     `json:"width"`
	Height      int     `json:"height"`
	DPR         float64 `json:"dpr"`
	DialogSeq   uint32  `json:"dialogSeq"`
	Accept      bool    `json:"accept"`
	PromptText  string  `json:"promptText,omitempty"`
}

func (s *Supervisor) protocolError(v *liveStream, detail string) {
	v.quiesced.Store(true)
	s.mu.Lock()
	_ = s.record(map[string]any{"type": "protocol-violation", "detail": detail})
	s.mu.Unlock()
	v.send(map[string]string{"t": "error", "code": "protocol", "message": detail})
}

func (m message) validate(input bool) error {
	if m.T == "ping" && !input {
		return nil
	}
	if m.Seq == 0 {
		return errors.New("sequence required")
	}
	if !input {
		switch m.T {
		case "navigate":
			if m.Action != "url" && m.Action != "back" && m.Action != "forward" && m.Action != "reload" && m.Action != "home" {
				return errors.New("invalid navigation")
			}
			if len(m.URL) > 2048 {
				return errors.New("URL too long")
			}
		case "surface":
			if m.Action != "activate" && m.Action != "close" && m.Action != "new" {
				return errors.New("invalid surface action")
			}
		case "viewport":
			if m.Width < 320 || m.Width > 3840 || m.Height < 240 || m.Height > 2400 || m.DPR < 1 || m.DPR > 3 {
				return errors.New("invalid viewport")
			}
		case "dialog":
			if len(m.PromptText) > 4096 {
				return errors.New("prompt too long")
			}
		case "end":
		default:
			return errors.New("invalid control")
		}
		return nil
	}
	if m.SurfaceSeq == 0 || m.ViewportGen == 0 || m.Modifiers < 0 || m.Modifiers > 15 || m.X < 0 || m.Y < 0 || m.X > 3840 || m.Y > 2400 {
		return errors.New("invalid input coordinates or generation")
	}
	switch m.Kind {
	case "mouse":
		if m.Action != "move" && m.Action != "down" && m.Action != "up" {
			return errors.New("invalid mouse action")
		}
		if m.Button != "left" && m.Button != "right" && m.Button != "middle" && m.Button != "none" {
			return errors.New("invalid button")
		}
		if m.Buttons < 0 || m.Buttons > 7 || m.ClickCount < 0 || m.ClickCount > 3 {
			return errors.New("invalid mouse state")
		}
	case "wheel":
		if m.DeltaX < -100000 || m.DeltaX > 100000 || m.DeltaY < -100000 || m.DeltaY > 100000 {
			return errors.New("invalid wheel delta")
		}
	case "key":
		if (m.Action != "down" && m.Action != "up") || len(m.Key) > 32 || len(m.Code) > 32 || len(m.Text) > 8 {
			return errors.New("invalid key")
		}
	case "text":
		if len(m.Text) > 64<<10 || (m.Source != "ime" && m.Source != "type") {
			return errors.New("invalid text")
		}
	default:
		return errors.New("invalid input kind")
	}
	return nil
}

func (s *Supervisor) Attach(conn net.Conn, reader io.Reader, attach Attach) error {
	v := newStream(conn, reader, attach.ControllerGen)
	defer v.flushClose()
	s.mu.Lock()
	if s.ending || attach.ControllerGen < s.highestGen {
		s.mu.Unlock()
		return errors.New("stale controller or ended session")
	}
	if attach.ControllerGen > s.highestGen {
		s.highestGen = attach.ControllerGen
	}
	if s.controller != nil {
		if !attach.TakeControl || attach.ControllerGen <= s.controller.gen {
			s.mu.Unlock()
			return v.waitBusy(60 * time.Second)
		}
		old := s.controller
		s.droppedLive += old.droppedFrames()
		s.releaseHeld()
		old.send(map[string]string{"t": "controller_lost", "reason": "taken"})
		old.mu.Lock()
		old.closeAfterWrite = true
		old.mu.Unlock()
		_ = s.record(map[string]any{"type": "controller", "controllerGen": attach.ControllerGen, "action": "taken", "actorId": attach.Actor.ID})
	}
	s.controller = v
	s.controllerGen = v.gen
	if s.grace != nil {
		s.grace.Stop()
		s.grace = nil
	}
	v.send(map[string]any{"t": "attached", "v": 1, "controllerGen": v.gen, "allocationGen": s.alloc.AllocationGen, "capabilities": map[string]any{"typedNavigation": s.credentials.WebConnection.AllowTypedNavigation}, "deadline": map[string]any{"expiresAt": s.credentials.ExpiresAt, "leaseUntil": s.credentials.LeaseUntil, "reconnectGraceSeconds": s.credentials.WebPolicy.ReconnectGraceSeconds}})
	if s.recorder != nil {
		_ = s.record(map[string]any{"type": "controller", "controllerGen": v.gen, "action": "attached", "actorId": attach.Actor.ID})
		_ = s.lifecycle("reattached", "")
	}
	v.send(s.surfacesMessage())
	if s.dialog != nil {
		v.send(s.dialog)
	}
	ready := s.ready
	if s.appOpened {
		go s.queueReport("active", "")
	}
	s.mu.Unlock()
	if ready {
		go func() {
			if err := s.captureProbe(); err != nil {
				s.recordingFailure(err)
			}
		}()
	}
	defer func() {
		s.mu.Lock()
		if s.controller == v {
			s.droppedLive += v.droppedFrames()
			s.releaseHeld()
			s.controller = nil
			if !s.ending {
				_ = s.record(map[string]any{"type": "controller", "controllerGen": v.gen, "action": "detached", "actorId": attach.Actor.ID})
				_ = s.lifecycle("detached", "")
				grace := time.Duration(s.credentials.WebPolicy.ReconnectGraceSeconds) * time.Second
				s.grace = time.AfterFunc(grace, func() {
					s.mu.Lock()
					detached := s.controller == nil
					s.mu.Unlock()
					if detached {
						s.End("reconnect-expired")
					}
				})
				go s.queueReport("detached", "")
			}
		}
		s.mu.Unlock()
	}()
	inputRate := rate.NewLimiter(240, 600)
	controlRate := rate.NewLimiter(30, 30)
	for {
		b, err := ReadFrame(reader, FromPlatform, true)
		if err != nil {
			err = v.readError(err)
			v.quiesced.Store(true)
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.mu.Lock()
				_ = s.record(map[string]any{"type": "protocol-violation", "detail": "invalid viewer frame"})
				s.mu.Unlock()
				v.send(map[string]string{"t": "error", "code": "protocol", "message": "invalid frame"})
			}
			return err
		}
		var m message
		if json.Unmarshal(b[1:], &m) != nil || m.validate(b[0] == Input) != nil {
			s.protocolError(v, "invalid input or control fields")
			return errors.New("protocol: invalid message")
		}
		if b[0] == Input && !inputRate.Allow() || b[0] == Control && !controlRate.Allow() {
			s.protocolError(v, "message rate exceeded")
			return errors.New("protocol: rate exceeded")
		}
		if m.T == "ping" {
			v.send(map[string]string{"t": "pong"})
			continue
		}
		s.mu.Lock()
		if m.Seq <= v.seq {
			s.droppedInputs++
			s.mu.Unlock()
			continue
		}
		v.seq = m.Seq
		s.mu.Unlock()
		select {
		case s.actions <- queuedAction{stream: v, message: m, input: b[0] == Input}:
		case <-v.done:
			return nil
		case <-s.ended:
			return nil
		default:
			s.mu.Lock()
			s.droppedInputs++
			s.mu.Unlock()
		}
	}
}

func (v *liveStream) waitBusy(timeout time.Duration) error {
	v.send(map[string]string{"t": "controller_busy"})
	_ = v.conn.SetReadDeadline(time.Now().Add(timeout))
	timer := time.AfterFunc(timeout, func() {
		v.mu.Lock()
		if v.closeErr == nil {
			v.closeErr = errors.New("busy")
		}
		v.mu.Unlock()
		v.close()
	})
	defer timer.Stop()
	for {
		if _, err := ReadFrame(v.reader, FromPlatform, true); err != nil {
			v.send(map[string]string{"t": "error", "code": "busy", "message": "controller is still in use"})
			return v.readError(err)
		}
	}
}

func (s *Supervisor) releaseHeld() {
	if s.cdp == nil {
		return
	}
	for _, m := range s.heldKeys {
		m.Action = "up"
		m.Text = ""
		s.dispatchInput(m, true)
	}
	for _, m := range s.heldButtons {
		m.Action = "up"
		m.Buttons = 0
		s.dispatchInput(m, true)
	}
	clear(s.heldKeys)
	clear(s.heldButtons)
}

func (s *Supervisor) dispatchLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case a := <-s.actions:
			s.mu.Lock()
			m := a.message
			if s.ending || !s.ready || a.stream.quiesced.Load() || s.controller != a.stream || a.stream.gen != s.controller.gen {
				s.droppedInputs++
				s.mu.Unlock()
				continue
			}
			select {
			case <-a.stream.done:
				s.droppedInputs++
				s.mu.Unlock()
				continue
			default:
			}
			if a.input {
				if m.SurfaceSeq != s.active || m.ViewportGen != s.viewportGen || s.frameViewportGen != s.viewportGen || m.X >= s.width || m.Y >= s.height {
					s.droppedInputs++
					s.mu.Unlock()
					continue
				}
				if m.Kind == "mouse" && m.Action == "move" && time.Since(s.lastMove) < time.Second/60 {
					s.droppedMoves++
					s.mu.Unlock()
					continue
				}
				if m.Kind == "mouse" && m.Action == "move" {
					s.lastMove = time.Now()
				}
				s.dispatchInput(m, false)
				s.lastInput = m.Seq
			} else {
				if m.T == "navigate" && m.SurfaceSeq != s.active {
					s.droppedInputs++
					s.mu.Unlock()
					continue
				}
				if m.T == "end" {
					_ = s.record(map[string]any{"type": "action", "seq": m.Seq, "controllerGen": s.controller.gen, "t": "end"})
					s.mu.Unlock()
					s.End("user-ended")
					return
				}
				s.dispatchControl(m)
			}
			s.mu.Unlock()
		}
	}
}

func (s *Supervisor) dispatchInput(m message, release bool) {
	v := s.surfaces[m.SurfaceSeq]
	if v == nil {
		return
	}
	var method string
	var params any
	switch m.Kind {
	case "mouse":
		kind := map[string]string{"move": "mouseMoved", "down": "mousePressed", "up": "mouseReleased"}[m.Action]
		method = "Input.dispatchMouseEvent"
		params = map[string]any{"type": kind, "x": m.X, "y": m.Y, "button": m.Button, "buttons": m.Buttons, "modifiers": m.Modifiers, "clickCount": m.ClickCount}
	case "wheel":
		method = "Input.dispatchMouseEvent"
		params = map[string]any{"type": "mouseWheel", "x": m.X, "y": m.Y, "deltaX": m.DeltaX, "deltaY": m.DeltaY, "modifiers": m.Modifiers}
	case "key":
		method = "Input.dispatchKeyEvent"
		params, m.Text = keyEventParams(m)
	case "text":
		method = "Input.insertText"
		params = map[string]any{"text": m.Text}
	}
	err := s.call(v.session, method, params, nil)
	recorded := map[string]any{"type": "input", "seq": m.Seq, "controllerGen": s.controllerGen, "surfaceSeq": m.SurfaceSeq, "viewportGen": m.ViewportGen, "kind": m.Kind}
	switch m.Kind {
	case "mouse":
		recorded["action"] = m.Action
		recorded["x"] = m.X
		recorded["y"] = m.Y
		recorded["button"] = m.Button
		recorded["buttons"] = m.Buttons
		recorded["modifiers"] = m.Modifiers
		recorded["clickCount"] = m.ClickCount
	case "wheel":
		recorded["x"] = m.X
		recorded["y"] = m.Y
		recorded["deltaX"] = m.DeltaX
		recorded["deltaY"] = m.DeltaY
		recorded["modifiers"] = m.Modifiers
	case "key":
		recorded["action"] = m.Action
		recorded["key"] = m.Key
		recorded["code"] = m.Code
		recorded["modifiers"] = m.Modifiers
		if m.Text != "" {
			recorded["text"] = m.Text
		}
	case "text":
		recorded["text"] = m.Text
		recorded["source"] = m.Source
	}
	if err != nil {
		recorded["error"] = true
	}
	_ = s.record(recorded)
	if release {
		return
	}
	if m.Kind == "key" {
		if m.Action == "up" {
			delete(s.heldKeys, m.Code)
		} else {
			s.heldKeys[m.Code] = m
		}
	}
	if m.Kind == "mouse" && m.Button != "none" {
		if m.Action == "up" {
			delete(s.heldButtons, m.Button)
		} else if m.Action == "down" {
			s.heldButtons[m.Button] = m
		}
	}
}

func (s *Supervisor) dispatchControl(m message) {
	v := s.surfaces[s.active]
	if m.T == "dialog" {
		if s.dialog == nil || m.DialogSeq != s.dialogSeq || s.dialog["surfaceSeq"] != m.SurfaceSeq {
			return
		}
		v = s.surfaces[m.SurfaceSeq]
	}
	if v == nil {
		return
	}
	var err error
	switch m.T {
	case "navigate":
		switch m.Action {
		case "reload":
			err = s.call(v.session, "Page.reload", map[string]any{}, nil)
		case "back", "forward":
			var history struct {
				Current int `json:"currentIndex"`
				Entries []struct {
					ID int `json:"id"`
				} `json:"entries"`
			}
			err = s.call(v.session, "Page.getNavigationHistory", map[string]any{}, &history)
			index := history.Current - 1
			if m.Action == "forward" {
				index = history.Current + 1
			}
			if err == nil && index >= 0 && index < len(history.Entries) {
				err = s.call(v.session, "Page.navigateToHistoryEntry", map[string]any{"entryId": history.Entries[index].ID}, nil)
			}
		case "home":
			err = s.call(v.session, "Page.navigate", map[string]any{"url": s.credentials.WebConnection.StartURL}, nil)
		case "url":
			u, parseErr := url.Parse(m.URL)
			allowed := false
			if parseErr == nil && u.User == nil && (u.Scheme == "http" || u.Scheme == "https") {
				host, hostErr := normalizeHost(u.Hostname())
				if hostErr == nil {
					for _, e := range s.credentials.WebConnection.AllowedDestinations {
						if e.Scheme == u.Scheme && e.Port == urlPort(u) && hostMatches(strings.ToLower(e.Host), host) {
							allowed = true
							break
						}
					}
				}
			}
			if !s.credentials.WebConnection.AllowTypedNavigation || !allowed {
				_ = s.record(map[string]any{"type": "policy", "kind": "navigation", "detail": "navigation not permitted"})
				s.send(map[string]any{"t": "policy_denied", "kind": "navigation", "detail": "navigation not permitted"})
				return
			}
			err = s.call(v.session, "Page.navigate", map[string]any{"url": m.URL}, nil)
		}
	case "viewport":
		err = s.call(v.session, "Page.stopScreencast", map[string]any{}, nil)
		if err == nil {
			err = s.call(v.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": m.Width, "height": m.Height, "deviceScaleFactor": m.DPR, "mobile": false}, nil)
		}
		if err == nil {
			s.width = m.Width
			s.height = m.Height
			s.dpr = m.DPR
			s.viewportGen++
			s.invalidateProbeLocked("viewport")
			s.metricsReadyAt = time.Now()
			s.frameViewportGen = 0
			err = s.startCapture(v)
			s.send(map[string]any{"t": "viewport_ack", "seq": m.Seq, "viewportGen": s.viewportGen})
			go func() {
				if err := s.captureProbe(); err != nil {
					s.recordingFailure(err)
				}
			}()
		}
	case "surface":
		if m.Action == "new" {
			if len(s.surfaces) >= 16 {
				return
			}
			err = s.call("", "Target.createTarget", map[string]any{"url": s.credentials.WebConnection.StartURL}, nil)
		} else {
			next := s.surfaces[m.SurfaceSeq]
			if next == nil || !next.ready {
				return
			}
			if m.Action == "close" {
				err = s.call("", "Target.closeTarget", map[string]any{"targetId": next.target}, nil)
			} else {
				_ = s.call(v.session, "Page.stopScreencast", map[string]any{}, nil)
				s.active = next.Seq
				s.viewportGen++
				s.invalidateProbeLocked("surface")
				s.frameViewportGen = 0
				err = s.call("", "Target.activateTarget", map[string]any{"targetId": next.target}, nil)
				if err == nil {
					err = s.call(next.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": s.width, "height": s.height, "deviceScaleFactor": s.dpr, "mobile": false}, nil)
					if err == nil {
						s.metricsReadyAt = time.Now()
					}
				}
				if err == nil {
					err = s.startCapture(next)
				}
				_ = s.record(map[string]any{"type": "surface", "action": "activated", "surfaceSeq": next.Seq})
				s.send(s.surfacesMessage())
			}
		}
	case "dialog":
		if s.dialog == nil || m.DialogSeq != s.dialogSeq {
			return
		}
		err = s.call(v.session, "Page.handleJavaScriptDialog", map[string]any{"accept": m.Accept, "promptText": m.PromptText}, nil)
		if err == nil {
			_ = s.record(map[string]any{"type": "dialog", "dialogSeq": m.DialogSeq, "surfaceSeq": m.SurfaceSeq, "dialogType": s.dialog["type"], "message": s.dialog["message"], "defaultPrompt": s.dialog["defaultPrompt"], "answered": map[string]any{"accept": m.Accept, "promptLen": utf8.RuneCountInString(m.PromptText)}})
			s.dialog = nil
			go func() {
				if err := s.captureProbe(); err != nil {
					s.recordingFailure(err)
				}
			}()
		}
	}
	event := map[string]any{"type": "action", "seq": m.Seq, "controllerGen": s.controller.gen, "t": m.T, "surfaceSeq": m.SurfaceSeq, "actionName": m.Action}
	if m.T == "navigate" {
		event["urlOriginPath"] = safeURL(m.URL)
	}
	if m.T == "dialog" {
		event["dialogSeq"] = m.DialogSeq
		event["accept"] = m.Accept
		event["promptText"] = m.PromptText
	}
	if m.T == "viewport" {
		event["width"] = m.Width
		event["height"] = m.Height
	}
	if err != nil {
		event["error"] = true
	}
	_ = s.record(event)
}
