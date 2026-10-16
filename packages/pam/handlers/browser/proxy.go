package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	startTimeout = 60 * time.Second
	inputTimeout = 2 * time.Second
	// The gateway closes the connection at expiry; this tells the viewer why just before.
	expiryNotice = 2 * time.Second
)

type BrowserProxyConfig struct {
	TargetURL             string
	StartPath             string
	AuthMethod            string
	Username              string
	Password              string
	Token                 string
	HeaderName            string
	HeaderValue           string
	TLSRejectUnauthorized bool
	TLSCaCertificate      string
	SessionID             string
	ExpiresAt             time.Time
	Engine                BrowserEngine // nil when no browser is installed
	OnActivity            func()        // viewer input only
	SessionLogger         session.SessionLogger
	SessionUploader       *session.SessionUploader
	PriorElapsedNs        uint64
}

type BrowserProxy struct {
	config BrowserProxyConfig
}

func NewBrowserProxy(config BrowserProxyConfig) *BrowserProxy {
	return &BrowserProxy{config: config}
}

// So a late reply to a dialog that's gone can't answer the next one.
type dialogTracker struct {
	next int64 // stream goroutine only
	open atomic.Int64
}

func (p *BrowserProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	defer clientConn.Close()

	l := log.With().Str("sessionID", p.config.SessionID).Logger()

	if p.config.Engine == nil {
		_ = writeJSON(clientConn, endMessage{Type: ServerEnd, Reason: EndError, Message: "This gateway can't run web app sessions"})
		return errors.New("web app session reached a gateway without a browser")
	}

	// No timeout: SSH channels ignore read deadlines.
	width, height, err := readInitialViewport(clientConn)
	if err != nil {
		return fmt.Errorf("failed to read the viewer's viewport: %w", err)
	}

	startCtx, cancelStart := context.WithTimeout(ctx, startTimeout)
	session, startURL, err := StartSession(startCtx, p.config.Engine, p.config, width, height)
	cancelStart()
	if err != nil {
		_ = writeJSON(clientConn, startFailure(err))
		return err
	}
	l.Info().Int("width", width).Int("height", height).Msg("Web app session started")

	// Before the stream starts, so it's the viewer's first message.
	if err := writeJSON(clientConn, readyMessage{Type: ServerReady, URL: startURL, Width: width, Height: height}); err != nil {
		session.Stop(endViewerDisconnected)
		return nil
	}
	rec := newRecorder(p.config)
	rec.start(startURL, width, height)

	stopOnCancel := context.AfterFunc(ctx, func() { session.Stop(EndTerminated) })
	defer stopOnCancel()
	if !p.config.ExpiresAt.IsZero() {
		expiry := time.AfterFunc(time.Until(p.config.ExpiresAt)-expiryNotice, func() { session.Stop(EndCompleted) })
		defer expiry.Stop()
	}

	var dialogs dialogTracker
	started := time.Now()
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		p.stream(clientConn, session, started, &dialogs, rec)
		// Unblocks the input loop however the session ended.
		clientConn.Close()
	}()

	reason := p.readInput(ctx, clientConn, session, &dialogs, rec, l)
	session.Stop(reason)
	<-streamDone
	rec.end(reason)
	return nil
}

// The connection's only writer once the session is ready.
func (p *BrowserProxy) stream(conn net.Conn, session Session, started time.Time, dialogs *dialogTracker, rec *recorder) {
	frames, events := session.Frames(), session.Events()
	var seq uint32
	sentEnd := false
	for frames != nil || events != nil {
		var err error
		select {
		case frame, ok := <-frames:
			if !ok {
				frames = nil
				continue
			}
			seq++
			err = WriteFrame(conn, FrameHeader{
				Seq:       seq,
				ElapsedMs: elapsedMs(started, frame.Timestamp),
				Width:     uint16(frame.Width),
				Height:    uint16(frame.Height),
			}, frame.JPEG)
			rec.frame(frame)
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			rec.event(event)
			var message any
			switch event.Type {
			case EventNavigation:
				message = urlMessage{Type: ServerURL, URL: event.URL, Title: event.Title}
			case EventCursor:
				message = cursorMessage{Type: ServerCursor, Cursor: event.Text}
			case EventDialog:
				dialogs.next++
				dialogs.open.Store(dialogs.next)
				message = dialogMessage{
					Type:          ServerDialog,
					ID:            dialogs.next,
					Kind:          event.DialogType,
					Message:       event.Text,
					DefaultPrompt: event.DefaultPrompt,
				}
			case EventBlockedRequest:
				message = blockedMessage{Type: ServerBlocked, URL: event.URL, Reason: blockedHostNotAllowed}
			case EventEnded:
				sentEnd = true
				message = endMessage{Type: ServerEnd, Reason: event.Text}
			default:
				continue
			}
			err = writeJSON(conn, message)
		}
		if err != nil {
			session.Stop(endViewerDisconnected)
			rec.end(endViewerDisconnected)
			return
		}
	}
	if !sentEnd {
		_ = writeJSON(conn, endMessage{Type: ServerEnd, Reason: endUnknown})
		rec.end(endUnknown)
	}
}

// Only input counts as activity: an animated page streams frames with nobody watching.
func (p *BrowserProxy) readInput(ctx context.Context, conn net.Conn, session Session, dialogs *dialogTracker, rec *recorder, l zerolog.Logger) string {
	for {
		messageType, payload, err := ReadMessage(conn, MaxClientMessageSize)
		if err != nil {
			return endViewerDisconnected
		}
		var message ClientMessage
		if messageType != MessageJSON || json.Unmarshal(payload, &message) != nil {
			continue
		}
		if p.config.OnActivity != nil {
			p.config.OnActivity()
		}
		switch message.Type {
		case ClientEnd:
			return EndUserQuit
		case ClientDialogReply:
			if message.DialogID == 0 || !dialogs.open.CompareAndSwap(message.DialogID, 0) {
				continue
			}
		}
		// Bounded, so a call stuck behind a dialog can't block reading the dialog reply.
		callCtx, cancel := context.WithTimeout(ctx, inputTimeout)
		// Before applying it, so the element is described as it was.
		recordInput(callCtx, session, rec, message)
		err = applyClientMessage(callCtx, session, message)
		cancel()
		if err != nil {
			l.Debug().Err(err).Str("type", message.Type).Msg("Failed to apply viewer input")
		}
	}
}

func applyClientMessage(ctx context.Context, session Session, message ClientMessage) error {
	switch message.Type {
	case ClientResize:
		width, height := clampViewport(message.Width, message.Height)
		return session.Resize(ctx, width, height)
	case ClientDialogReply:
		return session.HandleDialog(ctx, message.Accept, message.PromptText)
	case ClientMouse, ClientWheel, ClientKey, ClientText:
		return session.Input(ctx, message.input())
	}
	// Unknown types are skipped, so an older gateway tolerates a newer viewer.
	return nil
}

func recordInput(ctx context.Context, session Session, rec *recorder, message ClientMessage) {
	if rec == nil {
		return
	}
	switch message.Type {
	case ClientMouse:
		if message.Action != "down" {
			return
		}
		kind := "click"
		if message.Button == "right" {
			kind = "right_click"
		} else if message.ClickCount >= 2 {
			kind = "double_click"
		}
		element, _ := session.ElementAt(ctx, message.X, message.Y)
		rec.input(kind, &message.X, &message.Y, element.Label, "")
	case ClientWheel:
		rec.scroll(message.X, message.Y)
	case ClientKey, ClientText:
		if message.Type == ClientKey && message.Action != "down" {
			return
		}
		element, err := session.FocusedElement(ctx)
		rec.input(message.Type, nil, nil, element.Label, recordedText(message.Text, element, err == nil))
	}
}

func readInitialViewport(conn net.Conn) (int, int, error) {
	messageType, payload, err := ReadMessage(conn, MaxClientMessageSize)
	if err != nil {
		return 0, 0, err
	}
	var message ClientMessage
	if messageType == MessageJSON && json.Unmarshal(payload, &message) == nil && message.Type == ClientResize {
		width, height := clampViewport(message.Width, message.Height)
		return width, height, nil
	}
	return DefaultViewportWidth, DefaultViewportHeight, nil
}

func startFailure(err error) endMessage {
	switch {
	case errors.Is(err, ErrAtCapacity):
		return endMessage{Type: ServerEnd, Reason: EndCapacity}
	case errors.Is(err, ErrOpenFailed):
		return endMessage{Type: ServerEnd, Reason: EndError, Message: err.Error()}
	}
	return endMessage{Type: ServerEnd, Reason: EndError, Message: "The remote browser failed to start"}
}

func elapsedMs(started, at time.Time) uint32 {
	if elapsed := at.Sub(started); elapsed > 0 {
		return uint32(elapsed.Milliseconds())
	}
	return 0
}
