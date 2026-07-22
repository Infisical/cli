package gatewayv2

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// inputMessage is one client -> gateway input event, sent as newline-delimited JSON
// over the tunnel. WebSocket message boundaries are not preserved across the raw
// byte tunnel, so the newline is our framing.
type inputMessage struct {
	T  string  `json:"t"` // "m" = mouse (keyboard added later)
	E  string  `json:"e"` // "down" | "up" | "move" | "wheel"
	X  float64 `json:"x"` // CSS-pixel coords in the streamed frame's space
	Y  float64 `json:"y"`
	B  int     `json:"b"`  // mouse button: 0 left, 1 middle, 2 right
	DX float64 `json:"dx"` // wheel delta
	DY float64 `json:"dy"`
}

// dispatchInput replays a single client input event into the headless Chromium via CDP.
func dispatchInput(ctx context.Context, msg inputMessage) {
	if msg.T != "m" {
		return
	}
	// Log discrete actions (clicks/scroll); skip high-frequency moves to avoid spam.
	if msg.E != "move" {
		log.Info().
			Str("event", msg.E).
			Int("button", msg.B).
			Float64("x", msg.X).
			Float64("y", msg.Y).
			Msg("web-app: client input")
	}

	var typ input.MouseType
	switch msg.E {
	case "down":
		typ = input.MousePressed
	case "up":
		typ = input.MouseReleased
	case "move":
		typ = input.MouseMoved
	case "wheel":
		typ = input.MouseWheel
	default:
		return
	}

	p := input.DispatchMouseEvent(typ, msg.X, msg.Y)
	if msg.E == "wheel" {
		p = p.WithButton(input.None).WithDeltaX(msg.DX).WithDeltaY(msg.DY)
	} else {
		btn := input.Left
		switch msg.B {
		case 1:
			btn = input.Middle
		case 2:
			btn = input.Right
		}
		if msg.E == "move" {
			btn = input.None
		}
		p = p.WithButton(btn)
		if msg.E == "down" || msg.E == "up" {
			p = p.WithClickCount(1)
		}
	}
	// Best-effort: input is fire-and-forget; a dropped event shouldn't tear down the session.
	_ = chromedp.Run(ctx, p)
}

// handleWebAppProxy launches a headless Chromium, navigates it to the target web
// application, and streams the page as JPEG frames over conn. Each frame is
// length-prefixed (4-byte big-endian length + JPEG bytes) so the client can
// reassemble frame boundaries from the raw byte tunnel. Client input flows the
// other way as newline-delimited JSON and is replayed into Chromium via CDP.
func handleWebAppProxy(gctx context.Context, conn net.Conn, targetHost string, targetPort int, pamConfig *pam.GatewayPAMConfig) error {
	url := fmt.Sprintf("http://%s:%d", targetHost, targetPort)
	log.Info().Str("url", url).Msg("web-app: launching headless Chromium")

	sessionID := ""
	if pamConfig != nil {
		sessionID = pamConfig.SessionId
	}

	// Tamper-proof recording is best-effort: a recording failure must never break
	// the live session.
	var recorder *webAppRecorder
	if sessionID != "" {
		r, err := newWebAppRecorder(pamConfig)
		if err != nil {
			log.Warn().Err(err).Str("sessionId", sessionID).Msg("web-app: recording disabled")
		} else {
			recorder = r
			defer recorder.close()
			log.Info().Str("sessionId", sessionID).Msg("web-app: recording enabled")
		}
	}

	// loopCtx tears the whole handler down on client disconnect. Without it, a
	// static page (one frame then silence) would block the stream loop on
	// <-frameCh forever after the client leaves, leaking a headless Chrome per
	// connect. The egress proxy and Chromium both stop when it is cancelled.
	loopCtx, loopCancel := context.WithCancel(gctx)
	defer loopCancel()

	// Egress wall (Wall #2): route the browser through a per-session proxy that
	// only permits the one authorized target host:port. Fail closed — a headless
	// browser with no egress containment must never launch.
	proxyAddr, err := startEgressProxy(loopCtx, sessionID, targetHost, targetPort)
	if err != nil {
		return fmt.Errorf("start egress wall: %w", err)
	}

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ProxyServer(proxyAddr),
		// Override Chromium's implicit loopback bypass so even localhost/127.0.0.1
		// requests go through (and are filtered by) the wall.
		chromedp.Flag("proxy-bypass-list", "<-loopback>"),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(gctx, allocOpts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Read client input (and detect disconnect). A static page produces no new
	// frames, so the read hitting EOF is the only reliable disconnect signal.
	go func() {
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 1 {
				var msg inputMessage
				if json.Unmarshal(line, &msg) == nil {
					dispatchInput(ctx, msg)
				}
			}
			if err != nil {
				break
			}
		}
		loopCancel()
	}()

	// Recording runs on its own buffered channel + goroutine so capturing every
	// frame isn't limited by (and can't stall on) how fast the live client reads.
	var recordCh chan recFrame
	if recorder != nil {
		recordCh = make(chan recFrame, 256)
		go func() {
			for {
				select {
				case <-loopCtx.Done():
					return
				case rf := <-recordCh:
					recorder.record(rf.data, rf.at)
				}
			}
		}()
	}

	frameCh := make(chan []byte, 8)

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		f, ok := ev.(*page.EventScreencastFrame)
		if !ok {
			return
		}
		// Ack asynchronously (never block the CDP event loop) so Chrome keeps streaming.
		go func(sid int64) { _ = chromedp.Run(ctx, page.ScreencastFrameAck(sid)) }(f.SessionID)
		data, err := base64.StdEncoding.DecodeString(f.Data)
		if err != nil {
			return
		}
		at := time.Now()
		// To the live client: skip a frame if the client is behind (backpressure).
		select {
		case frameCh <- data:
		default:
		}
		// To the recorder, stamped at capture time. Its own buffer keeps recording
		// fidelity independent of client speed; drop only if truly overwhelmed.
		if recordCh != nil {
			select {
			case recordCh <- recFrame{data: data, at: at}:
			default:
			}
		}
	})

	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		page.StartScreencast().
			WithFormat(page.ScreencastFormatJpeg).
			WithQuality(60).
			WithMaxWidth(1280).
			WithMaxHeight(720),
	); err != nil {
		return fmt.Errorf("start screencast %s: %w", url, err)
	}
	log.Info().Str("url", url).Msg("web-app: screencast started")

	frameCount := 0
	for {
		select {
		case <-loopCtx.Done():
			log.Info().Int("frames", frameCount).Msg("web-app: client disconnected, closing")
			return nil
		case frame := <-frameCh:
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], uint32(len(frame)))
			if _, err := conn.Write(hdr[:]); err != nil {
				return nil
			}
			if _, err := conn.Write(frame); err != nil {
				return nil
			}
			frameCount++
			if frameCount == 1 || frameCount%30 == 0 {
				log.Info().Int("frames", frameCount).Int("bytes", len(frame)).Msg("web-app: streaming")
			}
		}
	}
}
