package gatewayv2

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// handleWebAppProxy launches a headless Chromium, navigates it to the target web
// application, and streams the page as JPEG frames over conn. Each frame is
// length-prefixed (4-byte big-endian length + JPEG bytes) so the client can
// reassemble frame boundaries from the raw byte tunnel.
func handleWebAppProxy(gctx context.Context, conn net.Conn, targetHost string, targetPort int) error {
	url := fmt.Sprintf("http://%s:%d", targetHost, targetPort)
	log.Info().Str("url", url).Msg("web-app: launching headless Chromium")

	ctx, cancel := chromedp.NewContext(gctx)
	defer cancel()

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
		select {
		case frameCh <- data:
		default: // drop the frame if the writer is behind (backpressure)
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
		case <-gctx.Done():
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
			if frameCount <= 2 {
				_ = os.WriteFile(fmt.Sprintf("/tmp/webapp_frame_%d.jpg", frameCount), frame, 0o644)
			}
			if frameCount == 1 || frameCount%30 == 0 {
				log.Info().Int("frames", frameCount).Int("bytes", len(frame)).Msg("web-app: streaming")
			}
		}
	}
}
