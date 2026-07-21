package gatewayv2

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
)

// handleWebAppProxy launches a headless Chromium, navigates it to the target web
// application, and (Phase 2.1) captures a screenshot to disk to prove the browser
// loaded the internal site. The connection is held open until the client
// disconnects. Phase 2.2 replaces the screenshot with a live screencast over conn.
func handleWebAppProxy(gctx context.Context, conn net.Conn, targetHost string, targetPort int) error {
	url := fmt.Sprintf("http://%s:%d", targetHost, targetPort)
	log.Info().Str("url", url).Msg("web-app: launching headless Chromium")

	ctx, cancel := chromedp.NewContext(gctx)
	defer cancel()

	var buf []byte
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.FullScreenshot(&buf, 90),
	); err != nil {
		return fmt.Errorf("navigate/screenshot %s: %w", url, err)
	}

	const shotPath = "/tmp/webapp_shot.png"
	if err := os.WriteFile(shotPath, buf, 0o644); err != nil {
		log.Warn().Err(err).Msg("web-app: failed to write screenshot")
	} else {
		log.Info().Str("path", shotPath).Int("bytes", len(buf)).Str("url", url).
			Msg("web-app: navigated and captured screenshot")
	}

	// Keep the session (and Chromium) alive until the client disconnects.
	// Phase 2.2 replaces this read-loop with the screencast stream.
	tmp := make([]byte, 4096)
	for {
		if _, err := conn.Read(tmp); err != nil {
			return nil
		}
	}
}
