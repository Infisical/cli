"use strict";

/**
 * playwright-agent.js
 *
 * Spawned by the Go WebApp PAM proxy handler. Communicates via stdin/stdout
 * using the framed binary protocol defined in proto.go:
 *
 *   [4-byte big-endian total payload length][1-byte message type][payload]
 *
 * Outbound (stdout → Go handler → relay → backend):
 *   0x01  FRAME     — raw JPEG bytes from Page.startScreencast
 *   0x02  PAGE_INFO — JSON { url, title } on navigation
 *
 * Inbound (stdin ← Go handler ← relay ← backend):
 *   0x03  MOUSE_MOVE  — JSON { x, y }
 *   0x04  MOUSE_DOWN  — JSON { x, y, button }
 *   0x05  MOUSE_UP    — JSON { x, y, button }
 *   0x06  KEY_DOWN    — JSON { key, code, modifiers }
 *   0x07  KEY_UP      — JSON { key, code, modifiers }
 *   0x08  KEY_CHAR    — JSON { text }
 *   0x09  SCROLL      — JSON { x, y, deltaX, deltaY }
 *   0x0A  RESIZE      — JSON { width, height }
 *   0x0B  NAVIGATE    — JSON { url }
 *   0xFF  CLOSE       — empty payload
 *
 * Configuration is passed via environment variables:
 *   WEBAPP_URL                    — required, target URL
 *   WEBAPP_SSL_REJECT_UNAUTHORIZED — "false" to skip TLS verification
 *   WEBAPP_SSL_CERTIFICATE         — optional PEM CA cert (triggers ignore-errors for now)
 */

const MSG_FRAME      = 0x01;
const MSG_PAGE_INFO  = 0x02;
const MSG_MOUSE_MOVE = 0x03;
const MSG_MOUSE_DOWN = 0x04;
const MSG_MOUSE_UP   = 0x05;
const MSG_KEY_DOWN   = 0x06;
const MSG_KEY_UP     = 0x07;
const MSG_KEY_CHAR   = 0x08;
const MSG_SCROLL     = 0x09;
const MSG_RESIZE     = 0x0A;
const MSG_NAVIGATE   = 0x0B;
const MSG_CLOSE      = 0xFF;

const targetUrl = process.env.WEBAPP_URL;
const sslRejectUnauthorized = process.env.WEBAPP_SSL_REJECT_UNAUTHORIZED !== "false";
const hasSslCertificate = Boolean(process.env.WEBAPP_SSL_CERTIFICATE);

const SPECIAL_KEY_CODES = {
  Backspace: 8,
  Tab: 9,
  Enter: 13,
  Shift: 16,
  Control: 17,
  Alt: 18,
  Escape: 27,
  " ": 32,
  ArrowLeft: 37,
  ArrowUp: 38,
  ArrowRight: 39,
  ArrowDown: 40,
  Delete: 46,
  Meta: 91,
};

function getKeyEventParams({ key, code, modifiers = 0 }) {
  const keyCode = SPECIAL_KEY_CODES[key] ?? (key && key.length === 1 ? key.toUpperCase().charCodeAt(0) : 0);
  const isPrintable = key && key.length === 1;
  const isSpecial = Object.prototype.hasOwnProperty.call(SPECIAL_KEY_CODES, key);

  return {
    key,
    code,
    modifiers,
    windowsVirtualKeyCode: keyCode,
    nativeVirtualKeyCode: keyCode,
    ...(isPrintable ? { text: key, unmodifiedText: key } : {}),
    ...(isSpecial ? { text: "", unmodifiedText: "" } : {}),
  };
}

if (!targetUrl) {
  process.stderr.write("playwright-agent: WEBAPP_URL is required\n");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Framed message I/O
// ---------------------------------------------------------------------------

function writeMessage(type, payload) {
  const totalLen = 1 + payload.length;
  const buf = Buffer.allocUnsafe(4 + 1 + payload.length);
  buf.writeUInt32BE(totalLen, 0);
  buf[4] = type;
  payload.copy(buf, 5);
  process.stdout.write(buf);
}

function writeJsonMessage(type, obj) {
  writeMessage(type, Buffer.from(JSON.stringify(obj)));
}

// Stdin buffering — TCP streams arrive in arbitrary chunks.
let stdinBuf = Buffer.alloc(0);
const inputHandlers = [];

process.stdin.on("data", (chunk) => {
  stdinBuf = Buffer.concat([stdinBuf, chunk]);
  while (stdinBuf.length >= 5) {
    const totalLen = stdinBuf.readUInt32BE(0);
    if (stdinBuf.length < 4 + totalLen) break;
    const msgType = stdinBuf[4];
    const payload = stdinBuf.slice(5, 4 + totalLen);
    stdinBuf = stdinBuf.slice(4 + totalLen);
    for (const h of inputHandlers) h(msgType, payload);
  }
});

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  let chromium;
  try {
    ({ chromium } = require("playwright"));
  } catch {
    process.stderr.write("playwright-agent: 'playwright' package not found. Install it with: npm install -g playwright && npx playwright install chromium\n");
    process.exit(1);
  }

  const launchArgs = [
    "--disable-dev-shm-usage",
    "--no-sandbox",
  ];

  // Disable TLS verification when requested or when a custom CA is provided.
  // TODO: proper custom CA support via NSS database injection.
  if (!sslRejectUnauthorized || hasSslCertificate) {
    launchArgs.push("--ignore-certificate-errors");
  }

  const browser = await chromium.launch({ headless: true, args: launchArgs });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    ignoreHTTPSErrors: !sslRejectUnauthorized || hasSslCertificate,
  });

  const page = await context.newPage();
  const client = await context.newCDPSession(page);

  // Navigate to target
  await page.goto(targetUrl, { waitUntil: "load", timeout: 30000 });

  // Send initial page info
  writeJsonMessage(MSG_PAGE_INFO, { url: page.url(), title: await page.title() });

  process.stderr.write(`playwright-agent: navigation complete, url=${page.url()}\n`);

  // Start screencast — Chrome pushes JPEG frames on content changes.
  // No maxWidth/maxHeight so frames are captured at the exact viewport size.
  await client.send("Page.startScreencast", {
    format: "jpeg",
    quality: 95,
  });

  let frameCount = 0;
  client.on("Page.screencastFrame", async ({ data, sessionId }) => {
    frameCount += 1;
    const jpegBytes = Buffer.from(data, "base64");
    process.stderr.write(`playwright-agent: frame #${frameCount} size=${jpegBytes.length} bytes\n`);
    writeMessage(MSG_FRAME, jpegBytes);
    // Ack so Chrome sends the next frame.
    try {
      await client.send("Page.screencastFrameAck", { sessionId });
    } catch {
      // Ignore — session may be closing.
    }
  });

  // Poll for URL/title changes every 2 s and emit PAGE_INFO on change.
  let lastUrl = page.url();
  const pageInfoInterval = setInterval(async () => {
    try {
      const currentUrl = page.url();
      if (currentUrl !== lastUrl) {
        lastUrl = currentUrl;
        writeJsonMessage(MSG_PAGE_INFO, { url: currentUrl, title: await page.title() });
      }
    } catch {
      // Page may be mid-navigation.
    }
  }, 2000);

  // ---------------------------------------------------------------------------
  // Input dispatch
  // ---------------------------------------------------------------------------

  inputHandlers.push(async (msgType, payload) => {
    try {
      switch (msgType) {

        case MSG_CLOSE:
          clearInterval(pageInfoInterval);
          await browser.close();
          process.exit(0);
          break;

        case MSG_MOUSE_MOVE: {
          const { x, y } = JSON.parse(payload.toString());
          await client.send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
          break;
        }

        case MSG_MOUSE_DOWN: {
          const { x, y, button = 0 } = JSON.parse(payload.toString());
          const btn = button === 1 ? "middle" : button === 2 ? "right" : "left";
          await client.send("Input.dispatchMouseEvent", {
            type: "mousePressed", x, y, button: btn, clickCount: 1,
          });
          break;
        }

        case MSG_MOUSE_UP: {
          const { x, y, button = 0 } = JSON.parse(payload.toString());
          const btn = button === 1 ? "middle" : button === 2 ? "right" : "left";
          await client.send("Input.dispatchMouseEvent", {
            type: "mouseReleased", x, y, button: btn, clickCount: 1,
          });
          break;
        }

        case MSG_KEY_DOWN: {
          const { key, code, modifiers = 0 } = JSON.parse(payload.toString());
          await client.send("Input.dispatchKeyEvent", {
            type: Object.prototype.hasOwnProperty.call(SPECIAL_KEY_CODES, key) ? "rawKeyDown" : "keyDown",
            ...getKeyEventParams({ key, code, modifiers }),
          });
          break;
        }

        case MSG_KEY_UP: {
          const { key, code, modifiers = 0 } = JSON.parse(payload.toString());
          await client.send("Input.dispatchKeyEvent", {
            type: "keyUp",
            ...getKeyEventParams({ key, code, modifiers }),
          });
          break;
        }

        case MSG_KEY_CHAR: {
          const { text, modifiers = 0 } = JSON.parse(payload.toString());
          await client.send("Input.dispatchKeyEvent", { type: "char", text, modifiers });
          break;
        }

        case MSG_SCROLL: {
          const { x, y, deltaX, deltaY } = JSON.parse(payload.toString());
          await client.send("Input.dispatchMouseEvent", {
            type: "mouseWheel", x, y, deltaX, deltaY,
          });
          break;
        }

        case MSG_RESIZE: {
          const { width, height } = JSON.parse(payload.toString());
          await page.setViewportSize({ width, height });
          // Restart screencast so frames are captured at the new viewport size.
          try { await client.send("Page.stopScreencast"); } catch {}
          await client.send("Page.startScreencast", { format: "jpeg", quality: 95 });
          break;
        }

        case MSG_NAVIGATE: {
          const { url } = JSON.parse(payload.toString());
          await page.goto(url, { waitUntil: "load", timeout: 30000 });
          break;
        }

        default:
          break;
      }
    } catch (err) {
      process.stderr.write(`playwright-agent: input dispatch error (type=0x${msgType.toString(16)}): ${err.message}\n`);
    }
  });

  // Keep process alive until stdin closes (Go handler closed connection).
  process.stdin.on("end", async () => {
    clearInterval(pageInfoInterval);
    await browser.close();
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    clearInterval(pageInfoInterval);
    await browser.close();
    process.exit(0);
  });
}

main().catch((err) => {
  process.stderr.write(`playwright-agent: fatal: ${err.message}\n`);
  process.exit(1);
});
