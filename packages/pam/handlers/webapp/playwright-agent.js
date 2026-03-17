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
const MSG_HTTP_EVENT = 0x0C;
const MSG_REPLAY_TRACE = 0x0D;
const MSG_CLOSE      = 0xFF;

const targetUrl = process.env.WEBAPP_URL;
const sslRejectUnauthorized = process.env.WEBAPP_SSL_REJECT_UNAUTHORIZED !== "false";
const hasSslCertificate = Boolean(process.env.WEBAPP_SSL_CERTIFICATE);
const rrwebRecordPath = process.env.WEBAPP_RRWEB_RECORD_PATH;
const rrwebBootstrapPath = process.env.WEBAPP_RRWEB_BOOTSTRAP_PATH;
const MAX_RECORDED_BODY_BYTES = 64 * 1024;

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
  const isSpecial = Object.prototype.hasOwnProperty.call(SPECIAL_KEY_CODES, key);

  return {
    key,
    code,
    modifiers,
    windowsVirtualKeyCode: keyCode,
    nativeVirtualKeyCode: keyCode,
    ...(isSpecial ? { text: "", unmodifiedText: "" } : {}),
  };
}

if (!targetUrl) {
  process.stderr.write("playwright-agent: WEBAPP_URL is required\n");
  process.exit(1);
}

if (!rrwebRecordPath) {
  process.stderr.write("playwright-agent: WEBAPP_RRWEB_RECORD_PATH is required\n");
  process.exit(1);
}

if (!rrwebBootstrapPath) {
  process.stderr.write("playwright-agent: WEBAPP_RRWEB_BOOTSTRAP_PATH is required\n");
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

function writeMessageAndWait(type, payload) {
  const totalLen = 1 + payload.length;
  const buf = Buffer.allocUnsafe(4 + 1 + payload.length);
  buf.writeUInt32BE(totalLen, 0);
  buf[4] = type;
  payload.copy(buf, 5);

  return new Promise((resolve, reject) => {
    process.stdout.write(buf, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function writeJsonMessage(type, obj) {
  writeMessage(type, Buffer.from(JSON.stringify(obj)));
}

function toMultiValueHeaders(headers) {
  return Object.fromEntries(
    Object.entries(headers ?? {}).map(([key, value]) => [
      key,
      Array.isArray(value) ? value.map(String) : [String(value)],
    ])
  );
}

function getHeaderValue(headers, name) {
  const values = headers?.[name] ?? headers?.[name.toLowerCase()] ?? headers?.[name.toUpperCase()];
  if (!values || values.length === 0) return "";
  return values[0];
}

function isTextLikeContentType(contentType) {
  if (!contentType) return false;
  const normalized = contentType.toLowerCase();
  return normalized.startsWith("text/")
    || normalized.includes("json")
    || normalized.includes("xml")
    || normalized.includes("javascript")
    || normalized.includes("form-urlencoded");
}

function encodeBody(bodyBuffer) {
  if (!bodyBuffer || bodyBuffer.length === 0) return undefined;
  const truncated = bodyBuffer.length > MAX_RECORDED_BODY_BYTES
    ? bodyBuffer.subarray(0, MAX_RECORDED_BODY_BYTES)
    : bodyBuffer;
  return truncated.toString("base64");
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
  await context.addInitScript({ path: rrwebRecordPath });
  await context.addInitScript({ path: rrwebBootstrapPath });

  const page = await context.newPage();
  const client = await context.newCDPSession(page);
  let requestCounter = 0;
  const requestIds = new WeakMap();
  let pageInfoInterval;
  let shuttingDown = false;
  const recordedRRWebEvents = [];
  const seenRRWebEventKeys = new Set();

  function appendRRWebEvents(events, reason) {
    for (const event of events) {
      const key = JSON.stringify(event);
      if (seenRRWebEventKeys.has(key)) continue;
      seenRRWebEventKeys.add(key);
      recordedRRWebEvents.push(event);
    }
  }

  await page.exposeBinding("__infisicalFlushRRWebEvents", async (_source, events, reason = "pagehide") => {
    if (!Array.isArray(events)) return;
    appendRRWebEvents(events, reason);
  });

  async function flushRRWebEventsFromPage(reason) {
    try {
      const events = await page.evaluate(() => {
        const events = window.__INFISICAL_RRWEB_EVENTS || [];
        window.__INFISICAL_RRWEB_EVENTS = [];
        return events;
      });

      appendRRWebEvents(events, reason);
    } catch (err) {
      process.stderr.write(`playwright-agent: failed to flush rrweb events (${reason}): ${err.message}\n`);
    }
  }

  async function ensureRRWebRecorderStarted() {
    try {
      await page.addScriptTag({ path: rrwebRecordPath });
    } catch (err) {
      process.stderr.write(`playwright-agent: failed to inject rrweb bundle: ${err.message}\n`);
    }

    try {
      await page.evaluate(() => {
        window.__INFISICAL_RRWEB_EVENTS = window.__INFISICAL_RRWEB_EVENTS || [];

        if (typeof window.rrwebRecord !== "function") {
          throw new Error("rrwebRecord global missing");
        }

        if (!window.__INFISICAL_RRWEB_STOP) {
          window.__INFISICAL_RRWEB_STOP = window.rrwebRecord({
            emit(event) {
              window.__INFISICAL_RRWEB_EVENTS.push(event);
            }
          });
        }

        if (typeof window.rrwebRecord.takeFullSnapshot === "function") {
          window.rrwebRecord.takeFullSnapshot(true);
        }
      });
    } catch (err) {
      process.stderr.write(`playwright-agent: failed to start rrweb recorder: ${err.message}\n`);
    }
  }

  async function emitReplayTrace() {
    try {
      await flushRRWebEventsFromPage("shutdown");
      const replayBytes = Buffer.from(JSON.stringify({
        format: "rrweb",
        events: recordedRRWebEvents,
      }));
      await writeMessageAndWait(MSG_REPLAY_TRACE, replayBytes);
    } catch (err) {
      process.stderr.write(`playwright-agent: failed to persist replay trace: ${err.message}\n`);
    }
  }

  async function shutdown(reason) {
    if (shuttingDown) return;
    shuttingDown = true;

    if (pageInfoInterval) clearInterval(pageInfoInterval);

    try {
      await client.send("Page.stopScreencast");
    } catch {
      // Session may already be shutting down.
    }

    await emitReplayTrace();
    await browser.close();
    process.stderr.write(`playwright-agent: shutdown complete (${reason})\n`);
    process.exit(0);
  }

  page.on("request", async (request) => {
    try {
      const url = request.url();
      if (!url.startsWith("http://") && !url.startsWith("https://")) return;

      const requestId = `${++requestCounter}`;
      requestIds.set(request, requestId);

      const headers = toMultiValueHeaders(
        typeof request.allHeaders === "function" ? await request.allHeaders() : await request.headers()
      );

      writeJsonMessage(MSG_HTTP_EVENT, {
        timestamp: new Date().toISOString(),
        requestId,
        eventType: "request",
        headers,
        method: request.method(),
        url,
        body: encodeBody(request.postDataBuffer?.() ?? null)
      });
    } catch (err) {
      process.stderr.write(`playwright-agent: failed to record request event: ${err.message}\n`);
    }
  });

  page.on("response", async (response) => {
    try {
      const url = response.url();
      if (!url.startsWith("http://") && !url.startsWith("https://")) return;

      const request = response.request();
      const requestId = requestIds.get(request) ?? `${++requestCounter}`;
      const headers = toMultiValueHeaders(
        typeof response.allHeaders === "function" ? await response.allHeaders() : await response.headers()
      );

      let body;
      if (isTextLikeContentType(getHeaderValue(headers, "content-type"))) {
        body = encodeBody(await response.body());
      }

      writeJsonMessage(MSG_HTTP_EVENT, {
        timestamp: new Date().toISOString(),
        requestId,
        eventType: "response",
        headers,
        status: `${response.status()} ${response.statusText()}`.trim(),
        body
      });
    } catch (err) {
      process.stderr.write(`playwright-agent: failed to record response event: ${err.message}\n`);
    }
  });

  page.on("load", async () => {
    await ensureRRWebRecorderStarted();
  });

  // Navigate to target
  await page.goto(targetUrl, { waitUntil: "load", timeout: 30000 });
  await ensureRRWebRecorderStarted();

  // Send initial page info
  writeJsonMessage(MSG_PAGE_INFO, { url: page.url(), title: await page.title() });

  process.stderr.write(`playwright-agent: navigation complete, url=${page.url()}\n`);

  // Start screencast — Chrome pushes JPEG frames on content changes.
  // No maxWidth/maxHeight so frames are captured at the exact viewport size.
  await client.send("Page.startScreencast", {
    format: "jpeg",
    quality: 95,
  });

  client.on("Page.screencastFrame", async ({ data, sessionId }) => {
    const jpegBytes = Buffer.from(data, "base64");
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
  pageInfoInterval = setInterval(async () => {
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
          await shutdown("close message");
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
          await flushRRWebEventsFromPage(`before navigate to ${url}`);
          await page.goto(url, { waitUntil: "load", timeout: 30000 });
          await ensureRRWebRecorderStarted();
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
    await shutdown("stdin closed");
  });

  process.on("SIGTERM", async () => {
    await shutdown("sigterm");
  });
}

main().catch((err) => {
  process.stderr.write(`playwright-agent: fatal: ${err.message}\n`);
  process.exit(1);
});
