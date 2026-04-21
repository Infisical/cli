# Oracle PAM — Research & Implementation Notes

## Current state (2026-04-22)

**Oracle PAM works end-to-end for JDBC thin clients.** Verified with sqlcl against AWS RDS Oracle 19c: SELECT, INSERT, DDL, PL/SQL, DBMS_OUTPUT, bind variables, session-metadata queries, clean disconnect. Credential injection works: user types `infisical-pam-proxy`, real Oracle password never leaves the gateway.

**Architecture shipped (see `packages/pam/handlers/oracle/proxy_auth.go`):** the gateway opens a raw TCP connection to upstream, forwards client's `CONNECT` / ANO / TCPNego / DataTypeNego bytes verbatim in both directions, and intercepts only at the O5Logon boundary to swap placeholder-keyed material for real-password-keyed material in four specific TTC fields. After auth, byte relay is transparent. This bypasses the state-mismatch problem that blocks the simpler "impersonate Oracle entirely" approach.

**File map (current, post-cleanup):**

- `proxy.go` — entry, relay loop, connection glue
- `proxy_auth.go` — the proxied-auth flow (pre-auth byte proxy + O5Logon translation)
- `o5logon.go` — O5Logon crypto primitives + `BuildSvrResponse`
- `o5logon_server.go` — phase-2 request parser, error packet helpers
- `tns.go` — DATA packet codec + REFUSE helper
- `ttc.go` — TTC codec (compressed ints, CLR strings, KVP encoding)
- `query_logger.go` — TTC tap for session recording
- `constants.go` — `ProxyPasswordPlaceholder`
- `ATTRIBUTION.md` — MIT notice for code ported from sijms/go-ora

**What still needs verification:**
- Session recording file actually contains the captured queries (tap is wired but not end-to-end tested on this path)
- Other clients: sqlplus (OCI), python-oracledb (thin), SQL Developer, DBeaver, Toad
- Oracle NNE (Native Network Encryption) customers
- Oracle RAC via SCAN listeners

**Historical sections below** document the impersonation approach we tried first (now removed from the codebase) and the research we did along the way. Kept for context — the "what we tried" and "how vendors solve this" analysis is still accurate.

---

## 1. Context

Oracle is the 8th database type being added to Infisical PAM. For the seven existing databases (Postgres, MySQL, MSSQL, MongoDB, Redis, plus SSH/Kubernetes), the gateway acts as a credential-injecting middleman: the user types a placeholder password, the gateway rewrites authentication on the fly with real credentials stored in Infisical, and forwards traffic. The user never sees real credentials, every query is session-recorded.

Oracle breaks this pattern because:

- The **TNS/TTC wire protocol is proprietary and poorly documented**. No published spec. Different reference behaviors per Oracle client (sqlplus/OCI vs. JDBC thin vs. python-oracledb vs. go-ora).
- **O5Logon authentication is cryptographic** — the server must generate a challenge derived from the password; client derives response from the same password; simple password substitution like Postgres/MySQL doesn't work.
- **Pre-authentication handshake has 4–5 negotiation phases** where each response must be byte-correct for the specific client profile.

## 2. Constraints (product-level)

Decided by product:

1. **No credential exposure to user** — not even ephemeral credentials. User must never see, store, or be able to exfiltrate an Oracle password.
2. **Must work with the mainstream Oracle clients** actual DBAs use: sqlplus, SQL Developer, DBeaver, Toad, JDBC applications.
3. **Complete support** — not a partial ship that only covers a subset of clients.
4. **Time/effort not a constraint.**
5. **Ongoing maintenance acceptable.**

## 3. All approaches evaluated

| Approach | Used by | Ruled in/out | Why |
|----------|---------|-------------|-----|
| Full protocol impersonation | StrongDM, our attempt | **IN (THE MASK)** | Meets all constraints |
| Cert-based auth (mTLS + `IDENTIFIED EXTERNALLY` users) | Teleport | **IN (THE PASS)** | Meets all constraints |
| Ephemeral Oracle users (`CREATE USER temp_x; DROP USER` per session) | CyberArk SIA | OUT | User sees ephemeral password |
| Jump-host with RDP video recording | CyberArk PSM | OUT | Wrong shape for a network gateway; heavy Windows infra |
| Vaulted credential checkout | Delinea, BeyondTrust, HashiCorp Boundary | OUT | User sees real password |

## 4. The two viable paths

### THE MASK — full protocol impersonation

Gateway pretends to be an Oracle server to the client, holds real credentials, authenticates upstream to the real Oracle, relays bytes. Zero Oracle-side configuration required by the customer.

**What StrongDM ships in production.** Confirmed by release-note analysis (see §9).

### THE PASS — cert-based auth

Infisical issues per-session client certificates. Oracle is configured with TCPS + users created as `IDENTIFIED EXTERNALLY AS 'CN=user'`. Gateway terminates client TLS, re-establishes TLS upstream with a signed cert. No passwords anywhere.

**What Teleport ships in production.** Specified in their [RFD 0115](https://github.com/gravitational/teleport/blob/master/rfd/0115-oracle-db-access-integration.md).

### Trade-off

One-axis choice:

- **MASK** = zero customer-side setup, permanent protocol maintenance
- **PASS** = one-time customer DBA setup per Oracle DB, minimal ongoing maintenance

## 5. Current state of THE MASK implementation

Branch: `oracle-db`. Handler: `packages/pam/handlers/oracle/`.

### File map (~2,750 LOC)

| File | Purpose |
|------|---------|
| `proxy.go` | `OracleProxy` struct, `HandleConnection` orchestration |
| `upstream.go` | Upstream dial via go-ora with TLS-in-dial trick; captures authenticated `net.Conn` |
| `tns.go` | TNS packet codec (CONNECT/ACCEPT/DATA/MARKER/REFUSE); ported from go-ora |
| `o5logon.go` + `o5logon_server.go` | Server-side O5Logon crypto + auth phase 1/2 builders |
| `nego.go` | `RunPreAuthExchange` pre-auth dispatcher; handles ANO/TCPNego/DataTypeNego |
| `nego_templates.go` | Captured RDS responses (currently used as static replies) |
| `ano.go` | ANO request parser + refusal response |
| `ttc.go` | TTC codec helpers (`TTCBuilder`, `TTCReader`) |
| `query_logger.go` | Passive TTC tap for session recording |
| `handshake_test.go` | Standalone test: runs server-side handshake, points go-ora at it |
| `constants.go` | `ProxyPasswordPlaceholder = "infisical-pam-proxy"` |
| `ATTRIBUTION.md` | MIT notice for ported go-ora code |

### Protocol flow and status

```
Client                                Gateway                          Upstream Oracle
  │                                     │                                     │
  │── CONNECT ──────────────────────▶   │                                     │
  │                                     │── CONNECT ───────────────────────▶  │  [go-ora]
  │                                     │◀── ACCEPT + nego + O5Logon ──────   │  [go-ora]
  │                                     │   (upstream authenticated)          │
  │◀─ ACCEPT ────────────────────────   │                                     │
  │                                     │                                     │
  │── connect-data supplement ──────▶   │  ← NEW 16-bit framed DATA           │
  │   (go-ora only — sqlplus skips)     │                                     │
  │                                     │                                     │
  │── ANO request ──────────────────▶   │                                     │
  │◀─ ANO refusal ────────────────────  │                                     │
  │                                     │                                     │
  │── TCPNego request ──────────────▶   │                                     │
  │◀─ TCPNego response ──────────────   │                                     │
  │                                     │                                     │
  │── DataTypeNego request ─────────▶   │                                     │
  │◀─ DataTypeNego response ─────────   │                                     │
  │                                     │                                     │
  │── O5Logon phase 1 ──────────────▶   │                                     │
  │◀─ phase 1 response ─────────────    │                                     │
  │── O5Logon phase 2 ──────────────▶   │                                     │
  │◀─ phase 2 response ──────────────   │                                     │
  │                                     │                                     │
  │── post-auth byte relay ◀────────────┼──────────── byte relay ──────────   │
```

### Per-stage status against each client

| Stage | go-ora | sqlcl (JDBC thin) | sqlplus (OCI) |
|-------|--------|-------------------|---------------|
| CONNECT / ACCEPT | ✅ | ✅ | untested |
| Connect-data supplement drain | ✅ | N/A | N/A |
| ANO refusal | ✅ | ✅ | untested |
| TCPNego | ✅ | ✅ | untested |
| DataTypeNego | ✅ (dynamic echo generator) | ✅ | untested |
| O5Logon phase 1 | ✅ | ✅ (fixed JDBC thin username encoding) | untested |
| O5Logon phase 2 + password verify | ✅ | ✅ | untested |
| Phase 2 response with trailing summary | ✅ | ✅ | untested |
| Post-auth byte relay | not tested E2E | ⚠ stalls — state mismatch between upstream (go-ora caps) and client (sqlcl caps) | untested |

**As of 2026-04-21 session, both go-ora and sqlcl (JDBC thin) complete the full handshake + O5Logon auth successfully.** sqlcl sends an OALL8 query through the relay, but upstream Oracle responds with a MARKER (protocol reset signal) + ORA-error instead of query results — because the upstream session was negotiated with go-ora's TTC caps at startup, and sqlcl's post-auth bytes don't match the state the upstream is in.

## 6. What broke (and what's fixable)

### Failure 1: sqlcl / JDBC thin — DataTypeNego

- **Symptom:** `ORA-17401: Protocol violation`
- **Root cause:** we replay a DataTypeNego response captured from `go-ora ↔ RDS` back to JDBC thin. JDBC's offered type list differs from go-ora's, so JDBC sees types it never advertised and aborts.
- **Fix shape:** build a dynamic generator (see §8 for the reference material found).

### Failure 2: go-ora — TCPNego response rejected

- **Symptom:** `server compile time caps length less than 8`
- **Likely cause:** either a content issue in our captured `rdsTCPNegoResponse` template or state-dependent parsing in go-ora tied to prior ANO/nego steps.
- **Fix shape:** debug the specific byte that go-ora trips on. Probably ~hours of work with packet-level diffing.

### Failure 3 (FIXED TODAY): go-ora — post-ACCEPT framing

- **Symptom:** `TNS packet too large: 16056320`
- **Root cause:** after ACCEPT, go-ora sends a **16-bit-framed DATA packet** containing `(DESCRIPTION=...)` as a connect-data supplement, BEFORE switching to 32-bit framing. Our code assumed 32-bit framing immediately after ACCEPT.
- **Fix shipped:** added `detectConnectDataSupplement` in `proxy.go` and drain logic in both `proxy.go` and `handshake_test.go`. When we detect a 16-bit-framed DATA packet with the signature pattern (length in `[0:2]`, zero checksum in `[2:4]`, DATA opcode `0x06` in `[4]`), we consume it and continue.
- **This unblocks 2 of 4 pre-auth stages for go-ora.**

## 7. Research: how the major PAM vendors solve Oracle

### StrongDM — confirmed via release-note analysis

Their Oracle integration is a protocol-level proxy written in Go (same as us). Release-note evidence proves they wrote their own TNS/TTC parser:

- 2025-10-16: "shorter username would cause ORA-03146: invalid buffer length for TTC field" — only happens if you wrote the TTC encoder yourself
- 2025-10-09: "JDBC-based Oracle clients (DBeaver, SQL Developer) could fail with a decoding error during authentication" — separate JDBC-specific decode path
- 2025-09-26: "warning messages are now correctly decoded if present during the Oracle authentication handshake"
- 2025-11-20: "corrects an issue with connecting to Oracle resources using server or client character sets other than AL32UTF8"

They ship separate "Oracle" and "Oracle (NNE)" resource types. NNE is the Native Network Encryption variant — they support both, with selectable AES/DES/RC4 + SHA algorithms. That means they implement full NNE termination (decrypt + re-encrypt), not refusal.

8+ Oracle-specific bug fixes in Sep–Nov 2025 alone. Confirms the maintenance burden is real and permanent — this is a team of 2–4 engineers actively hardening the protocol.

No public source code. We have to implement from scratch using go-ora and python-oracledb as references.

### Teleport — confirmed via public RFD and docs

Oracle Access Proxy. Terminates incoming TLS, re-establishes TLS to Oracle with a Teleport-signed client cert. Cert-based auth end-to-end.

Hard requirements on Oracle side:
- TCPS listener on port 2484
- `SSL_CLIENT_AUTHENTICATION = TRUE`
- `SQLNET.AUTHENTICATION_SERVICES = (TCPS)` in `sqlnet.ora`
- Teleport wallet installed on Oracle server
- Users created as `IDENTIFIED EXTERNALLY AS 'CN=user'`

Oracle 18c/19c/21c supported. 12c explicitly incompatible (dropped due to incompatibilities).

`tctl auth sign --format=oracle` generates the Oracle wallet for the server to trust. Turnkey DBA setup.

### CyberArk SIA — ruled out (would expose ephemeral creds)

Ephemeral Oracle users created per-session via bootstrap admin (`ALTER USER`, `CREATE USER`, `DROP USER`, `GRANT ANY ROLE`). Customer must also enable TCPS and disable NNE.

### CyberArk PSM — ruled out (wrong arch for gateway)

SQL Developer installed on PSM host itself. User RDPs to PSM, PSM launches SQL Developer with injected credentials via templated `ConnectionsTemplate.json`. Session recorded as RDP video.

### HashiCorp Boundary — **no native Oracle support**

Generic TCP tunneling + Vault credential brokering. Users still see Oracle passwords. No Oracle wire protocol handling. Confirmed via docs + source tree (no `oracle.go` in `internal/cmd/commands/connect`). Not a fourth architectural pattern.

### Delinea / BeyondTrust — ruled out (vaulted creds)

Secret Server templates / Password Safe. User checks out credential, sees the password.

## 8. Dynamic DataType Negotiation — the key technical finding

**The single most important finding for THE MASK path.**

### It's filter-and-echo, not set-intersection

Previous assumption: "server must compute intersection of client's offered types and server's supported types." That framing made the problem look like multi-week reverse engineering.

Correct behavior (from python-oracledb source):

> For each type the client offered, the server echoes back the same `(data_type, conv_data_type, representation)` entry **if the server supports it**; otherwise returns the type with `conv_data_type=0` (a "bare" marker meaning unsupported).

The server maintains its own fixed supported set (Oracle 19c's type catalog). For each offered type T, emit either echo-with-rep or `(T, 0)`. Representation echoed back may be the server's preferred rep, not the client's.

### Wire format (synthesized from go-ora + python-oracledb)

**Request (client → server), opcode 0x02:**
```
byte   0x02                         # TNS_MSG_TYPE_DATA_TYPES
u16LE  client_in_charset
u16LE  client_out_charset
byte   flags                        # TNS_ENCODING_MULTI_BYTE | TNS_ENCODING_CONV_LENGTH
byte   len + compile_time_caps[]    # ~45 bytes for 19c
byte   len + runtime_caps[]         # ~7 bytes
<if runtime_caps[1]&1: 11-byte tz block [+ optional 4-byte clientTZVersion]>
u16LE  client_ncharset              # go-ora sends this; JDBC may not
loop:                               # type-rep tuples (repeated)
  u16BE data_type
  u16BE conv_data_type
  u16BE representation
  u16BE 0                           # per-entry terminator
u16BE  0                            # final terminator
```

When `compile_time_caps[27] == 0`, each field is a single byte instead of u16BE — legacy mode.

**Response (server → client), opcode 0x02:**
```
byte   0x02
<if runtime_caps[1]&1: 11-byte tz block [+ optional 4-byte serverTZVersion]>
loop:
  u16BE data_type                   # 0 terminates
  u16BE conv_data_type              # 0 = bare entry, stop reading this entry
  <if conv_data_type != 0: 4 more bytes (u16BE rep + u16BE 0)>
```

### Reference materials

| Reference | URL | What's in it |
|-----------|-----|--------------|
| `oracle/python-oracledb` | https://github.com/oracle/python-oracledb/blob/main/src/oracledb/impl/thin/messages/data_types.pyx | **Oracle-authored.** 320-entry `DATA_TYPES` array as `(data_type, conv_data_type, representation)` tuples. `_write_message` (request builder) and `_process_message` (response parser). This is the Rosetta Stone — port this table. |
| `sijms/go-ora` | https://github.com/sijms/go-ora/blob/master/v2/data_type_nego.go | Full `buildTypeNego()` with ~270 `addTypeRep()` calls. Type range 1–640. Three reps: `NATIVE=0`, `UNIVERSAL=1`, `ORACLE=10`. Go-native cross-check. |
| `SpiderLabs/net-tns` | https://github.com/SpiderLabs/net-tns/blob/master/lib/net/tti/messages/data_type_negotiation_request.rb | Ruby request builder. Confirms `compile_time_caps[27]` 1-byte vs 2-byte encoding toggle. |
| Wireshark `packet-tns.c` | https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-tns.c | Falls through to generic data dissector for DTY. **Not useful** for content parsing but confirms the TNS framing. |
| `T4CTTIdty.java` (Oracle JDBC) | not public | We couldn't find a decompilation. Would be the third reference. Using python-oracledb + go-ora is sufficient since the Oracle-blessed reference covers 320 types. |

### Open questions (for the implementer)

- **Do go-ora's offered types differ from JDBC thin's?** Unknown without a JDBC capture. Likely JDBC offers a superset (XDB/XML, AQ, streams). The server's supported set should be derived from 19c, NOT from any specific client.
- **How to handle `compile_time_caps[27] == 0` legacy clients?** Match `go-ora`'s write/read logic — it already handles both modes.
- **Time zone block representation** — `runtime_caps[1] & 1` flag. Mirror what client advertises.

Research agent's confidence: tractable, 1–2 weeks of focused work.

## 9. StrongDM research — detailed findings

Full transcript of the research (what we could verify, what we couldn't):

**Verified facts:**
- Gateway is Go (job postings, HN threads, careers page)
- Hand-rolled TNS/TTC parser (release-note bugs prove it — `ORA-03146` invalid buffer length, character set conversion bugs, warning decode bugs)
- Separate decode paths per client (JDBC decode bugs distinct from OCI bugs in release notes)
- Oracle handling lives in main gateway binary (release notes ship as CLI version bumps, not sidecar)
- Full NNE termination (not refusal) — separate resource type with selectable algorithms, stacks with TLS
- Character-set conversion done themselves (AL32UTF8-specific bugs)
- Active team of 2–4 engineers hardening the protocol (8+ bug fixes Sep–Nov 2025)

**Not found (confirmed absent):**
- No public StrongDM source code for Oracle
- No fork of sijms/go-ora or godror on their GitHub org
- No patent, blog post, conference talk, or ex-employee writeup describing the Oracle internals
- No description of their DataType Negotiation strategy specifically

**Bottom line:** what we're building is what StrongDM ships. Their release-note patterns confirm the maintenance burden is ongoing but bounded — not an infinite commitment.

## 10. Code changes made in this session

### `packages/pam/handlers/oracle/proxy.go`

Added `detectConnectDataSupplement` (new function, ~20 LOC) that identifies a 16-bit-framed DATA packet post-ACCEPT by signature: `bytes[0:2]` = plausible length (8..64K), `bytes[2:4]` = 0 (checksum zero), `bytes[4]` = 0x06 (DATA opcode).

Added supplement-drain logic to `HandleConnection`: after ACCEPT peek, if a supplement is detected, consume it (either from the peek buffer alone or by reading additional bytes from the conn) before creating the `prependedConn` for `RunPreAuthExchange`.

### `packages/pam/handlers/oracle/handshake_test.go` (new file)

Standalone test that runs the client-facing handshake on a local TCP listener (skipping upstream Oracle dial) and points go-ora at it with `ProxyPasswordPlaceholder` as the password. Mirrors the proxy.go handshake logic in a test harness.

Gated by env var: `ORACLE_HANDSHAKE_TEST=1 go test -run TestHandshakeAgainstGoOra ./packages/pam/handlers/oracle/...`

Skipped by default. Useful for iterating on protocol fixes without needing a live Oracle or the full PAM/gateway stack.

### `packages/pam/handlers/oracle/nego_templates.go`

Removed a stray `0x00` byte at offset 180 of `rdsTCPNegoResponse` that was causing go-ora to read `compile_caps_length = 0` ("server compile time caps length less than 8"). The original capture had a one-byte surplus. Template now parses cleanly through go-ora's client-side `newTCPNego`.

### `packages/pam/handlers/oracle/nego.go`

**Full rewrite of DataType Nego parser and response builder.** Previously we parsed a minimal header and replayed a static captured RDS response. Now:

- `ClientDataTypeNegoRequest` struct holds the parsed request including TZ preamble, `ClientTZVersion`, `ServernCharset`, and a list of `DataTypeTuple` entries (full or bare).
- `parseClientDataTypeNego` parses the full wire format, including the optional TZ/version preamble (conditional on `runtime_caps[1]&1` and `compile_caps[37]&2`), the mandatory `ServernCharset`, and tuple-by-tuple type entries. Supports both 2-byte and 1-byte field modes (legacy `compile_caps[27]==0`).
- `buildServerDataTypeNego` now echoes the client's offered type list dynamically. For each tuple the client sent, we reply with an identical tuple ("supported"). The TZ preamble is mirrored from the client's request. Terminator is `u16BE 0` (or `u8 0` in legacy mode).

**Strategy note:** we mirror everything the client offered rather than maintaining a server-side supported-type set. This works because our gateway byte-relays data from upstream Oracle (which did its own type negotiation with go-ora); we just need the client to accept the handshake.

### `packages/pam/handlers/oracle/o5logon.go`

Fixed `VerifyClientPassword` to decrypt with `padding=true` instead of `padding=false`. Client calls `encryptPassword(pw, key, padding=true)` which returns the full PKCS5-padded ciphertext; decrypting with `padding=false` left the trailing pad bytes in place, causing `decoded[16:] != ProxyPasswordPlaceholder`.

### Handshake test now PASSES end-to-end

```
$ ORACLE_HANDSHAKE_TEST=1 go test -count=1 -run TestHandshakeAgainstGoOra \
    ./packages/pam/handlers/oracle/... -v
...
    handshake_test.go:173: password verified — client proved knowledge of placeholder
    handshake_test.go:182: phase-2 response sent — handshake complete from server side
    handshake_test.go:79: PASS: go-ora client completed the handshake against our impersonation
--- PASS: TestHandshakeAgainstGoOra (3.01s)
```

The go-ora client connects, authenticates with `ProxyPasswordPlaceholder`, and our server-side O5Logon successfully verifies its password. This proves the protocol impersonation approach works end-to-end for at least one major client profile.

## 11. What we exhausted and what's definitively needed for THE MASK

### Completed in this session
- ✅ Dynamic DataType Nego parser + echo generator
- ✅ TCPNego captured-template off-by-one fix
- ✅ Connect-data supplement drain
- ✅ O5Logon password verification padding fix
- ✅ JDBC thin username encoding (raw bytes, no CLR prefix) in phase 1 + phase 2 parsers
- ✅ Phase 2 response trailing summary packet
- ✅ End-to-end handshake against sqlcl (JDBC thin): full auth completes successfully
- ✅ Extracted upstream's real phase-2 KVPs (47 entries including `AUTH_SESSION_ID`, `AUTH_SERIAL_NUM`, all NLS params) via a custom byte-level parser; mirrored them in our downstream phase-2 response

### The architectural blocker (verified, not speculation)

**Post-auth byte relay fails even with full session-metadata mirroring.** When sqlcl sends its first query post-auth (an OALL8 execute, 469 bytes), upstream Oracle responds with MARKER packets (0x0C, Oracle's protocol-reset signal) followed by an ORA-error summary. Same behavior regardless of whether we mirror session IDs, serial numbers, NLS params, DB info, or any combination thereof.

Root cause: the upstream Oracle session was negotiated by **go-ora**, not by us. go-ora's session holds state we cannot access or influence from outside the library:
- **Sequence numbers** (per-session monotonic, incremented by every round-trip)
- **`UseBigClrChunks` / `ClrChunkSize`** framing flags
- **Compile-time capability bits** that influence downstream packet parsing (`ServerCompileTimeCaps[4]`, `[15]`, `[16]`, `[27]`, `[37]` all gate behaviors)
- **Runtime capability bits** (`RuntimeCap[1]` gates TZ handling)
- **Character-set conversion state**
- **Negotiated ANO service levels** (even though we refused ANO to the client, go-ora may have negotiated supervisor-level ANO with upstream)

The client (sqlcl) sends its post-auth RPCs per **its** negotiated state with us. When we relay those bytes to upstream, upstream interprets them per **go-ora's** state. Any mismatch in any of the above fields produces a protocol violation — which is exactly what we see.

### What would actually fix this

**Replace go-ora's upstream dial with our own client-side TNS/TTC/O5Logon implementation**, so we control every bit of the upstream session state and can match it to the client's negotiated state.

Scope (realistic):
- Port go-ora's client-side handshake logic into our own `upstream.go`
- Interleave client and upstream negotiation: read client's CONNECT → forward to upstream → forward ACCEPT back → etc.
- Intercept O5Logon specifically: decrypt client's AUTH_SESSKEY (with placeholder key), re-encrypt with real-password-derived key, forward to upstream; same for phase 2 AUTH_PASSWORD
- After auth, both sides are in matching state because we forwarded the same negotiation bytes to both
- Relay post-auth bytes transparently

This is substantial work. Estimate: **1–2 weeks of focused engineering**, plus ongoing maintenance for every new Oracle version and client-driver release (see StrongDM's release-note cadence as reference).

### Exhaustion checklist

Things we tried or thoroughly considered:
- ✅ Fix every pre-auth protocol bug we could find (done — auth succeeds for both go-ora and sqlcl)
- ✅ Mirror upstream's session metadata (all 47 phase-2 KVPs: AUTH_SESSION_ID, AUTH_SERIAL_NUM, NLS params, DB identity) to the client's phase-2 response (done — no effect on relay)
- ✅ Tested whether session ID/serial mismatch alone was the issue (no — fixing them didn't help)
- ✅ Tested whether ANO negotiation was wrapping packets asymmetrically (no — disabling ANO levels changed nothing)
- ✅ Researched all major PAM vendors' Oracle approaches (CyberArk SIA/PSM, StrongDM, Teleport, Delinea, BeyondTrust, HashiCorp Boundary — no fourth architecture exists)
- ✅ Searched for open-source Oracle proxies, honeypots, protocol analyzers we could reference (found ODAT, SpiderLabs net-tns, redwood spec, britus Wireshark dissector — none implement upstream re-auth with downstream impersonation; Teleport is the closest peer and it sidesteps the problem via cert auth)
- ✅ Checked go-ora's public API for ways to manipulate session state externally (only `Connection.SessionProperties` is exposed; sequence numbers, compile-time caps, UseBigClrChunks, ClrChunkSize are all private)

No cheap win remains. The state-mismatch is a fundamental consequence of using an existing client library for upstream. Every piece of go-ora's internal session state we'd need to match is either private or set during negotiation and not adjustable after the fact.

### Why this is a reasonable stopping point for THE MASK (if we stop)

- The handshake-plus-auth surface is proven viable (our `handshake_test.go` passes end-to-end for go-ora; sqlcl reaches and completes auth against the real gateway).
- The architectural blocker is understood and reproducible.
- The fix is well-defined but expensive (1–2+ weeks).
- The research confirms no external shortcut exists — even StrongDM had to build this themselves and maintain it with a dedicated team.
- **PASS (cert-based auth, Teleport's approach) is the pragmatic alternative** — it sidesteps this entire class of problems by avoiding upstream re-auth. It requires one-time customer DBA setup per Oracle DB but has vastly lower ongoing complexity.

### Medium priority
1. **Per-client profile detection** — different clients send slightly different request shapes (sqlcl sends 23-byte TCPNego with protocol list `05 04 03 02 01 00` before banner; go-ora sends 18-byte TCPNego without). Current static TCPNego response works for both so far, but may need splitting if we see future divergences.
2. **OCI (sqlplus/Toad) support** — untested. OCI uses a different client library than JDBC thin. The dynamic DataType Nego should adapt automatically but there may be other protocol-shape differences.
3. **Auth phase 1 response hardening** — currently sends a byte-for-byte RDS-captured trailing summary with a fixed sequence number `0x1A98`. Works for both go-ora and sqlcl so far but may need dynamic derivation for some clients.

### Medium priority
4. **OCI (sqlplus/Toad) support** — untested. OCI uses a different client library than JDBC thin. The dynamic DataType Nego should adapt automatically but there may be other protocol-shape differences.
5. **Auth phase 1 response hardening** — the captured trailing summary bytes are byte-for-byte correct for go-ora. JDBC and OCI may parse it differently; verify against each.
6. **Character set conversion** — we pass `AL32UTF8` only. Non-UTF-8 targets will break (StrongDM hit this in Nov 2025).

### Lower priority (but eventually needed)
7. **NNE termination** — StrongDM ships this as a separate resource type. When a customer requires `SQLNET.ENCRYPTION_CLIENT=REQUIRED`, the gateway must decrypt/re-encrypt rather than refuse. ~1000 LOC of crypto + state machine.
8. **Oracle RAC via SCAN** — single-host only in v1. RAC customers must use a specific VIP.
9. **Query logging hardening** — current `query_logger.go` handles OALL8/OFETCH/OCOMMIT; add OROLLBACK, OLOBOPS, bundled RPC calls.

## 12. Remaining work for THE PASS

Different shape of work — less protocol engineering, more infrastructure.

### High priority
1. **Oracle CA infrastructure** — new CA per org, scoped to Oracle targets. May be able to reuse existing Infisical cert-signing infrastructure if there is one.
2. **Per-session cert issuance** — on `pam db access`, CLI receives a short-lived cert signed by the Oracle CA with CN set to the Infisical user.
3. **CLI wallet generator** — CLI writes `cwallet.sso` + `tnsnames.ora` into a session-scoped temp dir. Prints `export TNS_ADMIN=<dir>` for the user.
4. **TCPS proxy** — gateway terminates incoming TLS from CLI, re-establishes TLS upstream with the session cert. Byte-relays post-TLS-auth.

### Medium priority
5. **DBA setup script / docs** — one-time per Oracle DB. Teleport's pattern: `tctl auth sign --format=oracle` generates the server wallet. We'd ship equivalent: an Infisical command that emits an Oracle wallet containing our CA + setup instructions for `listener.ora`, `sqlnet.ora`, and creating users as `IDENTIFIED EXTERNALLY AS 'CN=<user>'`.
6. **Autonomous DB / RDS support** — these have their own wallet-config paths. Document the specifics.

### What we'd delete
- All protocol impersonation code (TNS codec, O5Logon, nego handlers, DataType Nego) — ~2,000 LOC of current work.
- `nego_templates.go`
- The `handshake_test.go` test harness

### What we'd keep
- Backend resource/account schema (~70% reusable, need to swap password fields for cert config)
- Frontend resource form (~70% reusable)
- CLI subcommand structure
- Upstream dial via go-ora (used for initial connection validation; may or may not be retained post-redesign)
- Session recording tap (can parse TTC read-only, same as Teleport does, for audit logging)

## 13. How to run the current tests

### Handshake test (current state, demonstrates 2/4 stages working for go-ora)

```bash
cd /path/to/cli.oracle-db
ORACLE_HANDSHAKE_TEST=1 go test -count=1 -run TestHandshakeAgainstGoOra \
  ./packages/pam/handlers/oracle/... -v -timeout 30s
```

Expected output: test reaches TCPNego response, go-ora rejects with `server compile time caps length less than 8`. This confirms:
- CONNECT/ACCEPT works
- Connect-data supplement drain works
- ANO refusal works
- TCPNego request parsing works
- (Blocked on TCPNego response content bug)

### Full gateway + CLI end-to-end (against real Oracle)

Requires existing PAM resource `aws-oracledb` with account `admin` in backend. From prior work — may have been cleaned up.

```bash
# Terminal 1 — gateway
go run main.go gateway start local-pat-g2-1 \
  --enroll-method=token --token=gwe_... \
  --target-relay-name=local-pat-1 \
  --domain=https://oracle-db.test \
  --pam-session-recording-path=./sessionrecordings

# Terminal 2 — CLI proxy
go run main.go pam db access --resource aws-oracledb --account admin \
  --project-id <uuid> --duration 4h --domain https://oracle-db.test

# Terminal 3 — client
sql admin/infisical-pam-proxy@localhost:<port>/DATABASE
```

## 14. Recommended path for the fork

If committing to **THE MASK**:

1. Start with dynamic DataType Nego. Port python-oracledb's `DATA_TYPES` table. This is the concrete, well-scoped piece of work that gets us past the current blocker for JDBC.
2. Debug the go-ora TCPNego template issue. Should be hours, not days.
3. Verify end-to-end against go-ora (easiest because we captured templates from go-ora).
4. Extend to JDBC thin (sqlcl / SQL Developer / DBeaver). Expect per-client response shaping.
5. Extend to OCI (sqlplus / Toad). Separate test profile.
6. Hardening: char sets, NNE, more query logger coverage.

If committing to **THE PASS**:

1. Delete `packages/pam/handlers/oracle/{tns.go, ttc.go, nego.go, nego_templates.go, o5logon*.go, ano.go, handshake_test.go}`.
2. Keep `proxy.go` skeleton, `upstream.go`, `query_logger.go`, `constants.go`.
3. Build Oracle CA infrastructure in `backend/`.
4. Add per-session cert issuance on `/api/v1/pam/accounts/access`.
5. Add CLI wallet generator to `packages/pam/local/database-proxy.go`.
6. Replace upstream dial path with TCPS-with-cert instead of password auth.
7. Draft DBA setup script.

## 15. References

### Primary
- [python-oracledb data_types.pyx](https://github.com/oracle/python-oracledb/blob/main/src/oracledb/impl/thin/messages/data_types.pyx) — Oracle-authored type table
- [sijms/go-ora](https://github.com/sijms/go-ora) — pure-Go Oracle driver, client-side reference for TNS/TTC/O5Logon
- [Teleport RFD 0115](https://github.com/gravitational/teleport/blob/master/rfd/0115-oracle-db-access-integration.md) — cert-based Oracle proxy architecture

### Secondary
- [StrongDM Oracle docs](https://docs.strongdm.com/admin/resources/datasources/oracle) — what production protocol-injection Oracle looks like (surface only)
- [StrongDM release notes](https://docs.strongdm.com/changelog/release-notes) — indirect evidence of implementation decisions via bug fixes
- [CyberArk SIA Oracle ZSP](https://docs.cyberark.com/ispss-access/latest/en/content/db/dpa-database-manage-zsp.htm) — ephemeral-user approach details
- [SpiderLabs/net-tns](https://github.com/SpiderLabs/net-tns) — Ruby Oracle client library, DTY request builder
- [Wireshark packet-tns.c](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-tns.c) — TNS framing dissector

### Background
- [Passive Capture and Analysis of Oracle Network Traffic (NYOUG 2008)](https://www.nyoug.org/Presentations/2008/Sep/Harris_Listening%20In.pdf) — general TNS protocol overview
- [Oracle error index](https://docs.oracle.com/error-help/) — for decoding ORA-* errors seen during debugging

---

*Document generated 2026-04-21 after ~2 weeks of implementation attempts and research. Forks should update as findings evolve.*
