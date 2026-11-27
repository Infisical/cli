# AGENTS.md

This file provides guidance to coding agents working in this repository.

## Essential commands

- `go build -o infisical .`: build the CLI.
- `go test ./packages/cmd -run 'TestCommandSurfaceIsBackwardsCompatible|TestCommandConventions'`: the command guards described in [CLI.md](CLI.md).
- `go test ./test`: integration tests against a real Infisical instance. They need the `CLI_TESTS_*` environment variables and a binary built as `infisical-merge`.
- `e2e/`: a separate Go module with end-to-end suites (agent, PAM, proxy, relay). See `.github/workflows/run-cli-e2e-tests.yml` for how each one runs.

## Repository structure

- **`packages/cmd/`**: every cobra command. Secrets Management commands live under `infisical secrets-manager` (alias `sm`) in `sm.go`. The same builders also register the hidden legacy top-level `secrets`, `run`, `export`, and `dynamic-secrets`. Certificate Manager's one-shot commands (`cert-manager applications` and `cert-manager certificates`) live in `cert_manager.go`, beside the long-running `cert-manager agent` in `agent.go`.
- **`packages/api/`**: HTTP calls to the Infisical API and their request and response models.
- **`packages/util/`**: shared helpers. Flag and environment resolution (`helper.go`), `.infisical.yaml` handling (`config.go`), output formatting, and error printing (`log.go`).
- **`packages/visualize/`**: table output.
- **`packages/models/`**: config file and CLI models.
- Product packages: `agent`, `agentproxy`, `agentvault`, `gateway-v2`, `relay`, `pam`, `kmip`, `sandbox`, `telemetry`.

## Cross-cutting patterns

### Commands

**Read [CLI.md](CLI.md) before adding or changing a command or a flag.** It sets the command structure (`infisical <product> <resource> <action>`), the action vocabulary, the error format, delete confirmation, and the backwards-compatibility rules.

The short version: never remove or rename a command or flag (hide it instead), and record new ones in `packages/cmd/testdata/command_surface.json` with `-update-command-surface`.

### Telemetry

Short commands use `Telemetry.CaptureEvent`, which flushes before exiting. Use `CaptureEventAsync` only for commands that go on to run something long-lived; a short command that uses it loses the event. The opt-out (`--telemetry=false`, `INFISICAL_DISABLE_TELEMETRY`, `DO_NOT_TRACK`) is applied globally in `initTelemetry`.

### Code comments

**Default to no comments.** One earns its place only by explaining *why*: a non-obvious constraint, a workaround, an ordering dependency, or logic that looks wrong until you know the reason.

Never write: narration restating the next line; section headers inside a function; change history; references to plans, tickets, PRs, or reviewers; docstrings restating the signature; commented-out code.

### Agent Vault hooks

A hook (`packages/agentvault/hook.go`) is the customer's server, which the proxy asks before it brokers. Resolve sends at most one per service, as `services[].hook`, with optional narrowing: HTTP methods and path prefixes, or MCP tools. Ask it only for what that narrowing picks (`serviceHook.matches`); a hook with none, including the `{ url, secret }` older servers send, is asked about every request of its service, and a database or SSH service asks about every connection. Ask at most once per request or connection; an OAuth resend reuses the answer.

- Lean every matching decision toward asking, because a miss sends the request through unchecked. A method override header or a `_method` query parameter counts as the method it names, and a form POST (`_method` in the body) as any method; paths compare without case; an ambiguous path, its decoded form and the path after path substitutions all count against the prefixes; an MCP body that can't be read matches.
- Ask in `forward()` after the proxy's own checks and before substitutions, custom headers and the credential, so the payload holds only what the agent sent. Ask a database or SSH service once per connection, after `registerNative` and before the tunnel opens. Keep any new path that attaches a credential behind the same call.
- Fail closed once asked: anything but an `allow` or `deny` within 3 seconds refuses, and a hook the proxy can't use is a hook that always fails, never no hook.
- Never log the hook URL beyond `scheme://host`.

## Issue and PR guidelines

- Never create a GitHub issue.
- When creating a pull request, use and fully complete `.github/pull_request_template.md`.

## Keeping AGENTS.md up to date

When a change adds a package, a cross-cutting pattern, or a new convention, update this file (and [CLI.md](CLI.md) for command conventions) so future sessions start with correct context.
