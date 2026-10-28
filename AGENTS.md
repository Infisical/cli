# AGENTS.md

This file provides guidance to coding agents working in this repository.

## Essential commands

- `go build -o infisical .`: build the CLI.
- `go test ./packages/...`: unit tests. CI runs a subset (see `.github/workflows/run-cli-tests.yml`), so run the packages you touched locally.
- `go test ./packages/cmd -run 'TestCommandSurfaceIsBackwardsCompatible|TestCommandConventions'`: the command guards described in [CLI.md](CLI.md).
- `go test ./test`: integration tests against a real Infisical instance. They need the `CLI_TESTS_*` environment variables and a binary built as `infisical-merge`.
- `e2e/`: a separate Go module with end-to-end suites (agent, PAM, proxy, relay). See `.github/workflows/run-cli-e2e-tests.yml` for how each one runs.

## Repository structure

- **`packages/cmd/`**: every cobra command. Secrets Management commands live under `infisical secrets-manager` (alias `sm`) in `sm.go`. The same builders also register the legacy top-level `secrets`, `run`, `export`, and `dynamic-secrets`.
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

## Issue and PR guidelines

- Never create a GitHub issue.
- When creating a pull request, use and fully complete `.github/pull_request_template.md`.

## Keeping AGENTS.md up to date

When a change adds a package, a cross-cutting pattern, or a new convention, update this file (and [CLI.md](CLI.md) for command conventions) so future sessions start with correct context.
