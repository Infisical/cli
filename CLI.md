# CLI command conventions

Every new command, in any product, follows these rules. They exist so a person or an agent can read a command and predict what it does, and so a command line that works once keeps working.

`packages/cmd/conventions_test.go` checks the rules that can be checked mechanically, and `packages/cmd/compat_test.go` guards backwards compatibility. The rest is on the author and the reviewer.

## Structure

```
infisical <product> <resource> <action> [target] [flags]
infisical secrets-manager secrets get API_KEY --env prod
```

- **Product**: spelled out (`secrets-manager`, `cert-manager`), with at most one short alias (`sm`). Examples, help text, and suggested commands always use the full name.
- **Resource**: a plural noun (`secrets`, `folders`, `environments`, `projects`). A sub-resource nests under its parent: `<product> <resource> <sub-resource> <action>`.
- **Action**: `get`, `create`, `update`, or `delete`.
  - `get` without a name lists; `get <name>` shows one. Don't add a separate `list`.
  - `create` fails if the item exists, and `update` fails if it doesn't. Don't add upserts like `set`.
- **Workflow commands** act on a whole environment rather than one resource, and sit directly under the product: `run`, `export`.
- **Lifecycle actions** are for long-running things such as agents and services: `start`, `stop`, `install`, `uninstall`.

Adding a word to any of these lists is a design decision. Raise it in the PR, and update this file and `conventions_test.go` together.

## Arguments and flags

- **What you act on is positional**: `environments delete qa`, `projects get my-app`.
- **Where you act is a flag**: `--projectId`, `--env`, `--path`. These keep their existing names and fallbacks: the flag, then the environment variable, then `.infisical.yaml`.
- Every runnable command sets `Args` (`cobra.NoArgs`, `ExactArgs`, ...), so a stray argument is an error instead of being ignored.
- Every flag has a long form. Give a short form only to flags people type often, and never reuse a short form for a different meaning.

## Output

- Every `get`, `create`, `update`, and `delete` supports `-o json` and `-o yaml`.
- Data goes to stdout. Tips, warnings, and errors go to stderr, so `-o json` output can be piped.
- Respect `--silent` and structured output: don't print tips when either is set.

## Errors

A human-readable error is two sentences on stderr: what went wrong, then what to do next, ending with the command that does it.

```
Environment "stagng" doesn't exist in project payments-api.
To see the environments in this project, run: infisical secrets-manager environments get --projectId 6f1c2a3e-...
```

With `-o json`, the same error is JSON on stderr:

```json
{"error": {"code": "environment_not_found", "message": "...", "next": ["infisical secrets-manager environments get --projectId 6f1c2a3e-..."]}}
```

- `code` is stable snake_case. Codes are added, never renamed or removed.
- A suggested command is complete and runnable, and uses the full product name.
- A suggested command never contains a token or a secret value. Only interpolate values that are valid UUIDs or slugs, and write secret values as `<value>`.
- The same goes for the message: name something the user typed with `quoted(value, kind)`, which prints `<kind>` for anything that isn't a safe identifier, so a credential pasted in the wrong place never reaches a log.
- If no command can fix the error, the first sentence says what to do instead.
- The exit code stays `1`.

### How to return one

- Return a `*util.CLIError` (`packages/util/cli_error.go`) from one of the constructors in `packages/cmd/secrets_manager_errors.go`, and print it with `exitWithError(cmd, err)`. That function picks text, JSON, or YAML from `-o`, and exits `1`.
- Pass API errors through `classifyAPIError(err, notFound)`. It uses only what is stable: the status code, the error names the backend guarantees (`TokenError`, `PermissionDenied`), and, for a 404, the `notFound` error the caller passes when the request had one subject (an environment by slug, a project by ID). It never reads the message text, which the backend can reword at any time. Any other error comes back unchanged and prints as it always did, including the backend's own message.
- A backend error that can only be told apart by its message (a slug that's taken, delete protection, a plan limit) has no code until the backend gives it a stable error name. Never match on message text to add one.
- Build every value in a suggested command with `util.SuggestedValue` (or `util.SuggestedDomain` for `--domain`). Anything that isn't a UUID, slug, secret name, or folder path becomes a `<placeholder>`.
- To add a code, add a constant, a constructor, and a row to this table. The tests fail if a code isn't listed here, or if this table lists one that doesn't exist.

| Code | When |
| --- | --- |
| `auth_required` | No session, or the token is invalid or expired (401, or 403 `TokenError`) |
| `permission_denied` | The role doesn't allow the action (403) |
| `project_not_linked` | No `--projectId`, no `INFISICAL_PROJECT_ID`, and no `.infisical.yaml` |
| `project_not_found` | The project doesn't exist or isn't visible (404) |
| `project_type_not_supported` | A project of another product was passed to a `secrets-manager` command |
| `environment_not_found` | The environment slug doesn't exist in the project (404) |
| `secret_exists` | `secrets create` on a key that exists. Nothing is written |
| `secret_not_found` | `secrets update` on a key that doesn't exist. Nothing is written |
| `folder_not_found` | `folders get <name>` for a folder that doesn't exist |
| `nothing_to_update` | `update` called without any change flags |
| `confirmation_required` | A destructive command ran without a terminal and without `--yes` |
| `confirmation_declined` | The slug typed at the prompt didn't match, or the prompt was cancelled |

## Destructive commands

- Ask before deleting, by having the user type the slug or name of what's being deleted.
- `-y` / `--yes` skips the question, for scripts and agents.
- Without a terminal and without `--yes`, delete nothing. Fail with code `confirmation_required`, and suggest the same command with `--yes`.
- `--force` skips a safeguard, such as a soft-delete grace period. It never skips the question.
- A new destructive command never falls back to an implicit target (such as the project linked in `.infisical.yaml`).
- The existing deletes under `secrets-manager` (`secrets delete`, `secrets folders delete` and `dynamic-secrets lease delete`) also ask, but keep their project fallbacks (`INFISICAL_PROJECT_ID`, then `.infisical.yaml`) for compatibility. Their question names the project and where it came from, and the suggested rerun pins it with `--projectId`. The legacy top-level copies (`infisical secrets delete`, ...) keep deleting without asking, so existing scripts keep working.
- The question goes to stderr, so `-o json` output stays clean when it's piped.

For a new command, add the flags with `addConfirmFlags(cmd)`, then call `confirmDestructive(cmd, args, destructiveAction{...})` before deleting (`packages/cmd/confirm.go`). For a delete whose builder is shared with a legacy top-level command, add it to `confirmedUnderSecretsManager` in `sm.go` with a function that describes what the arguments delete, in which project (`deleteProject`). The suggested rerun repeats the command under its full name, with the same arguments and flags. Only flags that hold identifiers (`--projectId`, `--env`, `--path`, ...) keep their values, and only when the value is a safe identifier. Any other flag's value becomes a `<placeholder>`, and credential flags are left out. To repeat a new identifier flag, add it to `rerunIdentifierFlags` in `confirm.go`.

## Backwards compatibility

- **Never remove or rename a command or a flag.** Hide it instead: `Hidden: true` on a command, or `MarkHidden` plus `MarkDeprecated` on a flag (see `--enrollment-token` in `packages/cmd/agent_vault.go`). It keeps working but leaves `--help`.
- **Never change a flag's short form, type, or default.**
- Don't hide a command before its replacement ships. A release can be cut at any commit.
- Don't add subcommands to the legacy top-level `secrets`, `run`, `export`, and `dynamic-secrets` commands. New Secrets Management commands go under `secrets-manager`.

`testdata/command_surface.json` records every command path and flag the CLI has shipped. The test fails if one disappears or changes, and also when a new one isn't recorded yet. After adding a command or flag, record it:

```sh
go test ./packages/cmd -run TestCommandSurfaceIsBackwardsCompatible -update-command-surface
```

The update only adds entries. It never removes or changes a recorded one.

## Checklist for a new command

1. It fits `<product> <resource> <action>`, or is a workflow or lifecycle command.
2. `Short` starts with an imperative verb, and `Example` lines start with `infisical`.
3. `Args` is set. CRUD commands have `-o`. Destructive commands have `-y`/`--yes`.
4. Errors follow the two-sentence format, and suggested commands contain no secrets.
5. `go test ./packages/cmd -run 'TestCommandSurfaceIsBackwardsCompatible|TestCommandConventions'` passes.
