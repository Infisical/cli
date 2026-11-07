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
- **Workflow commands** act on a whole environment rather than one resource: `run` sits directly under the product, and `export` under the resource it writes out (`secrets-manager secrets export`). Agent Vault also has `agent-vault proxy`, which runs the proxy, and `agent-vault connect`, which opens local ports to a session's database and SSH services.
- **Lifecycle actions** are for long-running things such as agents and services: `start`, `stop`, `install`, `uninstall`.
- **Other resource actions** cover what CRUD can't say: `revoke` ends something that keeps existing (`agent-vault sessions revoke`), and `push` uploads a local copy (`agent-vault skills push`).

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
- The same goes for the message: name something the user typed with `quoted(value, kind)`, which prints `<kind>` for anything that isn't a safe identifier, so a credential pasted in the wrong place never reaches a log. Well-known token formats that would otherwise pass as a name (`ghp_...`, `sk_live_...`, `xoxb-...`, `AKIA...`) are recognized by prefix and length and treated the same way. To cover a new one, add it to `knownTokenFormat` in `packages/util/cli_error.go`. `WriteCLIError` also redacts anything credential-shaped in the message and in the suggestions, including text the CLI doesn't control, such as the backend's own message or a project's name.
- If no command can fix the error, the first sentence says what to do instead.
- The exit code stays `1`.

### How to return one

- Return a `*util.CLIError` (`packages/util/cli_error.go`) from one of the constructors in `packages/cmd/secrets_manager_errors.go` (Agent Vault's are in `packages/cmd/agent_vault_errors.go`), and print it with `exitWithError(cmd, err)`. That function picks text, JSON, or YAML from `-o`, and exits `1`.
- Pass API errors through `classifyAPIError(err, scope, notFound)`. It uses only what is stable: the status code, the error names the backend guarantees (`TokenError`, `PermissionDenied`, `ProjectMembershipNotFound`), and, for a 404, the `notFound` error the caller passes when the request had one subject (an environment by slug, a project by ID). `scope` is the `errorScope` the command was working on. A 403 `ProjectMembershipNotFound` becomes `project_not_found` for the project `scope` names, so someone who isn't a member is told the same as for a project that doesn't exist, and the project's ID isn't echoed back. It never reads the message text, which the backend can reword at any time. Any other error comes back unchanged and prints as it always did, including the backend's own message.
- A backend error that can only be told apart by its message (a slug that's taken, delete protection, a plan limit) has no code until the backend gives it a stable error name. Never match on message text to add one.
- Build every value in a suggested command with `util.SuggestedValue` (or `util.SuggestedDomain` for `--domain`). Anything that isn't a UUID, slug, secret name, or folder path becomes a `<placeholder>`.
- To add a code, add a constant, a constructor, and a row to this table. The tests fail if a code isn't listed here, or if this table lists one that doesn't exist.

| Code | When |
| --- | --- |
| `auth_required` | No session, or the token is invalid or expired (401, or 403 `TokenError`) |
| `permission_denied` | The role doesn't allow the action (403) |
| `project_not_linked` | No `--projectId`, no `INFISICAL_PROJECT_ID`, and no `.infisical.yaml` |
| `project_config_invalid` | The directory's `.infisical.yaml` (or a legacy `.infisical.json`) exists but can't be read. Suggests `infisical init` |
| `project_not_found` | The project doesn't exist, or the caller isn't a member of it (404, or 403 `ProjectMembershipNotFound`). For Agent Vault, also a project that isn't an Agent Vault one |
| `project_type_not_supported` | A project of another product was passed to a `secrets-manager` command |
| `environment_not_found` | The environment slug doesn't exist in the project (404) |
| `environment_exists` | `environments create` (or `update --slug`) with a slug an active environment has. Nothing is written |
| `environment_pending_deletion` | The slug belongs to an environment pending deletion, which keeps it until the grace period ends. Suggests `delete --force` |
| `invalid_flag_value` | A flag is missing or was given a value the command can't use, such as an empty `--name`, or a `--file` that doesn't exist, can't be parsed, or has a secret with no value. Nothing is sent |
| `service_token_not_supported` | A service token was used with a command whose API routes reject service tokens. Suggests the alternative that works |
| `token_project_mismatch` | `secrets create` or `update` with a service token for a different project than the one selected. Nothing is written |
| `invalid_argument` | An argument the command can't use, such as the same secret name given twice to `secrets create`, or a secret with no name or no value, or a name that starts with a number. Nothing is written |
| `project_delete_protected` | `projects delete` on a project with delete protection on, read from its settings. Nothing is deleted |
| `project_required` | A delete ran without `--projectId`. Deletes never use `INFISICAL_PROJECT_ID` or `.infisical.yaml`. For Agent Vault, no project from `--project-id`, `INFISICAL_AGENT_VAULT_PROJECT_ID` or `INFISICAL_PROJECT_ID` |
| `invalid_project_id` | An Agent Vault project ID from `--project-id` or a variable isn't a project ID |
| `access_bundle_required` | `agent-vault sessions create` without `--access-bundle` or `INFISICAL_AGENT_VAULT_ACCESS_BUNDLE` |
| `access_bundle_not_granted` | `agent-vault sessions create` with an access bundle the caller (or the user a session is on behalf of) can't use, or that doesn't exist (400 `AccessBundleNotGranted`) |
| `invalid_access_bundle` | An access bundle name from `--access-bundle` or `INFISICAL_AGENT_VAULT_ACCESS_BUNDLE` isn't a valid name. Nothing is sent |
| `session_token_required` | `agent-vault connect` without `--session-token` or `INFISICAL_AGENT_VAULT_SESSION_TOKEN` |
| `proxy_required` | `agent-vault connect` without `--proxy` or `INFISICAL_AGENT_VAULT_PROXY_ADDRESS` |
| `proxy_unreachable` | `agent-vault connect` can't reach the Agent Vault proxy at the address, or a connection to it failed |
| `proxy_untrusted` | `agent-vault connect` can't verify the proxy's certificate authority from `agent-vault run`'s CA file or Infisical (which doesn't list fingerprints yet, can't be reached, or doesn't list this proxy), or it doesn't match `--ca-fingerprint`. The session token isn't sent to the proxy |
| `proxy_not_supported` | The Agent Vault proxy at the address predates database and SSH services |
| `no_services` | `agent-vault connect` for a session that has no database or SSH services |
| `service_not_found` | `agent-vault connect` names a service the session doesn't have. The message lists the ones it has |
| `service_refused` | The proxy refused a database or SSH service, for example because personal values aren't set or the stored SSH key can't be used, or it can't serve one right now. The message is the proxy's. With `connect --all`, only when it refused every service |
| `session_invalid` | `agent-vault connect` with a session that has ended, or that belongs to a different Agent Vault project than the proxy, as Infisical or the proxy reports it |
| `local_port_unavailable` | `agent-vault connect` can't open a port on 127.0.0.1, such as a `--port` another program holds |
| `secret_exists` | `secrets create` on a key that exists. Nothing is written |
| `secret_not_found` | `secrets update` on a key that doesn't exist. Nothing is written |
| `folder_not_found` | `folders get`, `update` or `delete` on a folder that doesn't exist at `--path` |
| `folder_exists` | `folders create` (or `update --name`) with a name another folder at `--path` has. Nothing is written |
| `nothing_to_update` | `update` called without any change flags |
| `confirmation_required` | A destructive command ran without a terminal and without `--yes` |
| `confirmation_declined` | The slug typed at the prompt didn't match, the prompt was cancelled, or the delete's environment, path or project changed while the prompt was open |

## Destructive commands

- Ask before deleting, by having the user type the slug or name of what's being deleted.
- `-y` / `--yes` skips the question, for scripts and agents.
- Without a terminal and without `--yes`, delete nothing. Fail with code `confirmation_required`, and suggest the same command with `--yes`.
- `--force` skips a safeguard, such as a soft-delete grace period. It never skips the question.
- A new destructive command never falls back to an implicit target (such as the project linked in `.infisical.yaml`).
- The existing deletes under `secrets-manager` (`secrets delete`, `secrets folders delete` and `dynamic-secrets lease delete`) also ask, but keep their project fallbacks (`INFISICAL_PROJECT_ID`, then `.infisical.yaml`) for compatibility. Their question names the project and where it came from. The suggested rerun pins the resolved `--env`, `--path` and `--projectId` when they weren't typed, so running it without the same variables or workspace file can't delete somewhere else. After the question is answered, they resolve their target again, and delete nothing if it changed (a rewritten `.infisical.yaml` or a new git branch). The legacy top-level copies (`infisical secrets delete`, ...) keep deleting without asking, so existing scripts keep working.
- The question goes to stderr, so `-o json` output stays clean when it's piped.

For a new command, add the flags with `addConfirmFlags(cmd)`, then call `confirmDestructive(cmd, args, destructiveAction{...})` before deleting (`packages/cmd/confirm.go`). For a delete whose builder is shared with a legacy top-level command, add it to `confirmedUnderSecretsManager` in `sm.go` with a function that describes what the arguments delete and where (`deleteProject`, plus the resolved environment and path in `Scope`). The suggested rerun repeats the command under its full name, with the same arguments and flags. Only flags that hold identifiers (`--projectId`, `--env`, `--path`, ...) keep their values, and only when the value is a safe identifier. Any other flag's value becomes a `<placeholder>`, and credential flags are left out. A domain from `INFISICAL_DOMAIN` or `.infisical.yaml` is added as `--domain`, so running the rerun elsewhere can't send a token from the environment to Infisical Cloud instead. To repeat a new identifier flag, add it to `rerunIdentifierFlags` in `confirm.go`.

## Backwards compatibility

- **Never remove or rename a command or a flag.** Hide it instead: `Hidden: true` on a command, or `MarkHidden` plus `MarkDeprecated` on a flag (see `--enrollment-token` in `packages/cmd/agent_vault.go`). It keeps working but leaves `--help`.
- **Never change a flag's short form, type, or default.**
- Don't hide a command before its replacement ships. A release can be cut at any commit.
- Don't add subcommands to the legacy top-level `secrets`, `run`, `export`, and `dynamic-secrets` commands. New Secrets Management commands go under `secrets-manager`.
- The legacy top-level `secrets`, `run`, `export`, and `dynamic-secrets` are hidden from `infisical --help` but keep working.

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
