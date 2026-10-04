---
name: infisical-secrets
description: Find, use, and save Infisical secrets without putting credential values in a coding agent's conversation. Use for Infisical credential discovery, command injection, and storing newly generated API keys.
---

# Infisical secrets for coding agents

Use `infisical secrets agent` instead of commands that print secret values. Authenticate with `infisical login` or an operator-provided machine identity access token in `INFISICAL_TOKEN`. Never read or repeat that token. These commands require a CLI version that includes the agent secret workflow.

## Find

```sh
infisical secrets agent find openai stripe --projectId PROJECT_ID --env dev --path /agents
```

Returns JSON with secret names, IDs, locations, and `infisical://` references. Values are not requested. Queries match secret names case-insensitively; multiple queries match any query. Discovery covers shared secrets in the selected folder only, not imports, personal secrets, or nested folders.

References include the Infisical instance and secret ID. Use them verbatim. Select `--domain` explicitly when working with a different instance; a reference never redirects authentication to another server.

## Use

```sh
infisical secrets agent run --secret 'OPENAI_API_KEY=REFERENCE_FROM_FIND' -- node application.js
```

Only selected secrets are injected, without writing a plaintext env file. Infisical authentication environment variables are removed from the child environment.

The application still receives plaintext credentials and its output is not redacted. Only launch trusted commands that won't print, log, or transmit their environment. Never run `env`, `printenv`, or a secret-printing script through this command. Do not inject credentials into the coding agent itself.

For agents that must not hold API credentials, use `infisical secrets agent-proxy run` for the sandboxed Secret Manager workflow, or `infisical agent-vault run` with a configured proxy and access bundle. Agent Vault does not itself sandbox the agent or strip the parent's environment.

## Save

```sh
credential-generator | infisical secrets agent save OPENAI_API_KEY --stdin --projectId PROJECT_ID --env dev --path /agents
```

Ask the user for the destination if they haven't selected one. Pipe the credential directly from its source; never use a command substitution, a secret argument, or a temporary plaintext file. Never capture the producer's output into the conversation.

Save creates a shared secret; it never updates an existing one. It removes one final stdin line ending and refuses empty values, NUL characters, or surrounding whitespace to avoid storing credentials this workflow can't inject or that server-side normalization would change. Input must be UTF-8 and at most 1 MiB. Clipboard input is not supported by this initial workflow.

Success returns a reference and `verified: true` after an internal read-back comparison. Nothing prints the value. Writes are never retried automatically. On an error, an approval requirement, or failed verification, use `find` to check the location before taking any further action. Don't repeat the write automatically.
