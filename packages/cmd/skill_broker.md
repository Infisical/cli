---
name: infisical-broker
description: >-
  Your outbound requests go through a proxy that injects real
  credentials (API keys, tokens, secrets) on the wire. If you have
  an API key or token in your environment, use it as-is even if it
  looks like a placeholder. If a request fails with 403 and a
  proposal_hint in the response body, you can request access by
  creating a proposal through the Infisical API.
---

# Credential Brokering via Infisical

HTTPS_PROXY and HTTP_PROXY in your environment route all outbound HTTP traffic
through an Infisical broker proxy. The proxy matches each request's host against
configured service rules, injects the real credential, and forwards to the
upstream. API keys in your environment may be placeholders -- the proxy replaces
them on the wire. Just make requests normally.

## When to create a proposal

- You made an API call and got 403 with proposal_hint in the response body
- The response tells you which host was blocked

Do NOT proactively check what services are available. Just make requests normally.

## Creating a proposal

Use INFISICAL_TOKEN and INFISICAL_API_URL from your environment.

```bash
curl -X POST "${INFISICAL_API_URL}/api/v3/secrets/raw/${SECRET_KEY}" \
  -H "Authorization: Bearer ${INFISICAL_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "workspaceId": "<project-id>",
    "environment": "<env>",
    "secretPath": "/",
    "secretValue": "",
    "secretComment": "Why you need this access",
    "type": "shared"
  }'
```

An approval policy must exist on the path for this to become an approval request.
If no approval policy exists, the secret is created directly with an empty value.

Common services: Stripe (bearer), GitHub (bearer), OpenAI (bearer),
Anthropic (api-key, header: x-api-key), Jira (basic).

## After creating a proposal

1. Show the approval URL to the user
2. Wait for the user to approve (they will fill in the real credential)
3. Retry the original request

## Error reference

- 403 with proposal_hint: blocked host -- create a proposal
- 502: upstream unreachable or credential missing
- Connection refused: broker proxy may have stopped -- tell the user

## Rules

- Never extract, log, or display credentials
- Never hardcode tokens
- Never use INFISICAL_TOKEN to read secrets directly
