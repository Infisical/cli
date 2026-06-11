---
name: infisical-broker
description: >-
  Your outbound requests go through a proxy that injects real
  credentials (API keys, tokens, secrets) on the wire. If you have
  an API key or token in your environment, use it as-is even if it
  looks like a placeholder. If a request fails with 403 and a
  proposal_hint in the response body, you can request access by
  creating a proposal through the broker.
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

When you get a 403 from the proxy, create a proposal by calling the broker
directly. The broker handles authentication with Infisical.

```bash
curl -s -X POST http://localhost:14322/_internal/propose \
  -H "Content-Type: application/json" \
  -d '{
    "secretKey": "OPENAI_API_KEY",
    "host": "api.openai.com",
    "authType": "bearer",
    "comment": "Need OpenAI API access for code generation"
  }'
```

Auth type fields:
- **bearer**: no extra fields needed
- **api-key**: include `"headerName": "x-api-key"`
- **basic**: include `"username": "user@company.com"`
- **custom**: include `"headerTemplate": "X-Token: {{ VALUE }}"`

Common services: Stripe (bearer), GitHub (bearer), OpenAI (bearer),
Anthropic (api-key, header: x-api-key), Jira (basic).

## After creating a proposal

1. Show the reviewUrl from the response to the user
2. A human will review and fill in the real credential
3. The broker picks up the new config automatically
4. Retry your original request

## Discovering available services

```bash
curl -s http://localhost:14322/_internal/discover
```

Returns a list of configured hosts and their auth types.

## Error reference

- 403 with proposal_hint: blocked host -- create a proposal
- 502: upstream unreachable or credential missing
- Connection refused: broker proxy may have stopped -- tell the user

## Rules

- Never extract, log, or display credentials
- Never hardcode tokens
