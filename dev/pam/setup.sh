#!/usr/bin/env bash
# Register the running PAM resources + accounts with a local Infisical instance.
# Usage: ./setup.sh               # full flow: login, resolve gateway, create resources + accounts, print access snippets
#        ./setup.sh --print-info-only   # just print the plain connection table

set -euo pipefail

PRINT_INFO_ONLY=0
if [[ "${1:-}" == "--print-info-only" ]]; then
  PRINT_INFO_ONLY=1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

if [[ ! -f .env ]]; then
  echo "Missing .env. Run: cp .env.example .env && edit it." >&2
  exit 1
fi
# shellcheck disable=SC1091
set -a; . ./.env; set +a

for cmd in curl jq docker; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Required command '$cmd' not found on PATH." >&2; exit 1; }
done

# -----------------------------------------------------------------------------
# Static spec table: compose service -> (enable_flag, api_type, host_port, ssh_auth)
# ssh_auth is empty for non-SSH services.
# -----------------------------------------------------------------------------
SERVICES=(
  "postgres|ENABLE_POSTGRES|postgres|55432|"
  "mysql|ENABLE_MYSQL|mysql|55433|"
  "mssql|ENABLE_MSSQL|mssql|55434|"
  "mongodb|ENABLE_MONGODB|mongodb|55437|"
  "redis|ENABLE_REDIS|redis|55479|"
  "redis-noauth|ENABLE_REDIS_NOAUTH|redis|55480|"
  "ssh-server-password|ENABLE_SSH_PASSWORD|ssh|55422|password"
  "ssh-server-key|ENABLE_SSH_KEY|ssh|55423|publicKey"
)

# Which API resource types support a web-access page.
web_supported() {
  case "$1" in
    postgres|redis|ssh) return 0 ;;
    *) return 1 ;;
  esac
}

running_services() {
  docker compose ps --status running --format json 2>/dev/null \
    | jq -r 'if type == "array" then .[] else . end | .Service' 2>/dev/null \
    || true
}

# Is the given compose service currently running?
is_running() {
  local svc="$1"
  running_services | grep -qx "$svc"
}

# -----------------------------------------------------------------------------
# Connection info table
# -----------------------------------------------------------------------------
print_info() {
  local rows=()
  for entry in "${SERVICES[@]}"; do
    IFS='|' read -r svc _flag _type port ssh_auth <<<"$entry"
    is_running "$svc" || continue
    case "$svc" in
      postgres|mysql|mongodb)
        rows+=("$(printf '%-20s  %-9s  %-5s  %-9s  %-9s  %s' "$svc" "127.0.0.1" "$port" "infisical" "Infisical@123" "db=infisical")") ;;
      mssql)
        rows+=("$(printf '%-20s  %-9s  %-5s  %-9s  %-9s  %s' "$svc" "127.0.0.1" "$port" "infisical" "Infisical@123" "db=infisical")") ;;
      redis)
        rows+=("$(printf '%-20s  %-9s  %-5s  %-9s  %-9s  %s' "$svc" "127.0.0.1" "$port" "infisical" "Infisical@123" "")") ;;
      redis-noauth)
        rows+=("$(printf '%-20s  %-9s  %-5s  %-9s  %-9s  %s' "$svc" "127.0.0.1" "$port" "-" "-" "")") ;;
      ssh-server-password)
        rows+=("$(printf '%-20s  %-9s  %-5s  %-9s  %-9s  %s' "$svc" "127.0.0.1" "$port" "infisical" "Infisical@123" "")") ;;
      ssh-server-key)
        rows+=("$(printf '%-20s  %-9s  %-5s  %-9s  %-9s  %s' "$svc" "127.0.0.1" "$port" "infisical" "(pubkey)" "key: docker compose exec ssh-server-key cat /ssh-keys/id_ed25519")") ;;
    esac
  done

  echo ""
  echo "PAM dev stack — connection details:"
  echo ""
  printf '%-20s  %-9s  %-5s  %-9s  %-9s  %s\n' "resource" "host" "port" "user" "password" "extras"
  if (( ${#rows[@]} > 0 )); then
    for r in "${rows[@]}"; do echo "$r"; done
  else
    echo "(no services currently running — 'make up' brings them up)"
  fi
  echo ""
}

if (( PRINT_INFO_ONLY )); then
  print_info
  exit 0
fi

# -----------------------------------------------------------------------------
# Validate config
# -----------------------------------------------------------------------------
: "${INFISICAL_TOKEN:?INFISICAL_TOKEN is required in .env}"
: "${INFISICAL_DOMAIN:?INFISICAL_DOMAIN is required in .env}"
: "${INFISICAL_PROJECT_ID:?INFISICAL_PROJECT_ID is required in .env}"
RESOURCE_PREFIX="${RESOURCE_PREFIX:-local01}"

AUTH_HEADER="Authorization: Bearer ${INFISICAL_TOKEN}"
PREFIX="${RESOURCE_PREFIX}-$(date +%F)"

# -----------------------------------------------------------------------------
# Gateway ID — required by the Infisical PAM create-resource endpoints
# -----------------------------------------------------------------------------
if [[ -z "${INFISICAL_GATEWAY_ID:-}" ]]; then
  echo "INFISICAL_GATEWAY_ID is not set. Fetching gateways from ${INFISICAL_DOMAIN} ..."
  # PAM uses gatewayV2Service, so list v2 gateways — v1 IDs won't validate.
  gw_resp=$(curl -sS -H "$AUTH_HEADER" "${INFISICAL_DOMAIN}/api/v2/gateways/")
  if ! echo "$gw_resp" | jq -e 'type == "array"' >/dev/null 2>&1; then
    echo "Failed to list gateways. Response:" >&2
    echo "$gw_resp" >&2
    exit 1
  fi
  echo "Available gateways:"
  echo "$gw_resp" | jq -r '.[] | "  \(.id)  \(.name)"'
  echo ""
  echo "Paste one of those IDs into .env as INFISICAL_GATEWAY_ID and rerun." >&2
  exit 1
fi

# -----------------------------------------------------------------------------
# Helpers for API calls
# -----------------------------------------------------------------------------
post_json() {
  local url="$1" body="$2"
  curl -sS -w $'\n%{http_code}' -X POST "$url" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d "$body"
}

# Try a POST; echo the response body on success; on conflict or failure, bail.
create_or_bail() {
  local label="$1" url="$2" body="$3"
  local resp http_code body_only
  resp=$(post_json "$url" "$body")
  http_code=$(echo "$resp" | tail -n1)
  body_only=$(echo "$resp" | sed '$d')
  if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
    echo "$body_only"
    return 0
  fi
  if echo "$body_only" | grep -q 'already exists'; then
    echo "" >&2
    echo "Conflict: $label already exists in Infisical." >&2
    echo "Bump RESOURCE_PREFIX in .env (e.g. 'local02') and rerun 'make setup'." >&2
    exit 1
  fi
  echo "Failed to create $label (HTTP $http_code):" >&2
  echo "$body_only" >&2
  exit 1
}

# -----------------------------------------------------------------------------
# Build payloads per resource type and POST
# -----------------------------------------------------------------------------
metadata_tag='[{"key":"source","value":"LocalPAM"}]'

created=()  # "svc|api_type|resource_id|resource_name|account_id|account_name|web_supported"

register_one() {
  local svc="$1" api_type="$2" port="$3" ssh_auth="$4"
  local resource_name="${PREFIX}-${svc}"
  local account_name="${resource_name}-account"

  # -- Build connectionDetails JSON --
  local conn
  case "$api_type" in
    postgres|mysql|mssql)
      conn=$(jq -n --arg port "$port" \
        '{host:"127.0.0.1", port:($port|tonumber), database:"infisical", sslEnabled:false, sslRejectUnauthorized:false}')
      ;;
    mongodb)
      conn=$(jq -n --arg cs "mongodb://127.0.0.1:$port" \
        '{connectionString:$cs, database:"infisical", sslEnabled:false, sslRejectUnauthorized:false}')
      ;;
    redis)
      conn=$(jq -n --arg port "$port" \
        '{host:"127.0.0.1", port:($port|tonumber), sslEnabled:false, sslRejectUnauthorized:false}')
      ;;
    ssh)
      conn=$(jq -n --arg port "$port" \
        '{host:"127.0.0.1", port:($port|tonumber)}')
      ;;
  esac

  local res_body
  res_body=$(jq -n \
    --arg projectId "$INFISICAL_PROJECT_ID" \
    --arg gatewayId "$INFISICAL_GATEWAY_ID" \
    --arg name "$resource_name" \
    --argjson conn "$conn" \
    --argjson meta "$metadata_tag" \
    '{projectId:$projectId, gatewayId:$gatewayId, name:$name, connectionDetails:$conn, metadata:$meta}')

  local res_resp resource_id
  res_resp=$(create_or_bail "resource $resource_name" \
    "${INFISICAL_DOMAIN}/api/v1/pam/resources/${api_type}/" "$res_body")
  resource_id=$(echo "$res_resp" | jq -r '.resource.id // .id')

  # -- Build account credentials JSON --
  local creds
  case "$api_type" in
    postgres|mysql|mssql|mongodb)
      creds='{"username":"infisical","password":"Infisical@123"}' ;;
    redis)
      if [[ "$svc" == "redis-noauth" ]]; then
        creds='{"username":"","password":""}'
      else
        creds='{"username":"infisical","password":"Infisical@123"}'
      fi
      ;;
    ssh)
      case "$ssh_auth" in
        password)
          creds='{"authMethod":"password","username":"infisical","password":"Infisical@123"}' ;;
        publicKey)
          key_content=$(docker compose exec -T ssh-server-key cat /ssh-keys/id_ed25519 2>/dev/null || true)
          if [[ -z "$key_content" ]]; then
            echo "Could not read /ssh-keys/id_ed25519 from ssh-server-key container. Is it running?" >&2
            exit 1
          fi
          creds=$(printf '%s' "$key_content" | jq -Rs '{authMethod:"public-key", username:"infisical", privateKey:.}')
          ;;
      esac
      ;;
  esac

  local acc_body
  acc_body=$(jq -n \
    --arg resourceId "$resource_id" \
    --arg name "$account_name" \
    --argjson creds "$creds" \
    --argjson meta "$metadata_tag" \
    '{resourceId:$resourceId, name:$name, credentials:$creds, description:"LocalPAM", metadata:$meta}')

  local acc_resp account_id
  acc_resp=$(create_or_bail "account $account_name" \
    "${INFISICAL_DOMAIN}/api/v1/pam/accounts/${api_type}/" "$acc_body")
  account_id=$(echo "$acc_resp" | jq -r '.account.id // .id')

  local web_flag="no"
  web_supported "$api_type" && web_flag="yes"
  created+=("${svc}|${api_type}|${resource_id}|${resource_name}|${account_id}|${account_name}|${web_flag}")
  echo "  ok: ${resource_name} + ${account_name}"
}

echo ""
echo "Prefix: ${PREFIX}"
echo "Registering resources in Infisical ..."

any_registered=0
for entry in "${SERVICES[@]}"; do
  IFS='|' read -r svc _flag api_type port ssh_auth <<<"$entry"
  is_running "$svc" || continue
  register_one "$svc" "$api_type" "$port" "$ssh_auth"
  any_registered=1
done

if (( ! any_registered )); then
  echo "No eligible running services to register. Bring them up with 'make up' first."
  exit 0
fi

# -----------------------------------------------------------------------------
# Print access snippets per account
# -----------------------------------------------------------------------------
echo ""
echo "Access snippets:"
if [[ -z "${INFISICAL_ORG_ID:-}" ]]; then
  echo "  (set INFISICAL_ORG_ID in .env to also get web-access URLs)"
fi
echo ""

cli_verb_for() {
  case "$1" in
    postgres|mysql|mssql|mongodb) echo "db access" ;;
    redis) echo "redis access" ;;
    ssh) echo "ssh access" ;;
    *) echo "" ;;
  esac
}

for row in "${created[@]+${created[@]}}"; do
  IFS='|' read -r svc api_type rid rname aid aname web_flag <<<"$row"
  verb=$(cli_verb_for "$api_type")
  echo "${svc} (${rname} / ${aname})"
  if [[ -n "$verb" ]]; then
    echo "  CLI:  go run main.go pam ${verb} --resource ${rname} --account ${aname} --project-id ${INFISICAL_PROJECT_ID} --duration 1h --domain ${INFISICAL_DOMAIN}"
  fi
  if [[ "$web_flag" == "yes" && -n "${INFISICAL_ORG_ID:-}" ]]; then
    echo "  Web:  ${INFISICAL_DOMAIN}/organizations/${INFISICAL_ORG_ID}/projects/pam/${INFISICAL_PROJECT_ID}/resources/${api_type}/${rid}/accounts/${aid}/access"
  fi
  echo ""
done

print_info
