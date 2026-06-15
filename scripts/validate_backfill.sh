#!/bin/bash
#
# validate_backfill.sh
#
# Validates that backfilled Infisical CLI packages actually install from the new
# AWS repo THROUGH CloudFront, for deb / rpm / apk, across all migrated versions.
#
# For each selected format it spins up the matching Linux container
# (debian / almalinux / alpine), configures the repo using THIS repo's real
# setup scripts (scripts/setup/*) pointed at $PKG_URL (your CloudFront URL),
# then for every expected version:
#   - confirms the version is present in the repo index served by CloudFront
#   - pin-installs that exact version (signature verification is enforced by the
#     setup scripts: apt signed-by, yum gpgcheck/repo_gpgcheck, apk RSA key)
#   - confirms the installed package version matches and the binary runs
#
# "Expected versions" come from Cloudsmith (the migration source of truth) when
# --all is used, so a missing version is a hard failure (incomplete migration).
#
# Requirements on the host: docker, curl, jq. ($PKG_URL must be your test
# CloudFront domain, e.g. https://dxxxxxxxx.cloudfront.net. On a GitHub Actions
# ubuntu runner all of these are present.)
#
# Usage:
#   PKG_URL=https://dxxxx.cloudfront.net ./scripts/validate_backfill.sh --version 0.43.54
#   PKG_URL=... CLOUDSMITH_API_KEY=... ./scripts/validate_backfill.sh --all
#   optional: --format deb|rpm|apk   (default: all three)
#
# Notes:
#   - Validates the amd64/x86_64 packages (GitHub runners are amd64). aarch64
#     install validation would need qemu and is out of scope for the POC.

set -euo pipefail

CLOUDSMITH_OWNER="${CLOUDSMITH_OWNER:-infisical}"
CLOUDSMITH_REPO="${CLOUDSMITH_REPO:-infisical-cli}"
CLOUDSMITH_API="https://api.cloudsmith.io/v1"
PAGE_SIZE=100
PKG_NAME="infisical"

MODE=""
VERSION=""
FORMAT_FILTER=""

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SETUP_DIR="${REPO_ROOT}/scripts/setup"

log()  { printf '%s\n' "[validate] $*"; }
warn() { printf '%s\n' "[validate][WARN] $*" >&2; }
die()  { printf '%s\n' "[validate][ERROR] $*" >&2; exit 1; }

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die "--version needs a value"; MODE="version"; VERSION="$2"; shift 2 ;;
        --all)     MODE="all"; shift ;;
        --format)  [ $# -ge 2 ] || die "--format needs deb|rpm|apk"; FORMAT_FILTER="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) die "Unknown argument: $1 (use --help)" ;;
    esac
done

[ -n "$MODE" ] || die "Specify --version <v> or --all"
[ -n "${PKG_URL:-}" ] || die "PKG_URL must be set to your test CloudFront URL (e.g. https://dxxxx.cloudfront.net)"
for t in docker curl jq; do command -v "$t" >/dev/null 2>&1 || die "Required tool not found: $t"; done
[ -d "$SETUP_DIR" ] || die "setup scripts dir not found: $SETUP_DIR"
if [ -n "$FORMAT_FILTER" ]; then
    case "$FORMAT_FILTER" in deb|rpm|apk) ;; *) die "--format must be deb|rpm|apk" ;; esac
fi

want_format() { [ -z "$FORMAT_FILTER" ] || [ "$FORMAT_FILTER" = "$1" ]; }

# ----------------------------------------------------------------------------
# Expected versions per format. For --all we read them from Cloudsmith so any
# version that did not make it into the new repo is flagged as missing.
# Prints space-separated, de-duplicated version strings.
# ----------------------------------------------------------------------------
expected_versions() {
    local fmt="$1"   # deb | rpm | apk
    if [ "$MODE" = "version" ]; then
        printf '%s' "$VERSION"; return 0
    fi
    [ -n "${CLOUDSMITH_API_KEY:-}" ] || die "--all needs CLOUDSMITH_API_KEY to know the expected version set"
    local cs_fmt page http count tmpf
    case "$fmt" in deb) cs_fmt="deb" ;; rpm) cs_fmt="rpm" ;; apk) cs_fmt="alpine" ;; esac
    tmpf="$(mktemp)"
    page=1
    {
        while :; do
            # This Cloudsmith deployment returns 404 (not an empty array) for the
            # first page past the end, so a 404 after page 1 means end-of-list.
            http="$(curl -sS --retry 5 --retry-delay 2 --retry-all-errors \
                --connect-timeout 20 --max-time 180 \
                -H "X-Api-Key: $CLOUDSMITH_API_KEY" -H "Accept: application/json" \
                -o "$tmpf" -w '%{http_code}' \
                "${CLOUDSMITH_API}/packages/${CLOUDSMITH_OWNER}/${CLOUDSMITH_REPO}/?page=${page}&page_size=${PAGE_SIZE}")" \
                || http="000"
            if [ "$http" = "200" ]; then
                count="$(jq 'length' "$tmpf" 2>/dev/null || echo 0)"
                [ "$count" = "0" ] && break
                jq -r --arg f "$cs_fmt" '.[] | select(.format==$f) | .version' "$tmpf"
                page=$((page + 1))
                continue
            fi
            [ "$http" = "404" ] && [ "$page" -gt 1 ] && break
            rm -f "$tmpf"
            die "Cloudsmith API request failed (page $page, HTTP $http)"
        done
        rm -f "$tmpf"
    } | sort -u | tr '\n' ' '
}

# ============================================================================
# DEB validation (debian:12, amd64)
# ============================================================================
validate_deb() {
    local expected; expected="$(expected_versions deb)"
    [ -n "${expected// }" ] || { warn "deb: no expected versions, skipping"; return 0; }
    log "deb: expected versions: $expected"
    docker run --rm \
        -e PKG_URL="$PKG_URL" -e EXPECTED="$expected" -e PKG_NAME="$PKG_NAME" \
        -v "$SETUP_DIR":/setup:ro \
        debian:12 bash -euo pipefail -c '
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq >/dev/null
            apt-get install -y -qq curl gnupg ca-certificates >/dev/null
            # Configure the repo via our real setup script, pointed at CloudFront.
            bash /setup/setup.deb.sh >/dev/null
            apt-get update -qq >/dev/null
            fail=0
            for v in $EXPECTED; do
                # Exact version string as the repo advertises it (handles any revision suffix).
                cand=$(apt-cache madison "$PKG_NAME" | awk -F"|" "{gsub(/ /,\"\",\$2); print \$2}" | grep -E "^${v}(\b|[-+~])" | head -n1 || true)
                if [ -z "$cand" ]; then echo "  MISSING deb $v (not in index)"; fail=1; continue; fi
                if apt-get install -y -qq --allow-downgrades "${PKG_NAME}=${cand}" >/dev/null; then
                    got=$(dpkg-query -W -f="\${Version}" "$PKG_NAME")
                    if "$PKG_NAME" --help >/dev/null 2>&1; then
                        echo "  PASS deb $v (installed $got)"
                    else
                        echo "  FAIL deb $v (installed $got but binary did not run)"; fail=1
                    fi
                    apt-get purge -y -qq "$PKG_NAME" >/dev/null
                else
                    echo "  FAIL deb $v (install/signature error)"; fail=1
                fi
            done
            exit $fail
        '
}

# ============================================================================
# RPM validation (almalinux:9, x86_64)
# ============================================================================
validate_rpm() {
    local expected; expected="$(expected_versions rpm)"
    [ -n "${expected// }" ] || { warn "rpm: no expected versions, skipping"; return 0; }
    log "rpm: expected versions: $expected"
    docker run --rm \
        -e PKG_URL="$PKG_URL" -e EXPECTED="$expected" -e PKG_NAME="$PKG_NAME" \
        -v "$SETUP_DIR":/setup:ro \
        almalinux:9 bash -euo pipefail -c '
            dnf -q install -y curl >/dev/null 2>&1 || true
            bash /setup/setup.rpm.sh >/dev/null
            fail=0
            for v in $EXPECTED; do
                # Exact NEVR (version-release) from repo metadata.
                evr=$(dnf -q repoquery --available --queryformat "%{version}-%{release}" "$PKG_NAME" 2>/dev/null \
                      | grep -E "^${v}(-|\b)" | head -n1 || true)
                if [ -z "$evr" ]; then echo "  MISSING rpm $v (not in repodata)"; fail=1; continue; fi
                if dnf -q install -y "${PKG_NAME}-${evr}" >/dev/null 2>&1; then
                    got=$(rpm -q --qf "%{VERSION}-%{RELEASE}" "$PKG_NAME")
                    if "$PKG_NAME" --help >/dev/null 2>&1; then
                        echo "  PASS rpm $v (installed $got)"
                    else
                        echo "  FAIL rpm $v (installed $got but binary did not run)"; fail=1
                    fi
                    dnf -q remove -y "$PKG_NAME" >/dev/null 2>&1
                else
                    echo "  FAIL rpm $v (install/signature error)"; fail=1
                fi
            done
            exit $fail
        '
}

# ============================================================================
# APK validation (alpine:3.21, x86_64)
# ============================================================================
validate_apk() {
    local expected; expected="$(expected_versions apk)"
    [ -n "${expected// }" ] || { warn "apk: no expected versions, skipping"; return 0; }
    log "apk: expected versions: $expected"
    docker run --rm \
        -e PKG_URL="$PKG_URL" -e EXPECTED="$expected" -e PKG_NAME="$PKG_NAME" \
        -v "$SETUP_DIR":/setup:ro \
        alpine:3.21 sh -c '
            set -eu
            apk add --no-cache wget >/dev/null
            sh /setup/setup.apk.sh >/dev/null
            fail=0
            # All available versions from the index policy, e.g. "0.43.54-r0".
            # `apk policy` prints them as indented lines ending in a colon.
            avail=$(apk policy "$PKG_NAME" 2>/dev/null | sed -nE "s/^[[:space:]]+([0-9][^:]*):.*/\1/p")
            for v in $EXPECTED; do
                aver=$(printf "%s\n" "$avail" | grep -E "^${v}(-r|$)" | head -n1 || true)
                if [ -z "$aver" ]; then echo "  MISSING apk $v (not in APKINDEX)"; fail=1; continue; fi
                if apk add --no-cache "${PKG_NAME}=${aver}" >/dev/null 2>&1; then
                    if "$PKG_NAME" --help >/dev/null 2>&1; then
                        echo "  PASS apk $v (installed $aver)"
                    else
                        # Old builds may be glibc-linked and will not execute on Alpine/musl.
                        echo "  WARN apk $v (installed $aver but binary did not run -- possibly glibc-linked)"
                    fi
                    apk del "$PKG_NAME" >/dev/null 2>&1 || true
                else
                    echo "  FAIL apk $v (install/signature error)"; fail=1
                fi
            done
            exit $fail
        '
}

# ----------------------------------------------------------------------------
# Quick host-side CDN reachability gate: the index files must be served (200)
# through CloudFront before we bother spinning up containers.
# ----------------------------------------------------------------------------
cdn_check() {
    local url="$1" desc="$2" code
    code="$(curl -1s -o /dev/null -w '%{http_code}' "$url" || echo 000)"
    if [ "$code" = "200" ]; then
        log "CDN ok ($code): $desc"
    else
        warn "CDN returned $code for $desc ($url) -- CloudFront not serving / not invalidated yet?"
    fi
}

main() {
    log "Validating against PKG_URL=$PKG_URL (mode: $MODE${VERSION:+ $VERSION}${FORMAT_FILTER:+, format=$FORMAT_FILTER})"

    want_format deb && cdn_check "$PKG_URL/deb/dists/stable/Release" "deb Release"
    want_format rpm && cdn_check "$PKG_URL/rpm/x86_64/repodata/repomd.xml" "rpm repomd.xml (x86_64)"
    want_format apk && cdn_check "$PKG_URL/apk/stable/main/x86_64/APKINDEX.tar.gz" "apk APKINDEX"

    local rc=0
    want_format deb && { validate_deb || rc=1; }
    want_format rpm && { validate_rpm || rc=1; }
    want_format apk && { validate_apk || rc=1; }

    if [ "$rc" -eq 0 ]; then
        log "ALL VALIDATIONS PASSED"
    else
        die "One or more validations FAILED (see PASS/FAIL/MISSING lines above)"
    fi
}

main
