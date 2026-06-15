#!/bin/bash
#
# backfill_from_cloudsmith.sh
#
# One-time backfill of historical Infisical CLI packages (deb/rpm/apk) from the
# legacy Cloudsmith repo (infisical/infisical-cli) into our AWS package repo
# (s3://$INFISICAL_CLI_S3_BUCKET, served at https://artifacts-cli.infisical.com).
#
# Why: new releases already publish to the AWS repo via upload_to_s3.sh, but old
# versions only live on Cloudsmith. Before we delete the Cloudsmith repo we must
# copy every old deb/rpm/apk into the AWS repo so existing pins like
# `apt install infisical=<old>` keep resolving from the new host.
#
# This script REUSES the exact tooling, flags, env vars and signing keys from
# upload_to_s3.sh so backfilled packages are signed with the same keys that
# already-installed clients trust:
#   - deb:  deb-s3 upload --bucket=$INFISICAL_CLI_S3_BUCKET --prefix=deb \
#                         --visibility=private --sign=$INFISICAL_CLI_REPO_SIGNING_KEY_ID \
#                         --preserve-versions <file>
#   - rpm:  rpmsign --addsign --key-id=$INFISICAL_CLI_REPO_SIGNING_KEY_ID <file>
#           aws s3 cp <file> s3://$INFISICAL_CLI_S3_BUCKET/rpm/<arch>/Packages/
#           then mkrepo s3://$INFISICAL_CLI_S3_BUCKET/rpm/<arch> --sign, PER ARCH.
#           (Per-arch layout, like Cloudsmith: a single flat repo + mkrepo would
#           collapse a version's 5 arches to 1. baseurl is rpm/$basearch.)
#   - apk:  sync existing apks down, apk index -o APKINDEX.tar.gz *.apk,
#           abuild-sign -k /keys/infisical.rsa  (inside an alpine container)
#
# ============================================================================
# USAGE / RUNBOOK
# ============================================================================
#
# Required env vars (same names as the release workflow):
#   INFISICAL_CLI_S3_BUCKET             target bucket. Override with a TEST bucket
#                                       for the POC so prod is never touched.
#   INFISICAL_CLI_REPO_SIGNING_KEY_ID   GPG key id used to sign deb/rpm + indexes.
#   APK_PRIVATE_KEY_PATH                path to the apk RSA private key on disk
#                                       (release CI uses /tmp/infisical-apk.rsa).
#   CLOUDSMITH_API_KEY                  Cloudsmith API key (X-Api-Key header).
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
#                                       AWS creds for s3 / deb-s3 / mkrepo.
#
# Optional env vars:
#   CLOUDFRONT_DISTRIBUTION_ID          (or INFISICAL_CLI_REPO_CLOUDFRONT_DISTRIBUTION_ID)
#                                       CLI CloudFront dist to invalidate after a batch.
#                                       If unset, the exact command is printed instead.
#   CLOUDSMITH_OWNER                    default: infisical
#   CLOUDSMITH_REPO                     default: infisical-cli
#   CLOUDSMITH_DL_TOKEN                 entitlement token, only needed if the repo
#                                       is private and cdn_url returns 403.
#
# POC (single version, against a TEST bucket):
#   export INFISICAL_CLI_S3_BUCKET=my-test-cli-bucket
#   export INFISICAL_CLI_REPO_SIGNING_KEY_ID=<key-id>
#   export APK_PRIVATE_KEY_PATH=/tmp/infisical-apk.rsa
#   export CLOUDSMITH_API_KEY=<key>
#   export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
#
#   # 1) dry run: list exactly what would be downloaded and published
#   ./scripts/backfill_from_cloudsmith.sh --version 0.43.54
#
#   # 2) apply against the TEST bucket
#   ./scripts/backfill_from_cloudsmith.sh --version 0.43.54 --apply
#
# VERIFY one backfilled version (point a container's repo at the test/prod host):
#   deb:  apt-get update && apt-get install -y infisical=<v>
#   rpm:  yum clean all && yum install -y infisical-<v>     # or dnf/zypper
#   apk:  apk update && apk add infisical=<v>
#   index check:
#         deb-s3 list  --bucket=$INFISICAL_CLI_S3_BUCKET --prefix=deb | grep <v>
#         aws s3 ls    s3://$INFISICAL_CLI_S3_BUCKET/rpm/x86_64/Packages/ | grep <v>
#         aws s3 cp    s3://$INFISICAL_CLI_S3_BUCKET/apk/stable/main/x86_64/APKINDEX.tar.gz - \
#           | tar -xzO APKINDEX 2>/dev/null | grep -A2 '^P:infisical'
#
# FULL run (every version) against PROD, after the POC is verified:
#   export INFISICAL_CLI_S3_BUCKET=<prod-bucket>   # the real one
#   ./scripts/backfill_from_cloudsmith.sh --all              # dry run first
#   ./scripts/backfill_from_cloudsmith.sh --all --apply      # then apply
#
# Idempotent + resumable: re-running skips files already present in the repo and
# never removes or alters newer versions (deb-s3 --preserve-versions; rpm/apk
# indexes rebuilt from the full synced set). Safe to Ctrl-C and re-run.
# ============================================================================

set -euo pipefail

# Never page aws CLI output: in an interactive container the default pager
# (less) may be absent, which makes commands like `cloudfront create-invalidation`
# fail when trying to display their result.
export AWS_PAGER=""

# ----------------------------------------------------------------------------
# Defaults / globals
# ----------------------------------------------------------------------------
CLOUDSMITH_OWNER="${CLOUDSMITH_OWNER:-infisical}"
CLOUDSMITH_REPO="${CLOUDSMITH_REPO:-infisical-cli}"
CLOUDSMITH_API="https://api.cloudsmith.io/v1"
PAGE_SIZE=100

MODE=""              # "version" or "all"
VERSION=""           # set when MODE=version
FORMAT_FILTER=""     # optional: deb | rpm | apk
APPLY=0              # 0 = dry run (default), 1 = actually publish
DO_INVALIDATE=1      # CloudFront invalidation after a batch
REINDEX=0            # force rpm/apk metadata regeneration even if nothing new

TS="$(date +%Y%m%d-%H%M%S)"
WORKROOT="$(pwd)/.cloudsmith-backfill"
TMPDIR_DL="${WORKROOT}/download-${TS}"
BACKUP_DIR="${WORKROOT}/backups/${TS}"
STATE_FILE="${WORKROOT}/state-${CLOUDSMITH_OWNER}-${CLOUDSMITH_REPO}.done"

# Package name in our repos.
PKG_NAME="infisical"

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
log()  { printf '%s\n' "[backfill] $*"; }
warn() { printf '%s\n' "[backfill][WARN] $*" >&2; }
die()  { printf '%s\n' "[backfill][ERROR] $*" >&2; exit 1; }

usage() {
    sed -n '2,80p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# Marks "what would happen" in dry-run, runs it in apply mode.
run() {
    if [ "$APPLY" -eq 1 ]; then
        "$@"
    else
        log "DRY-RUN would run: $*"
    fi
}

# ----------------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            [ $# -ge 2 ] || die "--version requires a value"
            MODE="version"; VERSION="$2"; shift 2 ;;
        --all)
            MODE="all"; shift ;;
        --format)
            [ $# -ge 2 ] || die "--format requires a value (deb|rpm|apk)"
            FORMAT_FILTER="$2"; shift 2 ;;
        --bucket)
            [ $# -ge 2 ] || die "--bucket requires a value"
            INFISICAL_CLI_S3_BUCKET="$2"; export INFISICAL_CLI_S3_BUCKET; shift 2 ;;
        --apply)
            APPLY=1; shift ;;
        --no-invalidate)
            DO_INVALIDATE=0; shift ;;
        --reindex)
            REINDEX=1; shift ;;
        -h|--help)
            usage 0 ;;
        *)
            die "Unknown argument: $1 (use --help)" ;;
    esac
done

[ -n "$MODE" ] || die "Specify exactly one of --version <v> or --all (use --help)"
if [ -n "$FORMAT_FILTER" ]; then
    case "$FORMAT_FILTER" in
        deb|rpm|apk) ;;
        *) die "--format must be one of: deb, rpm, apk" ;;
    esac
fi

# ----------------------------------------------------------------------------
# Preflight: required env vars and tools (fail loudly)
# ----------------------------------------------------------------------------
preflight() {
    local missing=()
    [ -n "${INFISICAL_CLI_S3_BUCKET:-}" ]           || missing+=("INFISICAL_CLI_S3_BUCKET")
    [ -n "${INFISICAL_CLI_REPO_SIGNING_KEY_ID:-}" ] || missing+=("INFISICAL_CLI_REPO_SIGNING_KEY_ID")
    [ -n "${APK_PRIVATE_KEY_PATH:-}" ]              || missing+=("APK_PRIVATE_KEY_PATH")
    [ -n "${CLOUDSMITH_API_KEY:-}" ]                || missing+=("CLOUDSMITH_API_KEY")
    [ -n "${AWS_ACCESS_KEY_ID:-}" ]                 || missing+=("AWS_ACCESS_KEY_ID")
    [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]             || missing+=("AWS_SECRET_ACCESS_KEY")
    if [ ${#missing[@]} -gt 0 ]; then
        die "Missing required environment variables: ${missing[*]}"
    fi

    # The apk RSA private key must exist on disk (mounted into the container).
    [ -f "$APK_PRIVATE_KEY_PATH" ] || die "APK private key not found at: $APK_PRIVATE_KEY_PATH"

    # Required tools. docker/rpmsign/mkrepo/deb-s3 are only strictly needed for
    # --apply, but we check up front so dry runs surface gaps too.
    local tool
    for tool in curl jq aws; do
        command -v "$tool" >/dev/null 2>&1 || die "Required tool not found: $tool"
    done
    for tool in deb-s3 rpmsign mkrepo docker; do
        command -v "$tool" >/dev/null 2>&1 || warn "Tool not found (needed for --apply): $tool"
    done

    log "Target bucket : s3://$INFISICAL_CLI_S3_BUCKET"
    log "Signing key id: $INFISICAL_CLI_REPO_SIGNING_KEY_ID"
    log "Cloudsmith    : $CLOUDSMITH_OWNER/$CLOUDSMITH_REPO"
    log "Mode          : $MODE${VERSION:+ ($VERSION)}${FORMAT_FILTER:+ format=$FORMAT_FILTER}"
    log "Apply         : $([ "$APPLY" -eq 1 ] && echo yes || echo 'NO (dry run)')"
}

# ----------------------------------------------------------------------------
# Cloudsmith enumeration
#
# GET /v1/packages/{owner}/{repo}/?page=N&page_size=100 returns a JSON array of
# package objects. We read: .format (deb|rpm|alpine), .version,
# .architectures[0].name, .filename, .cdn_url.
#
# Pagination ends when a page comes back empty OR with HTTP 404: this Cloudsmith
# deployment returns 404 for the first page past the end rather than an empty
# array, so a 404 after page 1 is end-of-list, not an error. A 404 on page 1
# (or any other non-200) is a real failure (bad key / repo name).
#
# Output: one normalized TSV line per package file:
#   <format>\t<version>\t<arch>\t<filename>\t<download_url>
# where <format> is normalized to deb|rpm|apk. Duplicate filenames (Cloudsmith
# can hold re-synced copies) are de-duplicated, keeping the first occurrence.
# ----------------------------------------------------------------------------
enumerate_packages() {
    local page=1 http count tmpf
    tmpf="$(mktemp)"
    while :; do
        # --retry-all-errors recovers from transient TLS/connection drops; a 404
        # is a normal (non-error) response here, so it is NOT retried and falls
        # through to the end-of-list handling below.
        http="$(curl -sS \
            --retry 5 --retry-delay 2 --retry-all-errors \
            --connect-timeout 20 --max-time 180 \
            -H "X-Api-Key: $CLOUDSMITH_API_KEY" \
            -H "Accept: application/json" \
            -o "$tmpf" -w '%{http_code}' \
            "${CLOUDSMITH_API}/packages/${CLOUDSMITH_OWNER}/${CLOUDSMITH_REPO}/?page=${page}&page_size=${PAGE_SIZE}")" \
            || http="000"

        if [ "$http" = "200" ]; then
            count="$(jq 'length' "$tmpf" 2>/dev/null || echo 0)"
            [ "$count" = "0" ] && break
            jq -r '
                .[]
                # Only the three formats we publish; map "alpine" -> "apk".
                | select(.format=="deb" or .format=="rpm" or .format=="alpine")
                | [ (if .format=="alpine" then "apk" else .format end),
                    .version,
                    ((.architectures[0].name) // "noarch"),
                    .filename,
                    .cdn_url ]
                | @tsv' "$tmpf"
            page=$((page + 1))
            continue
        fi

        # A 404 past the first page just means we ran off the end of pagination.
        if [ "$http" = "404" ] && [ "$page" -gt 1 ]; then
            break
        fi

        rm -f "$tmpf"
        die "Cloudsmith API request failed (page $page, HTTP $http). Check CLOUDSMITH_API_KEY / repo name."
    done
    rm -f "$tmpf"
}

# Build the filtered, de-duplicated work list into $WORKLIST (a temp file).
build_worklist() {
    WORKLIST="${TMPDIR_DL}/worklist.tsv"
    mkdir -p "$TMPDIR_DL"

    enumerate_packages \
        | { if [ "$MODE" = "version" ]; then
                # Match the exact version (apk: "0.43.49") and any release-suffixed
                # form (rpm: "0.43.49-1"). index() is a literal substring test, so
                # dots are not treated as wildcards and "0.43.49" won't match "0.43.490".
                awk -F'\t' -v v="$VERSION" '$2==v || index($2, v"-")==1'
            else cat; fi; } \
        | { if [ -n "$FORMAT_FILTER" ]; then awk -F'\t' -v f="$FORMAT_FILTER" '$1==f'; else cat; fi; } \
        | awk -F'\t' '!seen[$1"\t"$2"\t"$3"\t"$4]++' \
        | sort -t$'\t' -k1,1 -k2,2 -k3,3 \
        > "$WORKLIST"

    local n
    n="$(wc -l < "$WORKLIST" | tr -d ' ')"
    if [ "$n" -eq 0 ]; then
        if [ "$MODE" = "version" ]; then
            die "No deb/rpm/apk packages found on Cloudsmith for version '$VERSION'."
        else
            die "No deb/rpm/apk packages found on Cloudsmith."
        fi
    fi
    log "Found $n package file(s) to consider:"
    awk -F'\t' '{printf "  - %-4s %-12s %-8s %s\n", $1, $2, $3, $4}' "$WORKLIST"
}

# ----------------------------------------------------------------------------
# State file (resumability): record successfully published filenames so a
# re-run can skip them quickly without round-tripping to S3 for each one.
# ----------------------------------------------------------------------------
state_has() { [ -f "$STATE_FILE" ] && grep -qxF "$1" "$STATE_FILE"; }
# Only record state when actually publishing. A dry run must never mark items
# done, or the following --apply would skip everything it "previewed".
state_add() { [ "$APPLY" -eq 1 ] || return 0; mkdir -p "$(dirname "$STATE_FILE")"; printf '%s\n' "$1" >> "$STATE_FILE"; }

# ----------------------------------------------------------------------------
# Download a single package file from Cloudsmith into $TMPDIR_DL/<format>/.
# Tries the public cdn_url first, then falls back to authenticated variants.
# Echoes the local path on success.
# ----------------------------------------------------------------------------
download_file() {
    local fmt="$1" filename="$2" url="$3"
    local dest_dir="${TMPDIR_DL}/${fmt}"
    local dest="${dest_dir}/${filename}"
    mkdir -p "$dest_dir"

    # Already downloaded this run (resume within a run).
    if [ -s "$dest" ]; then
        printf '%s' "$dest"; return 0
    fi

    if curl -fSL --retry 4 --retry-delay 3 -o "$dest" "$url" 2>/dev/null; then
        :
    elif curl -fSL --retry 4 --retry-delay 3 -H "X-Api-Key: $CLOUDSMITH_API_KEY" -o "$dest" "$url" 2>/dev/null; then
        :
    elif [ -n "${CLOUDSMITH_DL_TOKEN:-}" ] && \
         curl -fSL --retry 4 --retry-delay 3 -u "token:${CLOUDSMITH_DL_TOKEN}" -o "$dest" "$url" 2>/dev/null; then
        :
    else
        rm -f "$dest"
        die "Failed to download $filename from $url (set CLOUDSMITH_DL_TOKEN if the repo is private)."
    fi
    printf '%s' "$dest"
}

# ----------------------------------------------------------------------------
# Back up the index files we may overwrite, to a timestamped local dir.
# Rollback path beyond this: the bucket has S3 versioning enabled, so prior
# object versions of these keys can be restored directly in S3.
# ----------------------------------------------------------------------------
backup_indexes() {
    log "Backing up current index files to $BACKUP_DIR (S3 versioning is the deeper rollback path)"
    mkdir -p "$BACKUP_DIR"
    # deb: Release / InRelease / Release.gpg / Packages live under deb/dists/
    aws s3 cp "s3://$INFISICAL_CLI_S3_BUCKET/deb/dists/" "$BACKUP_DIR/deb-dists/" --recursive >/dev/null 2>&1 \
        || warn "No existing deb/dists to back up (first publish?)"
    # rpm: per-arch repodata (rpm/<arch>/repodata/) plus any legacy flat
    # rpm/repodata/. Copy repodata only, never the (large) Packages trees.
    aws s3 cp "s3://$INFISICAL_CLI_S3_BUCKET/rpm/" "$BACKUP_DIR/rpm/" --recursive \
        --exclude "*" --include "*/repodata/*" >/dev/null 2>&1 \
        || warn "No existing rpm repodata to back up (first publish?)"
    # apk: per-arch APKINDEX.tar.gz
    local a
    for a in x86_64 aarch64; do
        aws s3 cp "s3://$INFISICAL_CLI_S3_BUCKET/apk/stable/main/$a/APKINDEX.tar.gz" \
            "$BACKUP_DIR/apk-$a-APKINDEX.tar.gz" >/dev/null 2>&1 \
            || warn "No existing apk APKINDEX for $a to back up (first publish?)"
    done
}

# ============================================================================
# DEB publishing
#
# deb-s3 pulls the existing manifest from S3 and merges; --preserve-versions
# guarantees it never prunes other (newer) versions. Re-uploading an identical
# package is a no-op for the index, but we skip already-present ones to keep
# re-runs fast and quiet. This mirrors upload_to_s3.sh exactly.
# ============================================================================
deb_already_present() {
    local version="$1" arch="$2"
    # deb-s3 list prints: "<name>\t<version>\t<arch>" (default codename "stable",
    # component "main"), matching upload_to_s3.sh's defaults.
    deb-s3 list --bucket="$INFISICAL_CLI_S3_BUCKET" --prefix=deb --arch="$arch" 2>/dev/null \
        | awk -F'\t' -v n="$PKG_NAME" -v v="$version" '$1==n && $2==v {found=1} END{exit !found}'
}

publish_deb() {
    local file="$1" version="$2" arch="$3" filename="$4"
    if state_has "$filename"; then
        log "deb skip (state): $filename already backfilled"; return 0
    fi
    if [ "$APPLY" -eq 1 ] && deb_already_present "$version" "$arch"; then
        log "deb skip: $PKG_NAME $version ($arch) already in repo"
        state_add "$filename"; return 0
    fi
    log "deb publish: $filename"
    run deb-s3 upload \
        --bucket="$INFISICAL_CLI_S3_BUCKET" \
        --prefix=deb \
        --visibility=private \
        --sign="$INFISICAL_CLI_REPO_SIGNING_KEY_ID" \
        --preserve-versions \
        "$file"
    state_add "$filename"
}

# ============================================================================
# RPM publishing -- PER-ARCH layout (matches Cloudsmith and setup.rpm.sh's
# baseurl=${PKG_URL}/rpm/$basearch).
#
# Each rpm goes to rpm/<arch>/Packages/, and mkrepo runs once PER ARCH against
# rpm/<arch>. We do NOT use a single flat rpm/repodata: mkrepo keys packages by
# name-version-release and drops all but one arch, so a flat multi-arch repo
# collapses to one arch per version. Per arch there is exactly one package per
# version, so mkrepo's keying is fine -- and mkrepo stays incremental/S3-native
# (no bulk download), which a flat createrepo_c rebuild would require.
# ============================================================================
RPM_CHANGED=0
RPM_ARCHES=""   # space-delimited set of arch dirs touched this run

rpm_mark_arch() {
    case " $RPM_ARCHES " in *" $1 "*) ;; *) RPM_ARCHES="$RPM_ARCHES $1" ;; esac
}

publish_rpm_file() {
    local file="$1" filename="$2" arch="$3"
    # arch is the rpm's real arch from Cloudsmith metadata (x86_64, aarch64,
    # i386, armv6hl, armv7hl) -- the same value yum resolves $basearch to.
    local key="rpm:${arch}:${filename}"
    if state_has "$key"; then
        log "rpm skip (state): ${arch}/${filename} already backfilled"; return 0
    fi
    if [ "$APPLY" -eq 1 ] && aws s3 ls "s3://$INFISICAL_CLI_S3_BUCKET/rpm/${arch}/Packages/${filename}" >/dev/null 2>&1; then
        log "rpm skip: ${arch}/${filename} already in repo"
        state_add "$key"; rpm_mark_arch "$arch"; return 0
    fi
    log "rpm sign + upload: ${arch}/${filename}"
    # rpmsign mutates the file in place; it is a throwaway temp download.
    run rpmsign --addsign --key-id="$INFISICAL_CLI_REPO_SIGNING_KEY_ID" "$file"
    run aws s3 cp "$file" "s3://$INFISICAL_CLI_S3_BUCKET/rpm/${arch}/Packages/"
    state_add "$key"
    RPM_CHANGED=1
    rpm_mark_arch "$arch"
}

# Map a goreleaser rpm filename (..._linux_<goarch>.rpm) to its rpm arch dir.
rpm_arch_from_filename() {
    case "$1" in
        *_linux_amd64.rpm) printf 'x86_64'  ;;
        *_linux_arm64.rpm) printf 'aarch64' ;;
        *_linux_386.rpm)   printf 'i386'    ;;
        *_linux_armv6.rpm) printf 'armv6hl' ;;
        *_linux_armv7.rpm) printf 'armv7hl' ;;
        *) printf '' ;;
    esac
}

# One-time migration: copy any rpms in the LEGACY flat rpm/Packages/ into the
# per-arch rpm/<arch>/Packages/ layout, so versions that predate this layout
# (already on the prod repo) are not dropped. Idempotent (skips existing).
rpm_migrate_flat_layout() {
    local existing line filename arch
    existing="$(aws s3 ls "s3://$INFISICAL_CLI_S3_BUCKET/rpm/Packages/" 2>/dev/null | awk '{print $4}' | grep '\.rpm$' || true)"
    [ -n "$existing" ] || return 0
    log "rpm: migrating legacy flat rpm/Packages/ into per-arch layout"
    while IFS= read -r filename; do
        [ -n "$filename" ] || continue
        arch="$(rpm_arch_from_filename "$filename")"
        if [ -z "$arch" ]; then warn "rpm: cannot map arch for legacy $filename, skipping"; continue; fi
        if [ "$APPLY" -eq 1 ] && aws s3 ls "s3://$INFISICAL_CLI_S3_BUCKET/rpm/${arch}/Packages/${filename}" >/dev/null 2>&1; then
            continue
        fi
        log "rpm: relayout ${filename} -> ${arch}/"
        if [ "$APPLY" -eq 1 ]; then
            # Download+upload (GetObject/PutObject only). A server-side s3->s3 copy
            # would additionally require s3:GetObjectTagging/PutObjectTagging. These
            # rpms are already signed, so we just move them into the per-arch path.
            local tmp="${TMPDIR_DL}/relayout-${filename}"
            aws s3 cp "s3://$INFISICAL_CLI_S3_BUCKET/rpm/Packages/${filename}" "$tmp" >/dev/null
            aws s3 cp "$tmp" "s3://$INFISICAL_CLI_S3_BUCKET/rpm/${arch}/Packages/${filename}" >/dev/null
            rm -f "$tmp"
        else
            log "DRY-RUN would relayout ${filename} -> ${arch}/Packages/"
        fi
        RPM_CHANGED=1
        rpm_mark_arch "$arch"
    done <<< "$existing"
}

# List per-arch directories that currently exist under rpm/ in S3.
rpm_existing_arches() {
    aws s3 ls "s3://$INFISICAL_CLI_S3_BUCKET/rpm/" 2>/dev/null \
        | awk '/ PRE /{gsub("/","",$2); print $2}' \
        | grep -vxE 'Packages|repodata' || true
}

rpm_regenerate_metadata() {
    if [ "$RPM_CHANGED" -eq 0 ] && [ "$REINDEX" -eq 0 ]; then
        log "rpm: nothing new, skipping repodata regeneration"; return 0
    fi
    local arches
    if [ "$REINDEX" -eq 1 ]; then
        arches="$(rpm_existing_arches)"      # reindex every arch present
    else
        arches="$RPM_ARCHES"
    fi
    local arch
    for arch in $arches; do
        log "rpm: regenerating rpm/${arch} repodata with mkrepo --sign"
        if [ "$APPLY" -eq 1 ]; then
            GPG_SIGN_KEY="$INFISICAL_CLI_REPO_SIGNING_KEY_ID" \
            mkrepo "s3://$INFISICAL_CLI_S3_BUCKET/rpm/${arch}" --s3-region="us-east-1" --sign
        else
            log "DRY-RUN would run: GPG_SIGN_KEY=... mkrepo s3://$INFISICAL_CLI_S3_BUCKET/rpm/${arch} --s3-region=us-east-1 --sign"
        fi
    done
}

# ============================================================================
# APK publishing
#
# Stage downloaded apks into apk-staging/stable/main/<arch>/, sync ALL existing
# apks down from S3 FIRST (so nothing is dropped from the rebuilt index), add
# only the new files, then rebuild + sign APKINDEX inside an alpine container
# exactly as upload_to_s3.sh does. Renaming to <pkgname>-<pkgver>.apk and arch
# detection match the original script.
# ============================================================================
APK_STAGING="${TMPDIR_DL}/apk-staging"
APK_CHANGED=0

apk_stage_existing() {
    mkdir -p "$APK_STAGING/stable/main/x86_64" "$APK_STAGING/stable/main/aarch64"
    # Pull every existing apk down first; exclude indexes (we regenerate those).
    log "apk: syncing existing apks down from S3 (preserves all current versions)"
    run aws s3 sync "s3://$INFISICAL_CLI_S3_BUCKET/apk/" "$APK_STAGING/" --exclude "*/APKINDEX.tar.gz"
}

# Stage one downloaded apk into the right arch dir under the Alpine naming
# convention, unless it is already present (idempotent / dedup).
publish_apk_file() {
    local file="$1" filename="$2" arch="$3"
    local pkgname pkgver alpine_filename target archdir key

    # Use the arch from Cloudsmith metadata: the stored apk filename is the Alpine
    # convention <pkgname>-<pkgver>.apk and carries no arch. The new apk repo only
    # serves x86_64 and aarch64 (see upload_to_s3.sh / setup.apk.sh); other arches
    # (armv7, armhf, x86, 386, ...) are not published there, so skip them.
    case "$arch" in
        x86_64|amd64)  archdir="x86_64" ;;
        aarch64|arm64) archdir="aarch64" ;;
        *) log "apk skip: $filename arch '$arch' is not served by the new repo (only x86_64/aarch64)"; return 0 ;;
    esac

    pkgname="$(tar -xzf "$file" -O .PKGINFO 2>/dev/null | grep '^pkgname' | cut -d' ' -f3 || true)"
    pkgver="$(tar -xzf "$file" -O .PKGINFO 2>/dev/null | grep '^pkgver'  | cut -d' ' -f3 || true)"
    if [ -z "$pkgname" ] || [ -z "$pkgver" ]; then
        die "apk: failed to extract package info from $filename"
    fi
    alpine_filename="${pkgname}-${pkgver}.apk"
    target="$APK_STAGING/stable/main/${archdir}/${alpine_filename}"

    # Rely on the synced-staging tree (not the state file) to decide if this apk
    # is already published. apk uploads happen later in one batch, so recording
    # state at stage time would wrongly skip a file on re-run if that batch upload
    # never completed. The staging tree was just synced from S3, so an existing
    # target here means it is genuinely already in the repo.
    if [ -f "$target" ]; then
        log "apk skip: ${archdir}/${alpine_filename} already present in repo"
        return 0
    fi

    log "apk stage: $filename ($arch) -> ${archdir}/${alpine_filename}"
    if [ "$APPLY" -eq 1 ]; then
        mkdir -p "$(dirname "$target")"
        cp "$file" "$target"
    else
        log "DRY-RUN would copy $filename to staging ${archdir}/${alpine_filename}"
    fi
    APK_CHANGED=1
}

apk_build_and_upload_index() {
    if [ "$APK_CHANGED" -eq 0 ] && [ "$REINDEX" -eq 0 ]; then
        log "apk: nothing new, skipping index regeneration"; return 0
    fi
    log "apk: regenerating + signing APKINDEX inside alpine container"
    if [ "$APPLY" -ne 1 ]; then
        log "DRY-RUN would run apk index + abuild-sign in alpine:3.21 and sync apk-staging/ to S3"
        return 0
    fi

    # Identical container approach to upload_to_s3.sh: nFPM apks are unsigned, so
    # we --allow-untrusted to index them and sign only the APKINDEX itself.
    docker run --rm \
        -v "$APK_STAGING:/repo" \
        -v "$APK_PRIVATE_KEY_PATH:/keys/infisical.rsa:ro" \
        alpine:3.21 sh -c '
            set -e
            apk add --no-cache alpine-sdk || { echo "Failed to install alpine-sdk"; exit 1; }
            process_arch() {
                arch_dir="$1"
                if ls "/repo/stable/main/${arch_dir}"/*.apk 1> /dev/null 2>&1; then
                    cd "/repo/stable/main/${arch_dir}"
                    apk index --allow-untrusted -o APKINDEX.tar.gz *.apk
                    abuild-sign -k /keys/infisical.rsa APKINDEX.tar.gz
                    echo "${arch_dir} APKINDEX signed"
                fi
            }
            process_arch "x86_64"
            process_arch "aarch64"
        '

    log "apk: uploading repository to S3"
    aws s3 sync "$APK_STAGING/" "s3://$INFISICAL_CLI_S3_BUCKET/apk/"
}

# ============================================================================
# CloudFront invalidation (after a batch). Same paths as the release workflow.
# ============================================================================
invalidate_cloudfront() {
    [ "$DO_INVALIDATE" -eq 1 ] || { log "Skipping CloudFront invalidation (--no-invalidate)"; return 0; }

    local dist="${CLOUDFRONT_DISTRIBUTION_ID:-${INFISICAL_CLI_REPO_CLOUDFRONT_DISTRIBUTION_ID:-}}"
    # /rpm/* covers the per-arch repodata + packages (rpm/<arch>/...).
    local paths=('/rpm/*' '/deb/dists/stable/*' '/apk/stable/main/*')

    if [ -z "$dist" ]; then
        warn "No CloudFront distribution id in env. Run this manually after verifying:"
        printf '  aws cloudfront create-invalidation --distribution-id <DIST_ID> --paths %s\n' "${paths[*]}"
        return 0
    fi
    log "Invalidating CloudFront distribution $dist"
    run aws cloudfront create-invalidation --distribution-id "$dist" --paths "${paths[@]}"
}

# ============================================================================
# Main
# ============================================================================
main() {
    preflight
    build_worklist

    # Back up the indexes we may overwrite before mutating anything (apply only).
    if [ "$APPLY" -eq 1 ]; then
        backup_indexes
    else
        log "DRY-RUN: would back up deb/dists, rpm/repodata and apk APKINDEX.tar.gz to $BACKUP_DIR"
    fi

    # If any apk is in scope, stage the existing apks down once up front so the
    # rebuilt index includes every current version.
    if awk -F'\t' '$1=="apk"' "$WORKLIST" | grep -q .; then
        apk_stage_existing
    fi

    # If any rpm is in scope (or we're reindexing), migrate any legacy flat
    # rpm/Packages/ rpms into the per-arch layout first, so nothing is dropped.
    if [ "$REINDEX" -eq 1 ] || awk -F'\t' '$1=="rpm"' "$WORKLIST" | grep -q .; then
        rpm_migrate_flat_layout
    fi

    # Download + publish each file. Read columns from the TSV worklist.
    local fmt version arch filename url local_path
    while IFS=$'\t' read -r fmt version arch filename url; do
        [ -n "$fmt" ] || continue
        log "---- $fmt $version $arch $filename ----"
        local_path="$(download_file "$fmt" "$filename" "$url")"
        case "$fmt" in
            deb) publish_deb      "$local_path" "$version" "$arch" "$filename" ;;
            rpm) publish_rpm_file "$local_path" "$filename" "$arch" ;;
            apk) publish_apk_file "$local_path" "$filename" "$arch" ;;
        esac
    done < "$WORKLIST"

    # Regenerate per-format metadata once for the whole batch.
    rpm_regenerate_metadata
    apk_build_and_upload_index

    # Invalidate the CDN once after the batch.
    invalidate_cloudfront

    if [ "$APPLY" -eq 1 ]; then
        log "DONE. Backfill applied. Backups in: $BACKUP_DIR"
        log "Verify with the commands in this script's header (VERIFY section)."
    else
        log "DONE (dry run). Re-run with --apply to publish."
    fi
}

main
