#!/usr/bin/env bash
# GuardHub off-site backups: restic (client-side encrypted, authenticated) to an S3-compatible
# bucket. Run ON the server, normally via guardhub-ctl.sh (see ops/runbooks/production.md).
#
#   offsite.sh configured                exit 0 if RESTIC_REPOSITORY is set, 1 if not (silent)
#   offsite.sh init                      create the restic repository (once, at provisioning)
#   offsite.sh push <dump> <manifest>    upload one backup as a snapshot, then apply retention
#   offsite.sh forget                    retention: --keep-daily 14 --keep-weekly 8 --prune
#   offsite.sh restore-latest <dir>      fetch the newest snapshot into the EMPTY <dir>, verify
#                                        the dump's sha256 against the manifest stored with it,
#                                        print the dump's path on stdout
#   offsite.sh check                     verify repository integrity + show the newest snapshot
#   offsite.sh status                    one line for `guardhub-ctl.sh status`
#
# Configuration comes ONLY from $GUARDHUB_ROOT/shared/.env (default /opt/guardhub):
#   RESTIC_REPOSITORY  e.g. s3:https://<endpoint>/<bucket>/guardhub
#   RESTIC_PASSWORD    encrypts the repository; keep an OFFLINE copy (without it: unreadable)
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY  a key limited to that bucket
#   AWS_DEFAULT_REGION (optional)
# Secrets reach the restic container as `-e NAME` (value inherited from this process's
# environment), never on a command line, so they don't show up in `ps`. Only these variables
# are passed: the restic container never sees GuardHub's own secrets.
set -Eeuo pipefail
umask 077

ROOT=${GUARDHUB_ROOT:-/opt/guardhub}
ENV_FILE=$ROOT/shared/.env
# official image, exact release (2026-07-05) pinned by digest
RESTIC_IMAGE=restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510
NETWORK=${OFFSITE_DOCKER_NETWORK:-bridge} # tests point this at a private network with MinIO
SNAP_HOST=guardhub                         # fixed: the container hostname is random
SNAP_TAG=guardhub
SECRET_VARS=(RESTIC_REPOSITORY RESTIC_PASSWORD AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION)

log() { printf '%s offsite: %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[[ -f $ENV_FILE ]] || die "missing $ENV_FILE"
envval() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true; }

# Windows (Git Bash) test runs only: docker.exe needs C:/... paths for bind mounts.
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

is_configured() { [[ -n $(envval RESTIC_REPOSITORY) ]]; }

load_config() {
  is_configured || die "not configured: set RESTIC_REPOSITORY in $ENV_FILE"
  local name
  for name in "${SECRET_VARS[@]}"; do
    printf -v "$name" '%s' "$(envval "$name")"
    if [[ -n ${!name} ]]; then export "${name?}"; else unset "$name"; fi
  done
  [[ -n ${RESTIC_PASSWORD:-} ]] || die "RESTIC_PASSWORD is empty in $ENV_FILE"
  if [[ $RESTIC_REPOSITORY == s3:* ]]; then
    [[ -n ${AWS_ACCESS_KEY_ID:-} && -n ${AWS_SECRET_ACCESS_KEY:-} ]] ||
      die "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are required for an s3: repository"
  fi
}

# run_restic [-v host:container]... -- <restic args>
run_restic() {
  local -a mounts=()
  while [[ $1 == -v ]]; do mounts+=(-v "$2"); shift 2; done
  [[ $1 == -- ]] && shift
  local -a env=()
  local name
  for name in "${SECRET_VARS[@]}" RESTIC_COMPRESSION; do env+=(-e "$name"); done # NAME only
  docker run --rm --network "$NETWORK" --read-only --tmpfs /tmp:rw,size=512m \
    --cap-drop ALL --security-opt no-new-privileges --memory 768m --cpus 1 --pids-limit 256 \
    "${env[@]}" "${mounts[@]}" "$RESTIC_IMAGE" --no-cache "$@"
}

manifest_sha() { grep '^sha256=' "$1" | cut -d= -f2-; }

verify_dump() { # verify_dump <dump> <manifest>
  local want got
  want=$(manifest_sha "$2")
  [[ $want =~ ^[0-9a-f]{64}$ ]] || die "manifest $2 has no valid sha256"
  got=$(sha256sum "$1" | cut -d' ' -f1)
  [[ $got == "$want" ]] || die "checksum mismatch: $1 (got $got, manifest says $want)"
}

cmd_init() {
  load_config
  run_restic -- init >&2 || die "restic init failed (repository already exists, or bucket/credentials wrong)"
  log "repository initialised. Store RESTIC_PASSWORD OFFLINE now: without it the backups are unreadable."
}

cmd_forget() {
  load_config
  run_restic -- forget --host "$SNAP_HOST" --tag "$SNAP_TAG" --group-by host,tags \
    --keep-daily 14 --keep-weekly 8 --prune >&2 || die "retention (forget --prune) failed"
}

cmd_push() {
  local dump=${1:?usage: push <dump> <manifest>} manifest=${2:?usage: push <dump> <manifest>}
  [[ -f $dump && -f $manifest ]] || die "no such dump/manifest: $dump $manifest"
  [[ $manifest == "$dump.manifest" ]] || die "manifest must be <dump>.manifest (restore relies on it)"
  load_config
  verify_dump "$dump" "$manifest" # never upload a dump that doesn't match its manifest
  local name dir
  name=$(basename "$dump")
  dir=$(cd "$(dirname "$dump")" && pwd)
  run_restic -v "$(hostpath "$dir/$name"):/guardhub/$name:ro" \
    -v "$(hostpath "$dir/$name.manifest"):/guardhub/$name.manifest:ro" \
    -- backup --host "$SNAP_HOST" --tag "$SNAP_TAG" "/guardhub/$name" "/guardhub/$name.manifest" >&2 ||
    die "push of $name failed"
  log "pushed $name (+ manifest) to the off-site repository"
  cmd_forget
}

cmd_restore_latest() {
  local dir=${1:?usage: restore-latest <dir>}
  mkdir -p "$dir"
  [[ -z $(ls -A "$dir") ]] || die "$dir is not empty"
  load_config
  run_restic -v "$(hostpath "$(cd "$dir" && pwd)"):/restore" \
    -- restore latest --host "$SNAP_HOST" --tag "$SNAP_TAG" --target /restore >&2 ||
    die "could not restore the latest snapshot (wrong RESTIC_PASSWORD, credentials or repository?)"
  local -a dumps=("$dir"/guardhub/guardhub-*.dump)
  [[ ${#dumps[@]} -eq 1 && -f ${dumps[0]} ]] || die "latest snapshot does not hold exactly one dump"
  [[ -f ${dumps[0]}.manifest ]] || die "latest snapshot has no manifest"
  verify_dump "${dumps[0]}" "${dumps[0]}.manifest"
  log "restored $(basename "${dumps[0]}"); sha256 matches its manifest"
  echo "${dumps[0]}"
}

cmd_check() {
  load_config
  run_restic -- check >&2 || die "repository check FAILED"
  run_restic -- snapshots --host "$SNAP_HOST" --tag "$SNAP_TAG" --latest 1 >&2 || die "cannot list snapshots"
  log "repository OK"
}

cmd_status() {
  if ! is_configured; then echo "offsite: not configured"; return 0; fi
  load_config
  local out latest
  if out=$(run_restic -- snapshots --host "$SNAP_HOST" --tag "$SNAP_TAG" --latest 1 --json 2>/dev/null); then
    latest=$(printf '%s' "$out" | grep -o '"time":"[^"]*"' | tail -1 | cut -d'"' -f4)
    echo "offsite: configured, latest snapshot ${latest:-none}"
  else
    echo "offsite: configured, repository NOT reachable (run: offsite.sh check)"
  fi
}

case ${1:-} in
  configured) is_configured ;;
  init) cmd_init ;;
  push) cmd_push "${2:-}" "${3:-}" ;;
  forget) cmd_forget ;;
  restore-latest) cmd_restore_latest "${2:-}" ;;
  check) cmd_check ;;
  status) cmd_status ;;
  *) sed -n '2,14p' "$0"; exit 2 ;;
esac
