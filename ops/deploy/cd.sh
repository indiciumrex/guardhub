#!/usr/bin/env bash
# GuardHub CD agent, run ON the production server (ADR-0009). The server never builds: it pulls.
#
#   cd.sh tick          (cron, /etc/cron.d/guardhub-cd) deploy the newest main commit whose CI
#                       run is green, if it is not live yet. Does nothing while halted.
#   cd.sh deploy <sha>  deploy exactly that commit (it must be green on main and signed)
#   cd.sh verify        run the post-deploy gates against the serving colour (no switch)
#   cd.sh status        last result, halt reason
#   cd.sh resume        clear a halt (a human decision, after reading the report)
#
# A deploy: CI run for <sha> on main = success (every gate, incl. the release job) -> git objects
# fetched anonymously and archived (git checks every hash) -> the three images pulled from GHCR
# and accepted only when Sigstore proves the DIGEST was signed by ci.yml on refs/heads/main for
# exactly <sha> -> probes start (every second, through nginx) -> guardhub-ctl.sh activate
# (backup, expand-only migration, idle colour, health, switch) -> gates E C F H J G -> probes stop
# and gate K requires 0 failures over the whole window. ANY failed gate: automatic rollback to the
# previous colour, then HALT (no further deploys until `cd.sh resume`): stop and report.
#
# Scope (shared host): /opt/guardhub, the guardhub* compose projects, /etc/cron.d/guardhub-cd,
# /var/log/guardhub-cd.log and images named guardhub-* / ghcr.io/<owner>/guardhub-*. Nothing else.
set -Eeuo pipefail
umask 077

ROOT=${GUARDHUB_ROOT:-/opt/guardhub}
REPO=${GUARDHUB_REPO:-indiciumrex/guardhub}
OWNER=${REPO%%/*}
REG=ghcr.io/${OWNER,,}
COSIGN=ghcr.io/sigstore/cosign/cosign:v2.4.1@sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31
IDENTITY="https://github.com/$REPO/.github/workflows/ci.yml@refs/heads/main"
ISSUER=https://token.actions.githubusercontent.com
STATE=$ROOT/state
CDS=$STATE/cd
GITDIR=$ROOT/cd/repo.git
ENV_FILE=$ROOT/shared/.env
SELFVERIFY=$ROOT/selfverify/guardhub-verify.txt
PROBE_TAIL=${CD_PROBE_TAIL:-30} # seconds of probing after the last gate
declare -A PORT=([blue]=18701 [green]=18702)
mkdir -p "$CDS/runs"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
envval() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2-; }
active_color() { cat "$STATE/active_color" 2>/dev/null || true; }
current_version() { [[ -L $ROOT/current ]] && basename "$(readlink -f "$ROOT/current")" || true; }
PUBLIC=$(envval PUBLIC_BASE_URL)
HOST=$(sed -E 's#^https?://##; s#/.*$##' <<<"$PUBLIC")

halt() { # halt <reason>: no deploy runs until a human clears it
  printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >"$CDS/halt"
  log "HALTED: $*"
}

gh_api() { # gh_api <path> -> body on stdout. Anonymous (public repo); ETag-cached, and a 304
  # does not count against the 60/h anonymous limit this shared host's IP has.
  local key; key=$(sha256sum <<<"$1" | cut -c1-16)
  local body=$CDS/api-$key.json etag=$CDS/api-$key.etag hdr; hdr=$(mktemp)
  local code cond=()
  [[ -f $etag && -f $body ]] && cond=(-H "If-None-Match: $(cat "$etag")")
  code=$(curl -sS --max-time 20 -o "$body.new" -D "$hdr" -w '%{http_code}' \
    -H 'Accept: application/vnd.github+json' -H 'User-Agent: guardhub-cd' "${cond[@]}" \
    "https://api.github.com/$1") || { rm -f "$hdr" "$body.new"; return 1; }
  case $code in
    200) mv -f "$body.new" "$body"; grep -i '^etag:' "$hdr" | cut -d' ' -f2- | tr -d '\r' >"$etag" ;;
    304) rm -f "$body.new" ;;
    *) rm -f "$hdr" "$body.new"; log "GitHub API $1 -> HTTP $code"; return 1 ;;
  esac
  rm -f "$hdr"; cat "$body"
}

# newest COMPLETED push run of ci.yml on main: "<sha> <conclusion>"
newest_main_run() {
  gh_api "repos/$REPO/actions/workflows/ci.yml/runs?branch=main&event=push&per_page=10" |
    python3 -c 'import json,sys
for r in json.load(sys.stdin)["workflow_runs"]:
    if r["status"] == "completed" and r["head_branch"] == "main":
        print(r["head_sha"], r["conclusion"]); break'
}

# every gate (job) of the main push run for <sha> concluded success, the release job included
ci_green() {
  local sha=$1 runs run
  runs=$(gh_api "repos/$REPO/actions/workflows/ci.yml/runs?head_sha=$sha&event=push&per_page=10") || return 1
  run=$(python3 -c 'import json,sys
for r in json.load(sys.stdin)["workflow_runs"]:
    if r["head_branch"] == "main" and r["conclusion"] == "success":
        print(r["id"]); break' <<<"$runs")
  [[ -n $run ]] || { log "no successful main push run for $sha"; return 1; }
  gh_api "repos/$REPO/actions/runs/$run/jobs?per_page=50" | python3 -c 'import json,sys
jobs = json.load(sys.stdin)["jobs"]
bad = [j["name"] for j in jobs if j["conclusion"] != "success"]
rel = [j for j in jobs if j["name"].startswith("release")]
if bad or not rel:
    sys.exit("jobs not green: %s%s" % (bad, "" if rel else " (no release job)"))
print("run %s: %d jobs, all success" % (sys.argv[1], len(jobs)))' "$run" >&2
}

fetch_release() { # fetch_release <sha>: git-verified release files in releases/<v>
  local sha=$1 v=${1::12} dir=$ROOT/releases/${1::12}
  [[ -d $GITDIR ]] || git init -q --bare "$GITDIR"
  git --git-dir="$GITDIR" fetch -q --no-tags "https://github.com/$REPO.git" "+refs/heads/main:refs/remotes/origin/main"
  [[ $(git --git-dir="$GITDIR" cat-file -t "$sha" 2>/dev/null) == commit ]] || die "$sha is not a commit on main"
  git --git-dir="$GITDIR" merge-base --is-ancestor "$sha" origin/main || die "$sha is not on main"
  if [[ ! -d $dir ]]; then
    mkdir -p "$dir.tmp" && git --git-dir="$GITDIR" archive "$sha" | tar -x -C "$dir.tmp" && mv "$dir.tmp" "$dir"
  fi
  chmod 755 "$dir"
  log "release files for $v: $dir"
}

pull_verified() { # pull_verified <sha>: images accepted only with a valid signature for <sha>
  local sha=$1 v=${1::12} s ref digest
  for s in api scanner web; do
    ref=$REG/guardhub-$s:$v
    docker pull -q "$ref" >/dev/null || die "cannot pull $ref"
    digest=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" | grep -m1 "^$REG/guardhub-$s@sha256:") ||
      die "no digest for $ref"
    if ! docker run --rm "$COSIGN" verify --certificate-identity "$IDENTITY" \
      --certificate-oidc-issuer "$ISSUER" --certificate-github-workflow-sha "$sha" \
      --certificate-github-workflow-trigger push --certificate-github-workflow-ref refs/heads/main \
      "$digest" >"$CDS/cosign-$s.json" 2>"$CDS/cosign-$s.err"; then
      cat "$CDS/cosign-$s.err" >&2
      die "SIGNATURE: $digest is not signed by $IDENTITY for $sha"
    fi
    [[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$digest") == "$sha" ]] ||
      die "$digest: revision label is not $sha"
    docker tag "$digest" "guardhub-$s:$v"
    log "image $s: $digest (signature verified for $sha)"
  done
}

neighbours() { # every non-GuardHub container: name, id, running state (must not change)
  docker ps -a --format '{{.Names}} {{.ID}} {{.State}}' | grep -vE '^guardhub-' | sort || true
}

# ---- gate K: probes through nginx every second, like a visitor (without leaving the host) ----
PROBE_PID=
probe_start() { # probe_start <file>
  local out=$1
  : >"$out"
  (
    while [[ ! -f $out.stop ]]; do
      a=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --resolve "$HOST:443:127.0.0.1" "https://$HOST/" || true)
      b=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --resolve "$HOST:443:127.0.0.1" "https://$HOST/api/v1/health" || true)
      printf '%s %s %s\n' "$(date -u +%T)" "$a" "$b" >>"$out"
      sleep 1
    done
  ) &
  PROBE_PID=$!
}
probe_stop() { # probe_stop <file> -> "probes failures"
  touch "$1.stop"; wait "$PROBE_PID" 2>/dev/null || true; rm -f "$1.stop"; PROBE_PID=
  awk '{n++; if ($2 != 200 || $3 != 200) f++} END {printf "%d %d\n", n, f}' "$1"
}

# ---- gates on the serving colour -------------------------------------------------------------
FAILED=()
gate() { # gate <name> <description> <cmd...>
  local name=$1 what=$2; shift 2
  local out; if out=$("$@" 2>&1); then
    log "GATE $name ok: $what${out:+ ($(tail -1 <<<"$out"))}"
  else
    log "GATE $name FAILED: $what: $(tail -3 <<<"$out" | tr '\n' ' ')"
    FAILED+=("$name")
  fi
}

g_health() {
  local c; c=$(active_color)
  [[ -n $c ]] || { echo "no active colour"; return 1; }
  curl -fsS --max-time 5 "http://127.0.0.1:${PORT[$c]}/api/v1/health" | grep -q '"status":"ok"' ||
    { echo "colour $c unhealthy"; return 1; }
  curl -fsS --max-time 5 --resolve "$HOST:443:127.0.0.1" "https://$HOST/api/v1/health" | grep -q '"status":"ok"' ||
    { echo "nginx path unhealthy"; return 1; }
  echo "colour $c and nginx healthy"
}

g_no_internet() { # api and api-worker: no DNS, no route to a public IP
  local c svc; c=$(active_color)
  for svc in api api-worker; do
    docker exec -i "guardhub-$c-$svc-1" python - <<'PY' || { echo "$svc reaches the internet"; return 1; }
import socket, sys
try:
    socket.getaddrinfo("example.com", 443)
    sys.exit("DNS resolved example.com")
except OSError:
    pass
s = socket.socket(); s.settimeout(5)
try:
    s.connect(("1.1.1.1", 443))
    sys.exit("connected to 1.1.1.1:443")
except OSError:
    pass
PY
  done
  echo "api, api-worker: no DNS, no route out"
}

g_egress_allowlist() { # github-egress: CONNECT only to the allow-list
  local c; c=$(active_color)
  docker exec -i "guardhub-$c-api-1" python - <<'PY'
import socket, sys
def connect(host):
    s = socket.create_connection(("github-egress", 8888), timeout=10)
    s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    line = s.recv(256).split(b"\r\n")[0].decode(errors="replace"); s.close(); return line
ok, bad = connect("api.github.com"), connect("example.com")
if " 200" not in ok: sys.exit(f"api.github.com refused: {ok}")
if " 200" in bad: sys.exit(f"example.com allowed: {bad}")
print(f"api.github.com -> {ok}; example.com -> {bad}")
PY
}

g_exposure() { # GuardHub publishes only loopback ports; postgres/redis publish nothing
  local bad
  bad=$(docker ps --format '{{.Names}} {{.Ports}}' | grep -E '^guardhub-' |
    awk '/(0\.0\.0\.0|\[::\]|:::)[0-9]*->/ || ($1 ~ /postgres|redis/ && /->/)' || true)
  [[ -z $bad ]] || { echo "exposed: $bad"; return 1; }
  echo "only 127.0.0.1 ports published"
}

g_neighbours() {
  diff <(cat "$1") <(neighbours) >/dev/null || { diff <(cat "$1") <(neighbours); return 1; }
  echo "$(wc -l <"$1") other containers unchanged"
}

g_secrets() { # C: the env file stays root-only; images carry the signed revision
  [[ $(stat -c '%a %U' "$ENV_FILE") == "600 root" ]] || { echo "$ENV_FILE is $(stat -c '%a %U' "$ENV_FILE")"; return 1; }
  echo "$ENV_FILE 600 root"
}

g_selfscan() { # F: GuardHub scans its own site with the new scanner; critical/high blocks
  local v=$1 token saved rc=0
  token=ghv_cd_$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
  saved=$(mktemp); cp -p "$SELFVERIFY" "$saved" 2>/dev/null || : >"$saved"
  install -m 644 /dev/stdin "$SELFVERIFY" <<<"$token"
  docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    "guardhub-scanner:$v" selfscan "$PUBLIC" "$token" || rc=$?
  install -m 644 "$saved" "$SELFVERIFY"; rm -f "$saved"
  ((rc == 0)) || { echo "selfscan exit $rc"; return 1; }
}

g_sentry() { # H: one accepted test event per service
  local c; c=$(active_color)
  docker exec "guardhub-$c-api-1" python -m guardhub_api.common.observability test-event || return 1
  docker exec "guardhub-$c-api-worker-1" python -m guardhub_api.common.observability test-event --service api-worker ||
    return 1
  docker exec "guardhub-$c-scanner-1" /usr/local/bin/scanner sentry-test || return 1
  docker exec "guardhub-$c-web-1" node apps/web/scripts/sentry-test.mjs || return 1
}

g_smoke() { # J (HTTP level): the public pages in en and tr, and the checks catalogue
  local u code body
  for u in / /scan /account/login /account/register; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --resolve "$HOST:443:127.0.0.1" "https://$HOST$u")
    [[ $code == 200 ]] || { echo "$u -> $code"; return 1; }
  done
  body=$(curl -sS --max-time 10 --resolve "$HOST:443:127.0.0.1" -H 'Cookie: NEXT_LOCALE=tr' "https://$HOST/scan")
  grep -q 'lang="tr"' <<<"$body" || { echo "/scan in tr is not Turkish"; return 1; }
  curl -fsS --max-time 10 --resolve "$HOST:443:127.0.0.1" "https://$HOST/api/v1/checks" | grep -q '"exposed_env"' ||
    { echo "/api/v1/checks has no catalogue"; return 1; }
  echo "/, /scan, /account/login, /account/register 200; tr locale; checks catalogue"
}

g_backup() { # G: activate's pre-deploy dump exists, is fresh (deploy: < 1h) and matches its manifest
  local d; d=$(ls -t "$ROOT"/backups/guardhub-*.dump 2>/dev/null | head -1)
  [[ -n $d && -f $d.manifest ]] || { echo "no dump"; return 1; }
  (($(date +%s) - $(stat -c %Y "$d") < ${1:-3600})) || { echo "newest dump $d is older than ${1:-3600}s"; return 1; }
  [[ $(grep '^sha256=' "$d.manifest" | cut -d= -f2) == "$(sha256sum "$d" | cut -d' ' -f1)" ]] || { echo "sha256 mismatch"; return 1; }
  echo "$(basename "$d") sha256 ok; off-site: $(cat "$STATE/offsite-predeploy.status" 2>/dev/null || echo none)"
}

run_gates() { # run_gates <version> <neighbours-snapshot>
  FAILED=()
  gate E-health "serving colour + nginx health" g_health
  gate E-no-internet "api has no internet" g_no_internet
  gate E-egress "github-egress allow-list" g_egress_allowlist
  gate E-exposure "no public DB/Redis/app ports" g_exposure
  gate E-neighbours "other projects untouched" g_neighbours "$2"
  gate C-secrets "env file root-only" g_secrets
  gate F-selfscan "self-scan, no critical/high" g_selfscan "$1"
  gate H-sentry "test events accepted" g_sentry
  gate J-smoke "public pages en+tr, API" g_smoke
  gate G-backup "pre-deploy backup" g_backup "${3:-3600}"
}

prune_images() { # keep the images of the current, previous and both colours' releases
  local keep v
  keep=" $(current_version) $(basename "$(readlink -f "$ROOT/previous" 2>/dev/null)" 2>/dev/null) $(cat "$STATE"/blue.version "$STATE"/green.version 2>/dev/null | tr '\n' ' ') "
  docker image ls --format '{{.Repository}}:{{.Tag}}' |
    grep -E "^(guardhub-(api|scanner|web)|$REG/guardhub-(api|scanner|web)):[0-9a-f]{12}$" |
    while read -r ref; do
      v=${ref##*:}; [[ $keep == *" $v "* ]] || docker image rm "$ref" >/dev/null 2>&1 || true
    done
}

cmd_deploy() {
  local sha=${1:?sha}; [[ $sha =~ ^[0-9a-f]{40}$ ]] || die "need a full 40-character sha"
  local v=${sha::12} cur ts report probes snap ctl n f
  cur=$(current_version)
  ts=$(date -u +%Y%m%dT%H%M%SZ); report=$CDS/runs/$v-$ts.log
  exec 2> >(tee -a "$report" >&2)
  # any unexpected exit (a `die` in a helper) also halts CD and never leaves a probe loop behind
  trap 'rc=$?; [[ -n $PROBE_PID ]] && kill "$PROBE_PID" 2>/dev/null
        if ((rc)) && [[ ! -f $CDS/halt ]]; then halt "'"$v"': CD stopped (exit $rc), report '"$report"'"; fi' EXIT
  log "== CD deploy $v (serving: ${cur:-none}, colour $(active_color))"
  ci_green "$sha" || { halt "$v: CI run not green"; exit 1; }
  fetch_release "$sha"
  if [[ -n $cur ]]; then
    local cur_sha; cur_sha=$(git --git-dir="$GITDIR" rev-parse -q --verify "$cur^{commit}" || true)
    [[ -n $cur_sha ]] && ! git --git-dir="$GITDIR" merge-base --is-ancestor "$cur_sha" "$sha" &&
      { halt "$v does not descend from the serving $cur (no silent downgrade)"; exit 1; }
  fi
  pull_verified "$sha" || { halt "$v: image pull/signature failed"; exit 1; }
  ctl="bash $ROOT/releases/$v/ops/deploy/guardhub-ctl.sh"
  snap=$CDS/neighbours-$ts; neighbours >"$snap"
  probes=$CDS/runs/$v-$ts.probes
  probe_start "$probes"
  if ! $ctl activate "$v"; then
    # activate switches nginx only after the new colour is healthy; if it died AFTER the switch
    # (public health through nginx failed), put the previous upstream back.
    local up; up=$ROOT/shared/nginx-upstream.conf
    if [[ -f $up.bak ]] && ! grep -q ":${PORT[$(active_color)]} " "$up"; then
      cp -p "$up.bak" "$up" && nginx -t && systemctl reload nginx && log "restored the previous nginx upstream"
    fi
    read -r n f <<<"$(probe_stop "$probes")"
    halt "$v: activate failed (K: $n probes, $f failed); ${cur:-nothing} keeps serving"; exit 1
  fi
  run_gates "$v" "$snap"
  sleep "$PROBE_TAIL"
  read -r n f <<<"$(probe_stop "$probes")"
  if ((f == 0 && n > 0)); then log "GATE K ok: $n probes, 0 failed (deploy window)"; else
    log "GATE K FAILED: $n probes, $f failed"; FAILED+=(K); fi
  if ((${#FAILED[@]})); then
    log "RED: ${FAILED[*]} -> automatic rollback"
    probe_start "$probes.rollback"
    $ctl rollback || log "ROLLBACK FAILED: needs a human now"
    sleep 10
    read -r n f <<<"$(probe_stop "$probes.rollback")"
    log "rollback window: $n probes, $f failed; serving $(current_version) in $(active_color)"
    halt "$v: gates ${FAILED[*]} red; rolled back to $(current_version) (report $report)"
    exit 1
  fi
  install -D -m 700 "$ROOT/releases/$v/ops/deploy/cd.sh" "$ROOT/cd/cd.sh"
  install -m 644 "$ROOT/releases/$v/ops/deploy/guardhub-cd.cron" /etc/cron.d/guardhub-cd
  prune_images
  printf '%s %s ok %s\n' "$(date -u +%FT%TZ)" "$v" "$report" >"$CDS/last"
  log "== LIVE: $v in $(active_color); gates A-K green (report $report)"
}

cmd_tick() {
  exec 9>"$CDS/lock"; flock -n 9 || exit 0
  if [[ -f $CDS/halt ]]; then exit 0; fi
  local line sha concl
  line=$(newest_main_run) || { log "GitHub API unavailable; next tick"; exit 0; }
  read -r sha concl <<<"$line"
  [[ -n ${sha:-} ]] || exit 0
  [[ ${sha::12} == "$(current_version)" ]] && exit 0
  if [[ $concl != success ]]; then
    [[ $(cat "$CDS/seen-red" 2>/dev/null) == "$sha" ]] || { log "newest main run $sha is $concl: not deploying"; echo "$sha" >"$CDS/seen-red"; }
    exit 0
  fi
  cmd_deploy "$sha"
}

cmd_verify() {
  local snap; snap=$(mktemp); neighbours >"$snap"
  run_gates "$(current_version)" "$snap" 172800; rm -f "$snap" # verify: the nightly dump counts
  ((${#FAILED[@]} == 0)) || die "red: ${FAILED[*]}"
  log "all gates green on $(current_version)"
}

cmd_status() {
  echo "serving: $(current_version) in $(active_color)"
  echo "last: $(cat "$CDS/last" 2>/dev/null || echo none)"
  if [[ -f $CDS/halt ]]; then echo "HALTED: $(cat "$CDS/halt")"; else echo "halt: no"; fi
}

case ${1:-} in
  tick) cmd_tick ;;
  deploy) exec 9>"$CDS/lock"; flock -n 9 || die "another CD run holds the lock"; cmd_deploy "${2:-}" ;;
  verify) cmd_verify ;;
  status) cmd_status ;;
  resume) rm -f "$CDS/halt" "$CDS/seen-red"; log "halt cleared by $(logname 2>/dev/null || echo root)" ;;
  *) sed -n '2,22p' "$0"; exit 2 ;;
esac
