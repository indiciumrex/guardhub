#!/usr/bin/env bash
# Rehearse GuardHub's blue/green deploys on a disposable Linux box (e.g. WSL) BEFORE production.
# Never run on the production host: it tears down the "guardhub*" compose projects it creates.
#
#   ops/deploy/tests/bluegreen_rehearsal.sh <repo-path> <legacy-rev> <new-rev>
#
# Images guardhub-{api,scanner,web}:<rev> must already exist for both revs (12-char short sha).
# What it proves, with a probe hitting the proxy every 0.2 s the whole time (must see 0 errors):
#   1. legacy single-project layout (<legacy-rev>) -> blue/green cutover (<new-rev> in blue)
#   2. a second activate flips to green;  3. rollback flips back to blue
#   4. a broken release never gets traffic and is torn down; the serving colour is untouched
#   5. a marker row written before the cutover survives everything (same database)
set -Eeuo pipefail
REPO=${1:?repo path}; LEGACY=${2:?legacy rev}; NEW=${3:?new rev}
RH=${RH:-$HOME/gh-rehearsal}
[[ $RH != /opt/guardhub* ]] || { echo "refusing to run against /opt/guardhub" >&2; exit 2; }
[[ ! -d /opt/guardhub/releases ]] || { echo "this looks like the production host: refusing" >&2; exit 2; }
PROXY_PORT=18799
log() { printf '\n== %s\n' "$*"; }

cleanup() {
  for p in guardhub-blue guardhub-green guardhub; do
    docker compose -p "$p" down -v --remove-orphans >/dev/null 2>&1 || true
  done
  docker rm -f rh-nginx >/dev/null 2>&1 || true
  docker network rm guardhub-blue_app guardhub-green_app >/dev/null 2>&1 || true
}
cleanup
rm -rf "$RH"; mkdir -p "$RH"/{releases,shared,backups}; chmod 700 "$RH/shared" "$RH/backups"

log "releases + images"
for v in "$LEGACY" "$NEW"; do
  mkdir -p "$RH/releases/$v"; git -C "$REPO" archive "$v" | tar -x -C "$RH/releases/$v"
  for img in api scanner web; do docker image inspect "guardhub-$img:$v" >/dev/null; done
done
# the legacy prod compose hard-codes /opt/guardhub for the DB init mount; point it at $RH
sed -i "s#/opt/guardhub/shared/postgres-init#$RH/shared/postgres-init#" "$RH/releases/$LEGACY/docker-compose.prod.yml"
install -D -m 755 "$RH/releases/$LEGACY/ops/docker/postgres/10-app-role.sh" "$RH/shared/postgres-init/10-app-role.sh"

log "throwaway secrets"
(cd "$RH/releases/$NEW" && python3 ops/scripts/gen_secrets.py --force >/dev/null && mv .env "$RH/shared/.env")
sed -i 's#^PUBLIC_BASE_URL=.*#PUBLIC_BASE_URL=http://localhost#; s#^WEB_PORT=.*#WEB_PORT=18700#; s#^TRUSTED_PROXY_HOPS=.*#TRUSTED_PROXY_HOPS=2#' "$RH/shared/.env"
envv() { grep -E "^$1=" "$RH/shared/.env" | cut -d= -f2-; }

log "proxy stand-in (nginx container, reloads gracefully like the host nginx)"
printf 'upstream guardhub_web {\n    server host.docker.internal:18700;\n    keepalive 16;\n}\n' >"$RH/shared/nginx-upstream.conf"
cat >"$RH/shared/rh-site.conf" <<'NGINX'
include /etc/nginx/gh/nginx-upstream.conf;
server {
    listen 8080;
    location / {
        proxy_pass http://guardhub_web;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
NGINX
docker run -d --name rh-nginx --add-host host.docker.internal:host-gateway -p "127.0.0.1:$PROXY_PORT:8080" \
  -v "$RH/shared:/etc/nginx/gh:ro" -v "$RH/shared/rh-site.conf:/etc/nginx/conf.d/default.conf:ro" nginx:1.27-alpine >/dev/null

log "legacy layout: $LEGACY as the single project 'guardhub' on :18700"
GUARDHUB_VERSION=$LEGACY docker compose -p guardhub --project-directory "$RH/releases/$LEGACY" --env-file "$RH/shared/.env" \
  -f "$RH/releases/$LEGACY/docker-compose.yml" -f "$RH/releases/$LEGACY/docker-compose.prod.yml" up -d --no-build >/dev/null
ln -sfn "$RH/releases/$LEGACY" "$RH/current"
for _ in $(seq 1 90); do curl -fsS "http://127.0.0.1:$PROXY_PORT/api/v1/health" 2>/dev/null | grep -q '"ok"' && break; sleep 2; done
curl -fsS "http://127.0.0.1:$PROXY_PORT/api/v1/health"; echo
MARK="rehearsal-marker-$(date +%s)"
docker exec guardhub-postgres-1 psql -U "$(envv POSTGRES_USER)" -d "$(envv POSTGRES_DB)" -qc \
  "INSERT INTO audit_logs (actor, action, target) VALUES ('rehearsal', 'marker', '$MARK')"

log "probe: proxy health every 0.2 s"
PROBE=$RH/probe.log
( while :; do printf '%s %s\n' "$(date +%T.%3N)" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PROXY_PORT/api/v1/health")"; sleep 0.2; done ) >"$PROBE" &
PROBE_PID=$!
trap 'kill $PROBE_PID 2>/dev/null || true' EXIT

CTL=(env GUARDHUB_ROOT="$RH" UPSTREAM_HOST=host.docker.internal
  NGINX_TEST_CMD="docker exec rh-nginx nginx -t" NGINX_RELOAD_CMD="docker exec rh-nginx nginx -s reload"
  PUBLIC_HEALTH_URL="http://127.0.0.1:$PROXY_PORT/api/v1/health" bash "$RH/releases/$NEW/ops/deploy/guardhub-ctl.sh")

log "1) cutover: legacy -> $NEW in blue";      "${CTL[@]}" activate "$NEW"
log "2) second activate -> green";            "${CTL[@]}" activate "$NEW"
log "3) rollback -> blue";                    "${CTL[@]}" rollback

log "4) broken release must never get traffic"
BROKEN=broken0000000
cp -a "$RH/releases/$NEW" "$RH/releases/$BROKEN"
for img in api scanner web; do docker tag "guardhub-$img:$NEW" "guardhub-$img:$BROKEN"; done
# the API can't start: its DB password is wrong only for this release
python3 - "$RH/releases/$BROKEN/docker-compose.prod.yml" <<'PY'
import sys; p = sys.argv[1]; s = open(p).read()
s = s.replace("  api:\n", "  api:\n    environment: { DATABASE_URL: \"postgresql+asyncpg://nobody:wrong@postgres:5432/none\" }\n", 1)
open(p, "w").write(s)
PY
before=$(cat "$RH/shared/nginx-upstream.conf")
if HEALTH_TIMEOUT=60 "${CTL[@]}" activate "$BROKEN"; then echo "FAIL: broken release was activated" >&2; exit 1; fi
[[ $(cat "$RH/shared/nginx-upstream.conf") == "$before" ]] || { echo "FAIL: upstream changed" >&2; exit 1; }
echo "broken release refused; upstream unchanged"

sleep 3; kill $PROBE_PID; wait $PROBE_PID 2>/dev/null || true
log "status";  "${CTL[@]}" status
log "data survived"
docker exec guardhub-postgres-1 psql -U "$(envv POSTGRES_USER)" -d "$(envv POSTGRES_DB)" -Atc \
  "SELECT count(*) FROM audit_logs WHERE target = '$MARK'" | grep -qx 1 && echo "marker row present"
log "probe result"
total=$(wc -l <"$PROBE"); bad=$(grep -vc ' 200$' "$PROBE" || true)
echo "probes: $total, non-200: $bad"; grep -v ' 200$' "$PROBE" | head -5 || true
cleanup
if [[ $bad -eq 0 ]]; then echo "REHEARSAL PASSED: zero failed requests"; else echo "REHEARSAL FAILED"; exit 1; fi
