#!/usr/bin/env bash
# GuardHub production control, run ON the server (shared host, see ops/runbooks/production.md).
#
#   guardhub-ctl.sh activate <version>   ZERO-DOWNTIME blue/green: pre-deploy backup -> expand-only
#                                        migration -> start <version> in the idle colour -> health
#                                        gate -> switch nginx (graceful reload) -> stop the old colour.
#                                        If the new colour is unhealthy, nothing is switched.
#   guardhub-ctl.sh rollback             start the previous colour, health gate, switch back
#   guardhub-ctl.sh backup               pg_dump (custom format) + manifest, 14-day retention
#   guardhub-ctl.sh restore-drill [dump] restore into a throwaway, network-isolated Postgres and
#                                        PROVE it: row counts, schema version, RLS, audit trigger,
#                                        and that encrypted data decrypts with the production key
#   guardhub-ctl.sh status
#   guardhub-ctl.sh exec <service> <cmd...>   run a command in the ACTIVE colour's container
#
# Layout: data layer (postgres, redis, sentry-relay) = compose project "guardhub"; app layer =
# "guardhub-blue" / "guardhub-green" on 127.0.0.1:18701 / 18702, joined to the data networks
# (ops/deploy/compose.color.yml). nginx proxies to the upstream in shared/nginx-upstream.conf.
# Migrations must be EXPAND-ONLY (the old colour keeps serving while the new one migrates).
# Everything is scoped to /opt/guardhub and the "guardhub*" compose projects. Nothing here
# touches other projects' containers, networks, volumes or the host's databases.
set -Eeuo pipefail
umask 077

ROOT=${GUARDHUB_ROOT:-/opt/guardhub}
export GUARDHUB_ROOT=$ROOT # docker-compose.prod.yml mounts the DB init script from here
# Rehearsal hooks (ops/deploy/tests/bluegreen_rehearsal.sh). Defaults = production behaviour.
NGINX_TEST_CMD=${NGINX_TEST_CMD:-nginx -t}
NGINX_RELOAD_CMD=${NGINX_RELOAD_CMD:-systemctl reload nginx}
UPSTREAM_HOST=${UPSTREAM_HOST:-127.0.0.1}
ENV_FILE=$ROOT/shared/.env
BACKUPS=$ROOT/backups
RETENTION_DAYS=14
HEALTH_TIMEOUT=240
DRILL=guardhub-restore-drill # name of the throwaway container AND its internal network

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[[ -f $ENV_FILE ]] || die "missing $ENV_FILE"
envval() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2-; }

STATE=$ROOT/state
UPSTREAM_CONF=$ROOT/shared/nginx-upstream.conf
declare -A PORT=([blue]=18701 [green]=18702)

release_dir() { echo "$ROOT/releases/$1"; }
current_version() { [[ -L $ROOT/current ]] && basename "$(readlink -f "$ROOT/current")" || true; }
previous_version() { [[ -L $ROOT/previous ]] && basename "$(readlink -f "$ROOT/previous")" || true; }
active_color() { cat "$STATE/active_color" 2>/dev/null || true; }
color_version() { cat "$STATE/$1.version" 2>/dev/null || true; }
other_color() { if [[ $1 == blue ]]; then echo green; else echo blue; fi; }

compose_data() { # compose_data <version> args...   (long-lived project "guardhub")
  local v=$1; shift
  local dir; dir=$(release_dir "$v"); [[ -d $dir ]] || die "no release $v"
  GUARDHUB_VERSION=$v docker compose --project-name guardhub --project-directory "$dir" \
    --env-file "$ENV_FILE" -f "$dir/docker-compose.yml" -f "$dir/docker-compose.prod.yml" "$@"
}

compose_color() { # compose_color <version> <blue|green> args...
  local v=$1 c=$2; shift 2
  local dir; dir=$(release_dir "$v"); [[ -d $dir ]] || die "no release $v"
  GUARDHUB_VERSION=$v WEB_PORT=${PORT[$c]} docker compose --project-name "guardhub-$c" \
    --project-directory "$dir" --env-file "$ENV_FILE" -f "$dir/docker-compose.yml" \
    -f "$dir/docker-compose.prod.yml" -f "$dir/ops/deploy/compose.color.yml" "$@"
}

# the services of a release, split into the long-lived data layer and the per-colour app layer
data_services() { compose_data "$1" config --services | grep -xE 'postgres|redis|sentry-relay' | tr '\n' ' '; }
app_services() {
  compose_data "$1" config --services | grep -vxE 'postgres|redis|sentry-relay|migrate|demo-target|mailpit' | tr '\n' ' '
}

health_on_port() {
  curl -fsS --max-time 5 "http://127.0.0.1:$1/api/v1/health" 2>/dev/null | grep -q '"status":"ok"'
}
public_health() { # through nginx, exactly like a visitor (without leaving the host)
  if [[ -n ${PUBLIC_HEALTH_URL:-} ]]; then
    curl -fsS --max-time 5 "$PUBLIC_HEALTH_URL" 2>/dev/null | grep -q '"status":"ok"'
    return
  fi
  local host; host=$(envval PUBLIC_BASE_URL | sed -E 's#^https?://##; s#/.*$##')
  curl -fsS --max-time 5 --resolve "$host:443:127.0.0.1" "https://$host/api/v1/health" 2>/dev/null |
    grep -q '"status":"ok"'
}
health_ok() { local c; c=$(active_color); [[ -n $c ]] && health_on_port "${PORT[$c]}"; }

wait_port_healthy() {
  local deadline=$((SECONDS + HEALTH_TIMEOUT))
  until health_on_port "$1"; do
    ((SECONDS < deadline)) || return 1
    sleep 3
  done
}

# Point nginx at 127.0.0.1:<port>. `nginx -t` first; a graceful reload lets in-flight requests
# finish on the old upstream, so the switch drops nothing.
switch_upstream() {
  local port=$1 tmp=$UPSTREAM_CONF.new
  # max_fails=0: with a single server, one failed request must never take the site out of
  # rotation for fail_timeout (nginx's default would). No upstream keepalive: a reused idle
  # connection that Node.js closes at the same moment surfaces as a 502 (seen in rehearsal).
  printf 'upstream guardhub_web {\n    server %s:%s max_fails=0;\n}\n' "$UPSTREAM_HOST" "$port" >"$tmp"
  chmod 644 "$tmp"
  if [[ -f $UPSTREAM_CONF ]]; then cp -p "$UPSTREAM_CONF" "$UPSTREAM_CONF.bak"; fi
  mv -f "$tmp" "$UPSTREAM_CONF"
  if ! $NGINX_TEST_CMD >/dev/null 2>&1; then
    if [[ -f $UPSTREAM_CONF.bak ]]; then mv -f "$UPSTREAM_CONF.bak" "$UPSTREAM_CONF"; fi
    die "nginx -t failed after the upstream change; restored the previous upstream"
  fi
  $NGINX_RELOAD_CMD
  local i; for i in $(seq 1 10); do public_health && return 0; sleep 1; done
  die "public health check failed after switching nginx to port $port"
}

check_images() {
  local img; for img in api scanner web; do
    docker image inspect "guardhub-$img:$1" >/dev/null 2>&1 || die "image guardhub-$img:$1 not loaded"
  done
}

db_is_up() { docker ps --format '{{.Names}}' | grep -qx guardhub-postgres-1; }

cmd_backup() {
  db_is_up || { log "no database running yet, nothing to back up"; return 0; }
  mkdir -p "$BACKUPS"; chmod 700 "$BACKUPS"
  local ts file user db
  ts=$(date -u +%Y%m%dT%H%M%SZ); file=$BACKUPS/guardhub-$ts.dump
  user=$(envval POSTGRES_USER); db=$(envval POSTGRES_DB)
  local counts_sql="SELECT string_agg(t || '=' || n, ' ' ORDER BY t) FROM (
      SELECT 'users' t, count(*) n FROM users UNION ALL SELECT 'projects', count(*) FROM projects
      UNION ALL SELECT 'scans', count(*) FROM scans UNION ALL SELECT 'findings', count(*) FROM findings
      UNION ALL SELECT 'evidence', count(*) FROM evidence UNION ALL SELECT 'modules', count(*) FROM modules
      UNION ALL SELECT 'audit_logs', count(*) FROM audit_logs) c;"
  local before after attempt
  for attempt in 1 2 3; do
    before=$(docker exec guardhub-postgres-1 psql -U "$user" -d "$db" -Atc "$counts_sql")
    docker exec guardhub-postgres-1 pg_dump -U "$user" -d "$db" -Fc --no-owner >"$file.tmp"
    after=$(docker exec guardhub-postgres-1 psql -U "$user" -d "$db" -Atc "$counts_sql")
    [[ $before == "$after" ]] && break
    log "writes during dump (attempt $attempt), retrying for an exact manifest"
  done
  [[ $before == "$after" ]] || die "could not get a quiet window for an exact manifest"
  mv "$file.tmp" "$file"
  {
    echo "counts=$after"
    echo "alembic=$(docker exec guardhub-postgres-1 psql -U "$user" -d "$db" -Atc 'SELECT version_num FROM alembic_version')"
    echo "release=$(current_version)"
    echo "sha256=$(sha256sum "$file" | cut -d' ' -f1)"
  } >"$file.manifest"
  find "$BACKUPS" -name 'guardhub-*.dump*' -mtime +"$RETENTION_DAYS" -delete
  log "backup written: $file ($(du -h "$file" | cut -f1))"
  echo "$file"
}

drill_cleanup() { # globals only: also runs from the EXIT trap, after locals are gone
  docker rm -f "$DRILL" >/dev/null 2>&1 || true
  docker network rm "$DRILL" >/dev/null 2>&1 || true
}

cmd_restore_drill() {
  local dump=${1:-$(ls -1t "$BACKUPS"/guardhub-*.dump 2>/dev/null | head -1)}
  [[ -f $dump && -f $dump.manifest ]] || die "no backup (with manifest) to restore"
  local expected_counts expected_alembic expected_sha
  expected_counts=$(grep '^counts=' "$dump.manifest" | cut -d= -f2-)
  expected_alembic=$(grep '^alembic=' "$dump.manifest" | cut -d= -f2-)
  expected_sha=$(grep '^sha256=' "$dump.manifest" | cut -d= -f2-)
  [[ $(sha256sum "$dump" | cut -d' ' -f1) == "$expected_sha" ]] || die "checksum mismatch: $dump"

  local name=$DRILL net=$DRILL pw
  pw=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
  drill_cleanup
  trap drill_cleanup EXIT
  # internal network: no internet, not reachable from the host, nothing published
  docker network create --internal "$net" >/dev/null
  docker run -d --name "$name" --network "$net" --memory 512m --cpus 0.5 \
    -e POSTGRES_USER=drill -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=restored \
    postgres:16-alpine >/dev/null
  local i; for i in $(seq 1 60); do docker exec "$name" pg_isready -U drill -d restored >/dev/null 2>&1 && break; sleep 1; done
  sleep 2
  docker exec "$name" psql -U drill -d restored -qc "CREATE ROLE $(envval GUARDHUB_APP_DB_USER) NOLOGIN" >/dev/null
  docker exec -i "$name" pg_restore -U drill -d restored --no-owner --exit-on-error <"$dump"
  log "restored $(basename "$dump") into an isolated throwaway database"

  local q="docker exec $name psql -U drill -d restored -Atc"
  local counts alembic rls trig
  counts=$($q "SELECT string_agg(t || '=' || n, ' ' ORDER BY t) FROM (
      SELECT 'users' t, count(*) n FROM users UNION ALL SELECT 'projects', count(*) FROM projects
      UNION ALL SELECT 'scans', count(*) FROM scans UNION ALL SELECT 'findings', count(*) FROM findings
      UNION ALL SELECT 'evidence', count(*) FROM evidence UNION ALL SELECT 'modules', count(*) FROM modules
      UNION ALL SELECT 'audit_logs', count(*) FROM audit_logs) c;")
  alembic=$($q "SELECT version_num FROM alembic_version")
  rls=$($q "SELECT count(*) FROM pg_class WHERE relkind='r' AND relrowsecurity AND relnamespace='public'::regnamespace")
  trig=$($q "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid='audit_logs'::regclass")

  local ok=1
  [[ $counts == "$expected_counts" ]] || { log "row counts differ: got [$counts] want [$expected_counts]"; ok=0; }
  [[ $alembic == "$expected_alembic" ]] || { log "schema version $alembic != $expected_alembic"; ok=0; }
  ((rls >= 8)) || { log "row-level security missing on restored tables ($rls)"; ok=0; }
  ((trig >= 1)) || { log "append-only audit trigger missing"; ok=0; }

  # The data must be USABLE, not just present: decrypt encrypted columns with the production key.
  local v; v=$(current_version)
  local decrypted
  decrypted=$(docker run --rm -i --network "$net" --read-only --cap-drop ALL --memory 256m \
    -e DSN="postgresql://drill:$pw@$name:5432/restored" \
    -e DATA_ENCRYPTION_KEY="$(envval DATA_ENCRYPTION_KEY)" \
    "guardhub-api:$v" python - <<'PY'
import asyncio, base64, os
import asyncpg
from guardhub_api.common.crypto import Cipher

async def main() -> None:
    c = Cipher(base64.b64decode(os.environ["DATA_ENCRYPTION_KEY"]))
    db = await asyncpg.connect(os.environ["DSN"])
    users = await db.fetch("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL")
    ev = await db.fetch("SELECT id, redacted_payload FROM evidence")
    for r in users:
        c.decrypt(r["totp_secret"], associated_data=str(r["id"]).encode())
    for r in ev:
        c.decrypt(r["redacted_payload"], associated_data=str(r["id"]).encode())
    print(f"totp={len(users)} evidence={len(ev)}")

asyncio.run(main())
PY
  ) || { log "encrypted data could NOT be decrypted with the production key"; ok=0; }

  if ((ok)); then
    log "RESTORE DRILL PASSED: $counts | schema $alembic | RLS tables $rls | audit trigger ok | decrypted $decrypted"
  else
    die "RESTORE DRILL FAILED"
  fi
}

legacy_running() { docker ps --format '{{.Names}}' | grep -qx guardhub-web-1; }

cmd_activate() {
  local v=${1:?version}
  check_images "$v"
  local cur_v cur_c new_c legacy=0 serving
  cur_v=$(current_version); cur_c=$(active_color)
  if [[ -z $cur_c ]]; then
    if legacy_running; then legacy=1; fi
    new_c=blue
  else
    new_c=$(other_color "$cur_c")
  fi
  serving=${cur_c:-none}; if ((legacy)); then serving=legacy; fi
  log "activating $v in $new_c (serving now: ${cur_v:-none} in $serving)"
  cmd_backup >/dev/null
  mkdir -p "$STATE"
  # stable copy of the DB init script (see docker-compose.prod.yml): no DB restart per release
  install -D -m 755 "$(release_dir "$v")/ops/docker/postgres/10-app-role.sh" "$ROOT/shared/postgres-init/10-app-role.sh"
  local data apps
  data=$(data_services "$v"); apps=$(app_services "$v")
  # shellcheck disable=SC2086 # word splitting of the service lists is intended
  compose_data "$v" up -d --no-build $data
  log "migrating schema (expand-only: the serving colour is unaffected)"
  compose_color "$v" "$new_c" run --rm --no-deps -T migrate || die "migration failed; nothing was switched"
  # shellcheck disable=SC2086
  if ! compose_color "$v" "$new_c" up -d --no-build --no-deps --remove-orphans $apps ||
    ! wait_port_healthy "${PORT[$new_c]}"; then
    compose_color "$v" "$new_c" ps >&2 || true
    compose_color "$v" "$new_c" down >&2 || true
    die "$v did not become healthy in $new_c; nothing was switched, ${cur_v:-nothing} keeps serving"
  fi
  switch_upstream "${PORT[$new_c]}"
  if ((legacy)); then
    log "retiring the pre-blue/green app containers (data layer untouched)"
    compose_data "$cur_v" rm -sf api api-worker scanner web >&2
  elif [[ -n $cur_c ]]; then
    compose_color "$(color_version "$cur_c")" "$cur_c" stop >&2
  fi
  echo "$new_c" >"$STATE/active_color"
  echo "$v" >"$STATE/$new_c.version"
  if [[ -n $cur_v && $cur_v != "$v" ]]; then ln -sfn "$(release_dir "$cur_v")" "$ROOT/previous"; fi
  ln -sfn "$(release_dir "$v")" "$ROOT/current"
  log "ACTIVE: $v in $new_c (healthy, serving)"
}

cmd_rollback() {
  local cur_c prev_c cur_v prev_v
  cur_c=$(active_color); [[ -n $cur_c ]] || die "no active colour recorded"
  prev_c=$(other_color "$cur_c"); cur_v=$(color_version "$cur_c"); prev_v=$(color_version "$prev_c")
  [[ -n $prev_v ]] || die "no previous release recorded in $prev_c"
  cmd_backup >/dev/null
  log "rolling back $cur_v ($cur_c) -> $prev_v ($prev_c); schema is left as is (expand-only)"
  local apps; apps=$(app_services "$prev_v")
  # shellcheck disable=SC2086
  compose_color "$prev_v" "$prev_c" up -d --no-build --no-deps $apps
  wait_port_healthy "${PORT[$prev_c]}" || die "previous release $prev_v is not healthy; $cur_v keeps serving"
  switch_upstream "${PORT[$prev_c]}"
  compose_color "$cur_v" "$cur_c" stop >&2
  echo "$prev_c" >"$STATE/active_color"
  ln -sfn "$(release_dir "$cur_v")" "$ROOT/previous"
  ln -sfn "$(release_dir "$prev_v")" "$ROOT/current"
  log "ROLLED BACK: $prev_v serving from $prev_c; $cur_v kept (stopped) in $cur_c"
}

cmd_status() {
  local c; c=$(active_color)
  echo "active=${c:-none} current=$(current_version) previous=$(previous_version)"
  echo "blue=$(color_version blue) green=$(color_version green)"
  echo "upstream: $(grep -oE 'server [^;]+' "$UPSTREAM_CONF" 2>/dev/null || echo none)"
  docker ps -a --format '{{.Names}}\t{{.Status}}' | grep -E '^guardhub-' | sort
  if health_ok; then echo "active colour health: ok"; else echo "active colour health: NOT ok"; fi
  if public_health; then echo "public health: ok"; else echo "public health: NOT ok"; fi
}

cmd_exec() { # exec <service> <cmd...> in the active colour
  local svc=${1:?service}; shift
  local c; c=$(active_color); [[ -n $c ]] || die "no active colour"
  docker exec -i "guardhub-$c-$svc-1" "$@"
}

case ${1:-} in
  activate) cmd_activate "${2:-}" ;;
  rollback) cmd_rollback ;;
  backup) cmd_backup ;;
  restore-drill) cmd_restore_drill "${2:-}" ;;
  status) cmd_status ;;
  exec) shift; cmd_exec "$@" ;;
  *) sed -n '2,24p' "$0"; exit 2 ;;
esac
