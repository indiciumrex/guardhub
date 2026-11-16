#!/usr/bin/env bash
# GuardHub production control, run ON the server (shared host, see ops/runbooks/production.md).
#
#   guardhub-ctl.sh activate <version>   pre-deploy backup → start <version> → health gate;
#                                        on failure, automatically go back to the running version
#   guardhub-ctl.sh rollback             go back to the previous release (DB downgraded if needed)
#   guardhub-ctl.sh backup               pg_dump (custom format) + manifest, 14-day retention
#   guardhub-ctl.sh restore-drill [dump] restore into a throwaway, network-isolated Postgres and
#                                        PROVE it: row counts, schema version, RLS, audit trigger,
#                                        and that encrypted data decrypts with the production key
#   guardhub-ctl.sh status
#
# Everything is scoped to /opt/guardhub and the compose project "guardhub". Nothing here touches
# other projects' containers, networks, volumes or the host's databases.
set -Eeuo pipefail
umask 077

ROOT=/opt/guardhub
ENV_FILE=$ROOT/shared/.env
BACKUPS=$ROOT/backups
RETENTION_DAYS=14
HEALTH_TIMEOUT=240
DRILL=guardhub-restore-drill # name of the throwaway container AND its internal network

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[[ -f $ENV_FILE ]] || die "missing $ENV_FILE"
envval() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2-; }

release_dir() { echo "$ROOT/releases/$1"; }
current_version() { [[ -L $ROOT/current ]] && basename "$(readlink -f "$ROOT/current")" || true; }
previous_version() { [[ -L $ROOT/previous ]] && basename "$(readlink -f "$ROOT/previous")" || true; }

compose() { # compose <version> args...
  local v=$1; shift
  local dir; dir=$(release_dir "$v")
  [[ -d $dir ]] || die "no release $v"
  GUARDHUB_VERSION=$v docker compose --project-name guardhub --project-directory "$dir" \
    --env-file "$ENV_FILE" -f "$dir/docker-compose.yml" -f "$dir/docker-compose.prod.yml" "$@"
}

health_ok() {
  local port; port=$(envval WEB_PORT)
  curl -fsS --max-time 5 "http://127.0.0.1:${port}/api/v1/health" 2>/dev/null | grep -q '"status":"ok"'
}

wait_healthy() {
  local deadline=$((SECONDS + HEALTH_TIMEOUT))
  until health_ok; do
    ((SECONDS < deadline)) || return 1
    sleep 3
  done
}

start() { # start <version>
  local v=$1
  # stable copy of the DB init script (see docker-compose.prod.yml): no DB restart per release
  install -D -m 755 "$(release_dir "$v")/ops/docker/postgres/10-app-role.sh" "$ROOT/shared/postgres-init/10-app-role.sh"
  for img in api scanner web; do
    docker image inspect "guardhub-$img:$v" >/dev/null 2>&1 || die "image guardhub-$img:$v not loaded"
  done
  compose "$v" up -d --no-build --remove-orphans
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

# Make the DB schema match <target>'s migrations before starting it (rollback across a migration).
align_schema_for() {
  local target=$1 running=$2
  db_is_up || return 0
  local target_head current
  target_head=$(compose "$target" run --rm --no-deps -T migrate alembic -c /app/ops/migrations/alembic.ini heads 2>/dev/null | awk '{print $1}' | head -1)
  current=$(docker exec guardhub-postgres-1 psql -U "$(envval POSTGRES_USER)" -d "$(envval POSTGRES_DB)" -Atc 'SELECT version_num FROM alembic_version')
  if [[ -n $target_head && $target_head != "$current" ]]; then
    log "downgrading schema $current → $target_head using release $running"
    compose "$running" run --rm -T migrate alembic -c /app/ops/migrations/alembic.ini downgrade "$target_head"
  fi
}

cmd_activate() {
  local v=${1:?version}
  local cur; cur=$(current_version)
  [[ $v != "$cur" ]] || log "re-activating current version $v"
  cmd_backup >/dev/null
  log "starting $v (running: ${cur:-none})"
  if start "$v" && wait_healthy; then
    if [[ -n $cur && $cur != "$v" ]]; then ln -sfn "$(release_dir "$cur")" "$ROOT/previous"; fi
    ln -sfn "$(release_dir "$v")" "$ROOT/current"
    log "ACTIVE: $v (healthy)"
  else
    log "$v did not become healthy"
    compose "$v" ps >&2 || true
    if [[ -n $cur && $cur != "$v" ]]; then
      log "automatic rollback to $cur"
      align_schema_for "$cur" "$v"
      start "$cur" && wait_healthy && log "back on $cur (healthy)"
    fi
    die "activation of $v failed"
  fi
}

cmd_rollback() {
  local cur prev; cur=$(current_version); prev=$(previous_version)
  [[ -n $prev ]] || die "no previous release recorded"
  cmd_backup >/dev/null
  log "rolling back $cur → $prev"
  align_schema_for "$prev" "$cur"
  start "$prev"
  wait_healthy || die "previous release $prev is not healthy either; investigate now"
  ln -sfn "$(release_dir "$cur")" "$ROOT/previous"
  ln -sfn "$(release_dir "$prev")" "$ROOT/current"
  log "ROLLED BACK: now on $prev (healthy); $cur kept as previous"
}

cmd_status() {
  echo "current=$(current_version) previous=$(previous_version)"
  local v; v=$(current_version)
  [[ -n $v ]] && compose "$v" ps
  health_ok && echo "health: ok" || echo "health: NOT ok"
}

case ${1:-} in
  activate) cmd_activate "${2:-}" ;;
  rollback) cmd_rollback ;;
  backup) cmd_backup ;;
  restore-drill) cmd_restore_drill "${2:-}" ;;
  status) cmd_status ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
