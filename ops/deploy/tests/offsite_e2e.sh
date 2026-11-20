#!/usr/bin/env bash
# End-to-end proof of encrypted off-site backups, entirely local and throwaway:
#   MinIO (S3) + a migrated Postgres with sample rows (incl. encrypted columns, some under a
#   PREVIOUS key) → guardhub-ctl.sh backup (local dump + restic push) → wipe local dumps →
#   guardhub-ctl.sh restore-drill --offsite → PASS; then a wrong RESTIC_PASSWORD must fail and the
#   raw bucket objects must contain no plaintext.
#
#   bash ops/deploy/tests/offsite_e2e.sh        (needs docker; builds the api image from this tree)
#   E2E_API_IMAGE=guardhub-api:local bash ...   (reuse an already built api image instead)
#
# Every container/network it creates is named gh-ops-e2e-*; all are removed on exit. Every
# credential is generated at random per run (nothing secret is stored in the repository).
set -Eeuo pipefail
# On Linux run it as root, like guardhub-ctl.sh in production: dumps are mode 600 and the restic
# container (root, all capabilities dropped) can only read them when root owns them.
if [[ $(uname -s) == Linux && $(id -u) != 0 ]]; then
  echo "run as root on Linux (e.g. wsl -u root), like production" >&2
  exit 2
fi
export MSYS_NO_PATHCONV=1 MSYS=winsymlinks:nativestrict # Windows/Git Bash only; no-ops elsewhere

REPO=$(cd "$(dirname "$0")/../../.." && pwd)
CTL=$REPO/ops/deploy/guardhub-ctl.sh
OFFSITE=$REPO/ops/deploy/offsite.sh
P=gh-ops-e2e
NET=$P-net MINIO=$P-minio PG=$P-pg DRILL=$P-drill
# MinIO no longer publishes official images; this is the maintained community build of the same
# AGPL server (test-only, never deployed), pinned by tag + digest.
MINIO_IMAGE=pgsty/minio:RELEASE.2026-08-04T00-00-00Z@sha256:b6bfe7239bfc83fb90d31612d9704d86039dd714f7904b3f1ad68f211e602372
PG_IMAGE=postgres:16-alpine

rand() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf "%s" "$1"; fi; }
key32() { head -c 32 /dev/urandom | base64; }
step() { printf '\n=== %s\n' "$*"; }
fail() { printf '\nE2E FAILED: %s\n' "$*" >&2; exit 1; }

# The release name ends up in every manifest: a unique marker to look for in the raw bucket.
REL=ghopsmarker$(rand 16 | tr '[:upper:]' '[:lower:]')
API_IMAGE=guardhub-api:$REL # the drill runs guardhub-api:<current release>
WORK=$(mktemp -d)
ROOT=$WORK/root

cleanup() {
  docker rm -f "$MINIO" "$PG" "$DRILL" >/dev/null 2>&1 || true
  docker network rm "$NET" "$DRILL" >/dev/null 2>&1 || true
  docker rmi "$API_IMAGE" >/dev/null 2>&1 || true # removes only this run's tag
  rm -rf "$WORK"
}
trap cleanup EXIT
cleanup_prev() { docker rm -f "$MINIO" "$PG" "$DRILL" >/dev/null 2>&1 || true; docker network rm "$NET" "$DRILL" >/dev/null 2>&1 || true; }
cleanup_prev

step "api image $API_IMAGE"
if [[ -n ${E2E_API_IMAGE:-} ]]; then
  docker tag "$E2E_API_IMAGE" "$API_IMAGE"
else
  docker build -q -t "$API_IMAGE" -f "$(hostpath "$REPO/apps/api/Dockerfile")" "$(hostpath "$REPO")" >/dev/null
fi

step "throwaway GUARDHUB_ROOT, MinIO and Postgres"
mkdir -p "$ROOT/shared" "$ROOT/releases/$REL"
ln -s "$ROOT/releases/$REL" "$ROOT/current"
[[ -L $ROOT/current ]] || fail "could not create the current symlink"
MINIO_USER=e2e$(rand 12) MINIO_PASS=$(rand 32) PG_PASS=$(rand 24)
# shell/compose-hostile characters on purpose: the off-site file is read literally
RESTIC_PW="$(rand 20)\$HOME#x!&*()~?^%+@\$(id)$(rand 20)"
OLD_KEY=$(key32) NEW_KEY=$(key32)
cat >"$ROOT/shared/.env" <<EOF
POSTGRES_USER=owner
POSTGRES_DB=guardhub
GUARDHUB_APP_DB_USER=guardhub_app
WEB_PORT=1
DATA_ENCRYPTION_KEY=$NEW_KEY
DATA_ENCRYPTION_KEYS_PREVIOUS=$OLD_KEY
EOF
# off-site settings in their own file (never read by docker compose)
cat >"$ROOT/shared/offsite.env" <<EOF
RESTIC_REPOSITORY=s3:http://$MINIO:9000/guardhub-e2e/repo
RESTIC_PASSWORD=$RESTIC_PW
AWS_ACCESS_KEY_ID=$MINIO_USER
AWS_SECRET_ACCESS_KEY=$MINIO_PASS
AWS_DEFAULT_REGION=us-east-1
EOF
cp "$ROOT/shared/.env" "$WORK/env.good"
cp "$ROOT/shared/offsite.env" "$WORK/offsite.good"
grep -qF 'RESTIC_PASSWORD=' "$ROOT/shared/offsite.env" && grep -qF '$HOME#x!&*()~?^%+@$(id)' "$ROOT/shared/offsite.env" ||
  fail "test setup: the special-character password was not written literally"

docker network create "$NET" >/dev/null
MINIO_ROOT_USER=$MINIO_USER MINIO_ROOT_PASSWORD=$MINIO_PASS \
  docker run -d --name "$MINIO" --network "$NET" -e MINIO_ROOT_USER -e MINIO_ROOT_PASSWORD \
  "$MINIO_IMAGE" server /data >/dev/null
POSTGRES_PASSWORD=$PG_PASS docker run -d --name "$PG" --network "$NET" -e POSTGRES_USER=owner \
  -e POSTGRES_PASSWORD -e POSTGRES_DB=guardhub "$PG_IMAGE" >/dev/null
for _ in $(seq 1 60); do
  docker exec "$MINIO" curl -fsS http://127.0.0.1:9000/minio/health/ready >/dev/null 2>&1 &&
    docker exec "$PG" pg_isready -U owner -d guardhub >/dev/null 2>&1 && break
  sleep 1
done
sleep 2
docker exec "$PG" psql -U owner -d guardhub -qc "CREATE ROLE guardhub_app LOGIN PASSWORD '$(rand 20)' NOBYPASSRLS"
MIGRATIONS_DATABASE_URL="postgresql+asyncpg://owner:$PG_PASS@$PG:5432/guardhub" \
  docker run --rm --network "$NET" -e MIGRATIONS_DATABASE_URL -e GUARDHUB_APP_DB_USER=guardhub_app \
  "$API_IMAGE" alembic -c /app/ops/migrations/alembic.ini upgrade head

step "sample rows: TOTP + Slack webhook under the PREVIOUS key, evidence under the current key"
DSN="postgresql://owner:$PG_PASS@$PG:5432/guardhub" OLD_KEY=$OLD_KEY NEW_KEY=$NEW_KEY MARK=$REL \
  docker run --rm -i --network "$NET" -e DSN -e OLD_KEY -e NEW_KEY -e MARK "$API_IMAGE" python - <<'PY'
import asyncio, base64, os, uuid
import asyncpg
from guardhub_api.common.crypto import Cipher

async def main() -> None:
    old, new = (Cipher(base64.b64decode(os.environ[k])) for k in ("OLD_KEY", "NEW_KEY"))
    db = await asyncpg.connect(os.environ["DSN"])
    for i in range(3):
        uid = uuid.uuid4()
        await db.execute("INSERT INTO users (id, email, password_hash, totp_secret, totp_enabled) VALUES ($1,$2,'x',$3,true)",
                         uid, f"{os.environ['MARK']}-{i}@example.com", old.encrypt(f"JBSWY3DPEHPK3PX{i}", str(uid).encode()))
        await db.execute("INSERT INTO notification_settings (user_id, slack_webhook_enc) VALUES ($1,$2)",
                         uid, old.encrypt(f"https://hooks.example.invalid/{os.environ['MARK']}", str(uid).encode()))
    scan = uuid.uuid4()
    await db.execute("INSERT INTO scans (id, target_url, public_token_hash, status) VALUES ($1,'https://example.invalid','h','done')", scan)
    for i in range(2):
        fid, eid = uuid.uuid4(), uuid.uuid4()
        await db.execute("INSERT INTO findings (id, scan_id, check_id, finding_key, severity, title_key, plain_summary,"
                         " fix_guidance, fingerprint) VALUES ($1,$2,'exposed_env','k','info','t','s','f',$3)", fid, scan, str(i))
        await db.execute("INSERT INTO evidence (id, finding_id, kind, location, redacted_payload) VALUES ($1,$2,'http_response','/.env',$3)",
                         eid, fid, new.encrypt(f"API_KEY=****{i:04d}", str(eid).encode()))
    print("inserted 3 users (+3 webhooks) under the previous key and 2 evidence rows under the current key")

asyncio.run(main())
PY

export GUARDHUB_ROOT=$ROOT GUARDHUB_DB_CONTAINER=$PG GUARDHUB_DRILL_NAME=$DRILL OFFSITE_DOCKER_NETWORK=$NET
# Uncompressed restic packs: without client-side encryption the marker WOULD appear verbatim in
# the bucket, so "not found" below really proves encryption (not just compression).
export RESTIC_COMPRESSION=off

step "offsite: not configured → backup still works, says so, exit 0"
rm -f "$ROOT/shared/offsite.env" # no offsite.env and nothing in .env = not configured
out=$(bash "$CTL" backup 2>&1) || fail "backup without off-site config failed: $out"
grep -q "offsite: not configured" <<<"$out" || fail "missing 'offsite: not configured' log line"
[[ $(bash "$OFFSITE" status) == "offsite: not configured" ]] || fail "status should say not configured"
cp "$WORK/offsite.good" "$ROOT/shared/offsite.env"
rm -f "$ROOT"/backups/guardhub-*

step "offsite init + backup (local dump → restic push → retention), twice"
bash "$OFFSITE" init
bash "$CTL" backup >"$WORK/first" 2>"$WORK/backup.log" || { cat "$WORK/backup.log"; fail "backup 1"; }
sleep 1
bash "$CTL" backup >"$WORK/second" 2>>"$WORK/backup.log" || { cat "$WORK/backup.log"; fail "backup 2"; }
cat "$WORK/backup.log"
[[ $(grep -c "pushed guardhub-" "$WORK/backup.log") == 2 ]] || fail "expected two pushes"
manifest="$(cat "$WORK/second").manifest"
grep -q "release=$REL" "$manifest" || fail "positive control: marker not in the local manifest"
bash "$OFFSITE" check
status=$(bash "$OFFSITE" status)
echo "$status"
[[ $status == "offsite: configured, latest snapshot 20"* ]] || fail "status should show the latest snapshot"
# retention ran after each push, and both snapshots (different dump file names) are ONE group
# (--group-by host,tags); grouped by paths they would never expire. restic also keeps the oldest
# snapshot while fewer than 14 days exist, so both are kept here.
[[ $(grep -c "Applying Policy: keep 14 daily, 8 weekly snapshots" "$WORK/backup.log") == 2 ]] ||
  fail "retention policy did not run after each push"
grep -q "keep 2 snapshots:" "$WORK/backup.log" || fail "snapshots are not grouped together for retention"

wait_predeploy() { # wait_predeploy <ok|FAILED> <timeout-s>: the async pre-deploy copy's outcome
  local want=$1 deadline=$((SECONDS + $2)) st
  while ((SECONDS < deadline)); do
    st=$(cat "$ROOT/state/offsite-predeploy.status" 2>/dev/null || true)
    [[ $st == "$want "* ]] && { echo "pre-deploy status: $st"; return 0; }
    sleep 2
  done
  fail "pre-deploy status never became '$want' (last: ${st:-none}); log: $(tail -5 "$ROOT/state/offsite-predeploy.log" 2>/dev/null)"
}

step "pre-deploy backup: local dump at once, off-site copy in the background (storage healthy)"
t0=$SECONDS
out=$(bash "$CTL" predeploy-backup 2>&1) || fail "predeploy-backup failed: $out"
echo "$out"; ((SECONDS - t0 < 30)) || fail "predeploy-backup blocked for $((SECONDS - t0))s"
grep -q "off-site copy started in the background" <<<"$out" || fail "missing async log line"
wait_predeploy ok 180
bash "$CTL" status 2>/dev/null | grep -q "offsite pre-deploy copy: ok" || fail "status does not show the pre-deploy copy"
newest=$(ls -t "$ROOT"/backups/guardhub-*.dump | head -1)
grep -q "pushed $(basename "$newest") " "$ROOT/state/offsite-predeploy.log" ||
  fail "the background push did not upload the pre-deploy dump"

step "pre-deploy backup during a storage OUTAGE: deploy is not blocked, failure is recorded"
docker stop "$MINIO" >/dev/null
t0=$SECONDS
out=$(OFFSITE_PUSH_TIMEOUT=40 bash "$CTL" predeploy-backup 2>&1) || fail "predeploy-backup failed during the outage: $out"
echo "$out"; ((SECONDS - t0 < 30)) || fail "a storage outage blocked predeploy-backup for $((SECONDS - t0))s"
ls "$ROOT"/backups/guardhub-*.dump >/dev/null || fail "no local dump"
[[ $(ls -t "$ROOT"/backups/guardhub-*.dump | head -1) != "$newest" ]] || fail "no NEW local dump was written"
wait_predeploy FAILED 150
docker start "$MINIO" >/dev/null
for _ in $(seq 1 60); do docker exec "$MINIO" curl -fsS http://127.0.0.1:9000/minio/health/ready >/dev/null 2>&1 && break; sleep 1; done
bash "$OFFSITE" unlock >/dev/null 2>&1 || true # a push killed mid-way may leave a stale lock
step "the next (nightly) backup pushes again: storage recovered"
bash "$CTL" backup >"$WORK/third" 2>>"$WORK/backup.log" || { tail -20 "$WORK/backup.log"; fail "backup after outage"; }
bash "$OFFSITE" check

step "server lost: wipe ALL local dumps, then restore-drill --offsite"
rm -rf "$ROOT/backups"
bash "$CTL" restore-drill --offsite 2>&1 | tee "$WORK/drill.log"
grep -q "RESTORE DRILL PASSED" "$WORK/drill.log" || fail "off-site drill did not pass"
grep -q "offsite: fetched $(basename "$(cat "$WORK/third")")" "$WORK/drill.log" ||
  fail "the drill should use the NEWEST off-site snapshot"
grep -q "under_previous_key=6" "$WORK/drill.log" || fail "keyring proof should report 6 values under the previous key"
grep -q "totp=3 evidence=2 slack=3" "$WORK/drill.log" || fail "decrypt counts"
[[ -z $(ls -A "$ROOT/backups") ]] || fail "the off-site temp dir was not cleaned up"

step "the drill also fails if the previous key is gone (values under it can't be read)"
sed -i 's/^DATA_ENCRYPTION_KEYS_PREVIOUS=.*/DATA_ENCRYPTION_KEYS_PREVIOUS=/' "$ROOT/shared/.env"
if bash "$CTL" restore-drill --offsite >"$WORK/nokey.log" 2>&1; then fail "drill passed without the previous key"; fi
grep -q "could NOT be decrypted" "$WORK/nokey.log" || { cat "$WORK/nokey.log"; fail "expected a decrypt failure"; }
cp "$WORK/env.good" "$ROOT/shared/.env"

step "wrong RESTIC_PASSWORD must fail"
sed -i "s/^RESTIC_PASSWORD=.*/RESTIC_PASSWORD=wrong-$(rand 12)/" "$ROOT/shared/offsite.env"
mkdir -p "$WORK/wrong"
if bash "$OFFSITE" restore-latest "$WORK/wrong" >"$WORK/wrong.log" 2>&1; then fail "restore with a wrong password succeeded"; fi
cat "$WORK/wrong.log"
if bash "$CTL" restore-drill --offsite >"$WORK/wrong-drill.log" 2>&1; then fail "drill with a wrong password passed"; fi
if grep -q "RESTORE DRILL PASSED" "$WORK/wrong-drill.log"; then fail "drill log claims success"; fi
[[ -z $(ls -A "$WORK/wrong") ]] || fail "a wrong password must not produce any file"
cp "$WORK/offsite.good" "$ROOT/shared/offsite.env"

step "the bucket holds no plaintext"
docker cp "$MINIO:/data" - >"$WORK/bucket.tar"
objects=$(tar -tf "$WORK/bucket.tar" | grep -c 'guardhub-e2e/repo/data/' || true)
((objects > 0)) || fail "no restic data objects in the bucket?"
for needle in "$REL" "counts=users=" "sha256=" "PGDMP" "hooks.example.invalid" "API_KEY="; do
  if grep -aq -- "$needle" "$WORK/bucket.tar"; then fail "plaintext '$needle' found in the raw bucket objects"; fi
  echo "not in bucket: $needle"
done
# and the secrets themselves never left the server in clear (nor did GuardHub's own key)
for needle in "$RESTIC_PW" "$NEW_KEY" "$OLD_KEY"; do
  if grep -aqF -- "$needle" "$WORK/bucket.tar"; then fail "a secret was found in the bucket"; fi
done
echo "bucket: $objects data objects, no plaintext markers, no keys"

printf '\nOFFSITE E2E PASSED\n'
