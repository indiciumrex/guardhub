#!/usr/bin/env bash
# Founder-checkpoint proof (ADR-0008 §8.1) on GuardHub's OWN site: scope guard + kill switch +
# rate, through the live scanner image. Run it ONLY after the founder's "git" (the plan:
# docs/checkpoint-4b/kanit-plani.md). It is the only way active requests leave the host before
# active testing is turned on, and it never changes the production scanner: that service keeps
# SCANNER_ACTIVE_ENABLED unset; this is a one-off container with the switch set for itself only.
#
# Usage (on the server, as root):
#   GUARDHUB_FOUNDER_GO=yes bash ops/active-proof/run-proof.sh [admin|auto]
#     admin (default): the founder presses "stop this scan" in the admin panel (audited) once
#                      the script says so; the scanner's report records when the key appeared
#     auto:            the proof sets the scan's kill key itself after 8 sent requests
#   Then a second run with the GLOBAL kill switch already set must send nothing (exit 5).
#
# Evidence (no secrets): /opt/guardhub/proof/<UTC time>/ report-run1.json, access-run1.log,
# report-run2.txt, access-run2.log, summary.txt. The access logs come from nginx itself: for the
# proof only, guardhub.dev.conf logs requests whose User-Agent is GuardHub-Active/ (host, URI,
# UA); the change is reverted on exit, whatever happens.
set -Eeuo pipefail

MODE=${1:-admin}
ORIGIN=${ORIGIN:-https://guardhub.dev}
CHECK=${CHECK:-active_xss}
EXCLUDE=${EXCLUDE:-/admin,/api,/account/projects,/account/settings}
START=${START:-/account/login?next=/account,/account/register?next=/account}
ROOT=${GUARDHUB_ROOT:-/opt/guardhub}
NGINX_CONF=${NGINX_CONF:-/etc/nginx/sites-enabled/guardhub.dev.conf}
PROOF_LOG=/var/log/nginx/guardhub-active-proof.log

[[ ${GUARDHUB_FOUNDER_GO:-} == yes ]] || { echo "refused: set GUARDHUB_FOUNDER_GO=yes only after the founder's go" >&2; exit 2; }
[[ $MODE == admin || $MODE == auto ]] || { echo "mode must be admin or auto" >&2; exit 2; }
[[ -f $NGINX_CONF ]] || { echo "nginx conf $NGINX_CONF not found" >&2; exit 2; }

color=$(cat "$ROOT/state/active_color")
scanner="guardhub-$color-scanner-1"
image=$(docker inspect -f '{{.Config.Image}}' "$scanner")
token=$(tr -d '[:space:]' <"$ROOT/selfverify/guardhub-verify.txt") # public: nginx serves it
out="$ROOT/proof/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
chmod 700 "$ROOT/proof"
# the scanner image runs as nonroot (uid 65532, distroless): it writes its reports here.
# The first live run (2026-11-25 11:26Z) lost both reports to "permission denied" without this.
chown 65532:65532 "$out"
here=$(cd "$(dirname "$0")" && pwd)

# no deploy in flight (CD's lock), and none may start during the proof
exec 9>"$ROOT/state/cd/lock"
flock -n 9 || { echo "a CD run holds the lock; try again after it" >&2; exit 1; }

# the scanner's REDIS_URL, copied from the live scanner into a 0600 file; never printed
envf=$(mktemp)
chmod 600 "$envf"
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$scanner" | grep -E '^(REDIS_URL|SCANNER_REQUEST_TIMEOUT)=' >"$envf"
echo "SCANNER_ACTIVE_ENABLED=true" >>"$envf"

# nginx: log GuardHub-Active requests for the proof only
cp -p "$NGINX_CONF" "$out/.nginx.bak"
restore() {
  rm -f "$envf"
  if [[ -f $out/.nginx.bak ]]; then
    cp -p "$out/.nginx.bak" "$NGINX_CONF" && nginx -t -q && systemctl reload nginx && rm -f "$out/.nginx.bak"
    echo "nginx restored"
  fi
}
trap restore EXIT
python3 - "$NGINX_CONF" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
head = (
    'map $http_user_agent $guardhub_active_proof { "~^GuardHub-Active/" 1; default 0; }\n'
    "log_format guardhub_active_proof 'proof $host $request_uri $http_user_agent';\n"
)
# the TLS server of guardhub.dev itself (not www): its "access_log off;" becomes the proof's log
i = s.find("server_name guardhub.dev;")
j = s.find("access_log off;", i)
if i < 0 or j < 0 or "listen 443" not in s[s.rfind("server {", 0, i):i]:
    raise SystemExit("cannot find the TLS server's access_log in the nginx conf")
s = s[:j] + "access_log /var/log/nginx/guardhub-active-proof.log guardhub_active_proof if=$guardhub_active_proof;" + s[j + len("access_log off;"):]
open(p, "w", encoding="utf-8").write(head + s)
PY
: >"$PROOF_LOG"
nginx -t -q && systemctl reload nginx
echo "nginx logs GuardHub-Active requests to $PROOF_LOG for the proof"

run_proof() { # run_proof <name> <scan id> [extra args...]
  local name=$1 id=$2
  shift 2
  local c
  c=$(docker create --read-only --cap-drop=ALL --security-opt no-new-privileges --network guardhub_backend \
    --env-file "$envf" -v "$out:/out" "$image" activeproof --origin "$ORIGIN" --confirm "$ORIGIN" \
    --token "$token" --check "$CHECK" --exclude "$EXCLUDE" --start "$START" --scan-id "$id" \
    --out "/out/report-$name.json" "$@")
  docker network connect guardhub_egress "$c"
  set +e
  docker start -a "$c"
  local code=$?
  set -e
  docker rm -f "$c" >/dev/null
  return $code
}

# run 1: the scan, then the kill
id1=$(cat /proc/sys/kernel/random/uuid)
echo "run 1: $CHECK on $ORIGIN, scan id $id1, 1 request/s, excluded $EXCLUDE"
if [[ $MODE == admin ]]; then
  echo ">>> about 10 s after this line: admin panel -> Scan Orchestration -> Kill switch -> stop scan $id1"
  run_proof run1 "$id1" && code1=0 || code1=$?
else
  run_proof run1 "$id1" --kill-after 8 && code1=0 || code1=$?
fi
sleep 2
grep '^proof ' "$PROOF_LOG" >"$out/access-run1.log" || true
python3 "$here/../../test_corpus/active/check_activeproof.py" "$out/report-run1.json" "$out/access-run1.log" \
  ${EXCLUDE//,/ } | tee "$out/summary.txt" && check1=0 || check1=$?

# run 2: global kill set before the start -> nothing may be sent
redis_c=guardhub-redis-1
docker exec "$redis_c" sh -c 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli SET gh:active:kill proof-run2' >/dev/null
lines_before=$(wc -l <"$PROOF_LOG")
id2=$(cat /proc/sys/kernel/random/uuid)
run_proof run2 "$id2" && code2=0 || code2=$?
docker exec "$redis_c" sh -c 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli DEL gh:active:kill' >/dev/null
sleep 1
tail -n +"$((lines_before + 1))" "$PROOF_LOG" >"$out/access-run2.log"
sent2=$(grep -c '^proof ' "$out/access-run2.log" || true)
echo "run 2 (global kill set before the start): exit $code2 (5 expected), requests at nginx: $sent2 (0 expected)" |
  tee -a "$out/summary.txt" >"$out/report-run2.txt"

ok=yes
[[ $code1 == 0 && $check1 == 0 ]] || ok=no
[[ $code2 == 5 && $sent2 == 0 ]] || ok=no
echo "proof: $ok (run 1 exit $code1, check $check1; run 2 exit $code2, $sent2 requests)" | tee -a "$out/summary.txt"
echo "evidence: $out"
[[ $ok == yes ]]
