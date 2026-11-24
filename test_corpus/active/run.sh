#!/usr/bin/env bash
# Gate M (ADR-0008 §9): measure the active checks on the lab and compare the ground truth with
# OWASP ZAP. Lab only: every origin is *.lab.test on the isolated lab network.
#
#   bash test_corpus/active/run.sh OUT_DIR
#
# 1. the light lab targets + DVWA, Juice Shop, WebGoat, the purpose-built av-* sites (avlab) and
#    the OOB collaborator start (no other heavy app)
# 2. login-*.sh make the lab sessions (two accounts each for DVWA, WebGoat, av-idor; lab setup,
#    not the scanner)
# 3. `scanner activelab` (the production active path) scores the active manifests:
#    docs/accuracy-active/ (scorecards) + OUT_DIR/activelab-results.json (findings + request logs)
# 4. the pinned ZAP oracle (+ the pinned ascanrulesBeta add-on: CORS 40040, SSRF 40046) scans
#    every manifest origin with the same session and route list; compare.py fails on any
#    disagreement
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
cd "$HERE/.."
LAB=(docker compose -f docker-compose.lab.yml)
NET=guardhub-lab_lab
ZAP_IMAGE=zaproxy/zap-stable:2.17.0@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af
# ZAP's beta scan rules (CORS 40040, SSRF 40046 are not in zap-stable), pinned by release + sha256
ZAP_BETA_URL=https://github.com/zaproxy/zap-extensions/releases/download/ascanrulesBeta-v67/ascanrulesBeta-beta-67.zap
ZAP_BETA_SHA=81e84d592b1f7ad803470bcc8d8b659d4f7e21370546a482b606207e57a7db69
cleanup() {
  "${LAB[@]}" --profile run down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f active/manifests/*-session.json
}
trap cleanup EXIT
cleanup
export LAB_SOURCE=${LAB_SOURCE:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}

# 1. services: everything except the heavy apps this gate does not use
skip=" wordpress wordpress-db drupal phpmyadmin grafana repolab "
services=()
for s in $("${LAB[@]}" config --services); do
  [[ $skip == *" $s "* ]] || services+=("$s")
done
"${LAB[@]}" up -d --build --quiet-pull "${services[@]}"

origins=$(awk '/^origin:/ {print $2}' active/manifests/*.yaml)
hosts=$( (for o in $origins; do o=${o#*://}; echo "${o%%[:/]*}"; done; echo oob.lab.test) | sort -u | paste -sd, -)
tools() { docker run --rm --network "$NET" -v "$PWD/active:/a" -v "$OUT:/out" -v "$PWD/../docs:/docs" "$@"; }

# every origin must answer before anything is measured
for o in $origins; do
  tools guardhub-lab-tools:local sh -c "i=0; until curl -sk -o /dev/null --max-time 3 $o/; do i=\$((i+1)); [ \$i -lt 120 ] || exit 1; sleep 2; done" \
    || { echo "lab target $o never answered" >&2; exit 1; }
  echo "up: $o"
done

# 2. the lab sessions (two consented lab accounts per logged-in target)
tools guardhub-lab-tools:local sh /a/login-dvwa.sh /a/manifests/dvwa-session.json
tools guardhub-lab-tools:local sh /a/login-avidor.sh /a/manifests/av-idor-session.json
tools guardhub-lab-tools:local sh /a/login-webgoat.sh /a/manifests/webgoat-session.json

# 3. the measurement (production path; 5 requests/s against the local lab instead of 1)
mkdir -p ../docs/accuracy-active
tools -e SCANNER_ALLOW_PRIVATE_HOSTS="$hosts" guardhub-lab-tools:local \
  scanner activelab --manifests /a/manifests --out /docs/accuracy-active \
  --results /out/activelab-results.json --source "$LAB_SOURCE" --rps 5 --oob http://oob.lab.test

# 3b. the founder-checkpoint proof, rehearsed in the lab (ADR-0008 §8.1): `scanner activeproof`
#     at the production rate (1 request/s) with two excluded paths; the proof sets the scan's
#     kill key after 8 sent requests. It must hold on both sides: the scanner's report (scope
#     probes refused, stop ≤ 2 s after the kill, ≥ 0.9 s between requests) and the target's own
#     access record (avlab logs host, path, User-Agent): nothing excluded or out of scope arrived,
#     and exactly as many GuardHub-Active requests as the report says were sent.
before=$("${LAB[@]}" logs --no-log-prefix avlab 2>/dev/null | wc -l)
tools -e SCANNER_ALLOW_PRIVATE_HOSTS=av-xss.lab.test -e REDIS_URL=redis://redis.lab.test:6379/0 \
  guardhub-lab-tools:local scanner activeproof --origin http://av-xss.lab.test --check active_xss \
  --exclude /profile,/lang --kill-after 8 --out /out/activeproof-lab.json
sleep 1
"${LAB[@]}" logs --no-log-prefix avlab 2>/dev/null | tail -n +$((before + 1)) | grep '^avlab ' >"$OUT/activeproof-lab-access.log" || true
python3 active/check_activeproof.py "$OUT/activeproof-lab.json" "$OUT/activeproof-lab-access.log" /profile /lang

# 4. ground truth: ZAP on every origin, logged in as account A where the manifest has sessions,
#    starting from the manifest's route list too
beta="$OUT/zap-addon/ascanrulesBeta-beta-67.zap"
mkdir -p "$OUT/zap-addon"
curl -sSfL -o "$beta" "$ZAP_BETA_URL"
echo "$ZAP_BETA_SHA  $beta" | sha256sum -c - || { echo "ZAP add-on checksum mismatch" >&2; exit 1; }
docker pull -q "$ZAP_IMAGE" >/dev/null
python3 - active/manifests > "$OUT/zap-targets.tsv" <<'PY'
import glob, json, os, sys
import yaml
d = sys.argv[1]
for p in sorted(glob.glob(os.path.join(d, "*.yaml"))):
    m = yaml.safe_load(open(p, encoding="utf-8"))
    cookie = ""
    if m.get("sessions"):
        cookie = json.load(open(os.path.join(d, m["sessions"]), encoding="utf-8"))["a"]["cookie"]
    o = m["origin"].rstrip("/")
    print("|".join([o, cookie, json.dumps([o + s for s in m.get("start") or []])]))  # "|": an empty cookie must stay a field
PY
while IFS='|' read -r o c seeds; do
  name=$(echo "$o" | sed 's#^[a-z]*://##; s#[^a-zA-Z0-9]#-#g')
  echo "== zap $o"
  docker run --rm --network "$NET" --network-alias zap.lab.test -v "$PWD/oracles/zap:/o:ro"     -v "$beta:/zap/plugin/ascanrulesBeta-beta-67.zap:ro" "$ZAP_IMAGE" sh -c '
    zap.sh -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true >/tmp/zap.log 2>&1 &
    python3 -c "
import time, urllib.request
for _ in range(120):
    try:
        urllib.request.urlopen(\"http://127.0.0.1:8090\", timeout=2); break
    except Exception:
        time.sleep(2)
else:
    raise SystemExit(\"zap daemon never started\")"
    python3 /o/oracle_zap.py "$0" "$1" "$2"' "$o" "$c" "$seeds" > "$OUT/zap-$name.json" < /dev/null
done < "$OUT/zap-targets.tsv"
python3 oracles/zap/compare.py "$OUT"
