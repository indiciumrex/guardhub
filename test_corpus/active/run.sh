#!/usr/bin/env bash
# Gate M (ADR-0008 §9): measure the active checks on the lab and compare the ground truth with
# OWASP ZAP. Lab only: every origin is *.lab.test on the isolated lab network.
#
#   bash test_corpus/active/run.sh OUT_DIR
#
# 1. the light lab targets + DVWA, Juice Shop and WebGoat start (no other heavy app)
# 2. login-dvwa.sh makes DVWA's lab session (lab setup, not the scanner)
# 3. `scanner activelab` (the production active path) scores the active manifests:
#    docs/accuracy-active/ (scorecards) + OUT_DIR/activelab-results.json (findings + request logs)
# 4. the pinned ZAP oracle scans every manifest origin; compare.py fails on any disagreement
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
cd "$HERE/.."
LAB=(docker compose -f docker-compose.lab.yml)
NET=guardhub-lab_lab
ZAP_IMAGE=zaproxy/zap-stable:2.17.0@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af
SESSION=active/manifests/dvwa-session.json
cleanup() {
  "${LAB[@]}" --profile run down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$SESSION"
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
hosts=$(for o in $origins; do o=${o#*://}; echo "${o%%[:/]*}"; done | sort -u | paste -sd, -)
tools() { docker run --rm --network "$NET" -v "$PWD/active:/a" -v "$OUT:/out" -v "$PWD/../docs:/docs" "$@"; }

# every origin must answer before anything is measured
for o in $origins; do
  tools guardhub-lab-tools:local sh -c "i=0; until curl -s -o /dev/null --max-time 3 $o/; do i=\$((i+1)); [ \$i -lt 120 ] || exit 1; sleep 2; done" \
    || { echo "lab target $o never answered" >&2; exit 1; }
  echo "up: $o"
done

# 2. DVWA's lab session
tools guardhub-lab-tools:local sh /a/login-dvwa.sh "/a/manifests/dvwa-session.json"

# 3. the measurement (production path; 5 requests/s against the local lab instead of 1)
mkdir -p ../docs/accuracy-active
tools -e SCANNER_ALLOW_PRIVATE_HOSTS="$hosts" guardhub-lab-tools:local \
  scanner activelab --manifests /a/manifests --out /docs/accuracy-active \
  --results /out/activelab-results.json --source "$LAB_SOURCE" --rps 5

# 4. ground truth: ZAP on every origin (DVWA with the same lab session)
cookie=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["a"]["cookie"])' "$SESSION")
docker pull -q "$ZAP_IMAGE" >/dev/null
for o in $origins; do
  c=""; [[ $o == *dvwa.lab.test* ]] && c=$cookie
  name=$(echo "$o" | sed 's#^[a-z]*://##; s#[^a-zA-Z0-9]#-#g')
  echo "== zap $o"
  docker run --rm --network "$NET" -v "$PWD/oracles/zap:/o:ro" "$ZAP_IMAGE" sh -c '
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
    python3 /o/oracle_zap.py "$0" "$1"' "$o" "$c" > "$OUT/zap-$name.json"
done
python3 oracles/zap/compare.py "$OUT"
