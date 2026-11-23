#!/usr/bin/env bash
# Ground truth for header_quality, cookie_depth, exposed_files (oracles/files) and js_libraries (oracles/js) on every lab site target, from Mozilla's HTTP
# Observatory and Google's CSP Evaluator (oracle_headers.mjs), then a comparison
# with the manifests (compare.py). Used by CI's header-truth job.
#
#   bash test_corpus/oracles/headers/run.sh OUT_DIR
#
# The light targets (nginx, DNS stand-ins) run together. The heavy third-party
# apps run one at a time: start, wait until ready, measure, remove; the next
# one starts only after the previous one is gone.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
cd "$HERE/../.."
LAB=(docker compose -f docker-compose.lab.yml)
NET=guardhub-lab_lab
cleanup() { "${LAB[@]}" --profile run down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

# app manifest -> its services (start order)
declare -A HEAVY=(
  [juice-shop]="juice-shop"
  [dvwa]="dvwa-db dvwa"
  [webgoat]="webgoat"
  [wordpress]="wordpress-db wordpress"
  [drupal]="drupal"
  [phpmyadmin]="dvwa-db phpmyadmin"
  [grafana]="grafana"
)
HEAVY_ORDER=(juice-shop dvwa webgoat wordpress drupal phpmyadmin grafana)
heavy_services=" $(printf '%s ' "${HEAVY[@]}") "

origin_of() { awk '/^origin:/ {print $2; exit}' "manifests/$1.yaml"; }
light=()
for f in $(grep -l 'header_quality' manifests/*.yaml); do
  t=$(basename "$f" .yaml)
  [[ -n "${HEAVY[$t]:-}" ]] && continue
  o=$(origin_of "$t"); [[ -n "$o" ]] && light+=("$o")
done

docker build -q -t gh-oracle-headers "$HERE" >/dev/null
docker build -q -t gh-oracle-files "$HERE/../files" >/dev/null
docker build -q -t gh-oracle-js "$HERE/../js" >/dev/null
files_oracle() { # files_oracle OUTFILE origins...   (exposed_files truth, curl + libmagic)
  local out=$1; shift
  docker run --rm --network "$NET" gh-oracle-files "$@" > "$out"
}
js_oracle() { # js_oracle OUTFILE origins...   (js_libraries truth, retire.js)
  local out=$1; shift
  # content, not TLS, is judged here: certificate checks relaxed, as the files oracle (curl -k)
  docker run --rm --network "$NET" "${RELAX[@]}" gh-oracle-js "$@" > "$out"
}
RELAX=(-e NODE_TLS_REJECT_UNAUTHORIZED=0 -e "NODE_OPTIONS=--tls-min-v1.0 --tls-cipher-list=DEFAULT@SECLEVEL=0")
oracle() { # oracle OUTFILE [docker -e ...] -- origins...
  local out=$1; shift; local env=()
  while [[ $1 != -- ]]; do env+=("$1"); shift; done; shift
  docker run --rm --network "$NET" -v guardhub-lab_pki:/pki:ro -e NODE_EXTRA_CA_CERTS=/pki/ca.pem \
    "${env[@]}" gh-oracle-headers "$@" > "$out"
}
wait_ready() {
  docker run --rm --network "$NET" "${RELAX[@]}" --entrypoint node gh-oracle-headers /o/wait.mjs "$@"
}

# 1. light targets, all together
light_services=()
for s in $("${LAB[@]}" config --services); do
  [[ $heavy_services == *" $s "* || $s == repolab ]] && continue
  light_services+=("$s")
done
echo "light services: ${light_services[*]}"
"${LAB[@]}" up -d --build --quiet-pull "${light_services[@]}"
wait_ready --soft "${light[@]}"
oracle "$OUT/light.json" -- "${light[@]}"
files_oracle "$OUT/files-light.json" "${light[@]}"
js_oracle "$OUT/js-light.json" "${light[@]}"
# targets whose TLS Node refuses (expired, self-signed, SHA-1, legacy ciphers...): read
# again with certificate checks relaxed, marked as such in the notes
mapfile -t refused < <(python3 -c 'import json,sys
for o,t in json.load(open(sys.argv[1])).items():
    if any(n.startswith("fetch failed") for n in t["notes"]): print(o)' "$OUT/light.json")
if ((${#refused[@]})); then
  oracle "$OUT/light-relaxed.json" "${RELAX[@]}" -- "${refused[@]}"
fi

# 2. heavy apps, one at a time
for app in "${HEAVY_ORDER[@]}"; do
  read -r -a svcs <<< "${HEAVY[$app]}"
  o=$(origin_of "$app")
  echo "== $app (${svcs[*]}) $o"
  "${LAB[@]}" up -d --quiet-pull "${svcs[@]}"
  wait_ready "$o"
  oracle "$OUT/app-$app.json" -- "$o"
  files_oracle "$OUT/files-app-$app.json" "$o"
  js_oracle "$OUT/js-app-$app.json" "$o"
  "${LAB[@]}" rm -s -f -v "${svcs[@]}" >/dev/null
  echo "removed: ${svcs[*]}"
done

python3 "$HERE/compare.py" "$OUT"
