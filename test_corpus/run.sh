#!/usr/bin/env bash
# Measure every check against the validation lab and regenerate
# docs/accuracy/ + packages/shared/accuracy.json. Needs docker; a fresh lab
# (new throwaway PKI and secrets) is started and removed every time.
#
#   bash test_corpus/run.sh            # then: git diff docs/accuracy packages/shared/accuracy.json
#   LAB_SKIP_HEAVY=1 bash test_corpus/run.sh
#       light run (pull requests): without the heavy apps in heavy-apps.txt. Its
#       accuracy.json covers fewer targets, so it is never a scorecard to commit;
#       ops/ci/accuracy_gate.py compares it with the committed one instead.
set -Eeuo pipefail
cd "$(dirname "$0")"
LAB=(docker compose -f docker-compose.lab.yml)
cleanup() {
  "${LAB[@]}" --profile run down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf .manifests-light
}
trap cleanup EXIT
cleanup
export LAB_SOURCE=${LAB_SOURCE:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}
if [[ ${LAB_SKIP_HEAVY:-} == 1 ]]; then
  mapfile -t heavy < <(grep -v '^#' heavy-apps.txt | awk 'NF')
  heavy_targets=" $(printf '%s\n' "${heavy[@]}" | awk '{print $1}' | tr '\n' ' ') "
  heavy_services=" $(printf '%s\n' "${heavy[@]}" | cut -d' ' -f2- | tr '\n' ' ') "
  mkdir -p .manifests-light
  for f in manifests/*.yaml; do
    t=$(basename "$f" .yaml)
    [[ $heavy_targets == *" $t "* ]] || cp "$f" .manifests-light/
  done
  services=()
  for s in $("${LAB[@]}" config --services); do
    [[ $heavy_services == *" $s "* ]] || services+=("$s")
  done
  echo "light lab: $(ls .manifests-light | wc -l) targets, heavy apps skipped:$heavy_targets"
  export LAB_MANIFESTS=./.manifests-light LAB_SOURCE="light-$LAB_SOURCE"
  "${LAB[@]}" up -d --build --quiet-pull "${services[@]}"
else
  "${LAB[@]}" up -d --build --quiet-pull
fi
"${LAB[@]}" --profile run run --rm runner
