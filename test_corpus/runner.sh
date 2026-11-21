#!/bin/sh
# Runs inside the lab runner container: wait for every target to answer, then
# measure. The scanner itself refuses anything that is not *.lab.test.
# Writes docs/accuracy/ (scorecards) and packages/shared/accuracy.json (the
# API's gate); raw findings stay inside the container (/tmp).
set -eu
for origin in $(grep -h '^origin:' /corpus/manifests/*.yaml | awk '{print $2}'); do
  i=0
  until curl -sk -o /dev/null --max-time 3 "$origin/"; do
    i=$((i + 1)); [ "$i" -lt 90 ] || { echo "lab target $origin never answered" >&2; exit 1; }
    sleep 2
  done
  echo "up: $origin"
done
# Repository targets: the GitHub/OSV stand-in must answer too.
i=0
until curl -s -o /dev/null --max-time 3 http://github.lab.test/healthz; do
  i=$((i + 1)); [ "$i" -lt 90 ] || { echo "repo stand-in never answered" >&2; exit 1; }
  sleep 2
done
echo "up: github.lab.test (repo targets)"
exec scanner lab --manifests /corpus/manifests --out /out --results /tmp/raw-results.json \
  --roots /pki/ca.pem --source "$LAB_SOURCE" --shared /shared/accuracy.json   --dns-recursion-probe clean.lab.test.
