#!/usr/bin/env bash
# Measure every check against the validation lab and regenerate
# docs/accuracy/ + packages/shared/accuracy.json. Needs docker; a fresh lab
# (new throwaway PKI and secrets) is started and removed every time.
#
#   bash test_corpus/run.sh            # then: git diff docs/accuracy packages/shared/accuracy.json
set -Eeuo pipefail
cd "$(dirname "$0")"
LAB=(docker compose -f docker-compose.lab.yml)
cleanup() { "${LAB[@]}" --profile run down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
export LAB_SOURCE=${LAB_SOURCE:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}
"${LAB[@]}" up -d --build --quiet-pull
"${LAB[@]}" --profile run run --rm runner
