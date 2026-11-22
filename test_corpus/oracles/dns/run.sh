#!/usr/bin/env bash
# Ground truth for dns_depth on every lab site target (oracle_dns.py: BIND dig/delv, OpenSSL,
# curl), compared with the manifests. Used by CI's dns-truth job.
#
#   bash test_corpus/oracles/dns/run.sh OUT_DIR
#
# Only the DNS stand-ins and the light web fronts are started: the third-party apps are
# Docker-served names outside the lab zones, so their DNS answers do not depend on them running.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
cd "$HERE/../.."
LAB=(docker compose -f docker-compose.lab.yml)
cleanup() { "${LAB[@]}" --profile run down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
"${LAB[@]}" build pki
"${LAB[@]}" up -d pki ddkeys dns-res dns-ns dns-open dns-web dd-sts clean
docker build -q -t gh-oracle-dns "$HERE" >/dev/null
for i in $(seq 1 60); do # wait until the resolver answers the signed lab zones
  docker run --rm --network guardhub-lab_lab --entrypoint dig gh-oracle-dns +short @dns-res.lab.test good.dd.lab.test DNSKEY | grep -q . && break
  [[ $i == 60 ]] && { echo "dns-res never answered" >&2; exit 1; }
  sleep 2
done
docker run --rm --network guardhub-lab_lab -v guardhub-lab_pki:/pki:ro -v "$PWD/manifests:/m:ro" -v "$OUT:/out" \
  gh-oracle-dns /m /out
