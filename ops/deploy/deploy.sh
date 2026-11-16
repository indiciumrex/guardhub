#!/usr/bin/env bash
# Build GuardHub images HERE, ship them + the release files to the server, then activate there.
# Heavy builds never run on the shared host.   Usage: ops/deploy/deploy.sh root@host
set -Eeuo pipefail
HOST=${1:?usage: deploy.sh user@host}
cd "$(git rev-parse --show-toplevel)"
[[ -z $(git status --porcelain) ]] || { echo "working tree not clean: commit first" >&2; exit 1; }
V=$(git rev-parse --short=12 HEAD)
echo "== building $V"
GUARDHUB_VERSION=$V docker compose -f docker-compose.yml build migrate scanner web
echo "== shipping release files"
ssh "$HOST" "mkdir -p /opt/guardhub/releases/$V /opt/guardhub/shared && chmod 700 /opt/guardhub/shared"
git archive --format=tar HEAD | ssh "$HOST" "tar -x -C /opt/guardhub/releases/$V"
echo "== shipping images"
docker save "guardhub-api:$V" "guardhub-scanner:$V" "guardhub-web:$V" | gzip -1 | ssh "$HOST" 'gunzip | docker load'
echo "== activating"
ssh "$HOST" "bash /opt/guardhub/releases/$V/ops/deploy/guardhub-ctl.sh activate $V"
