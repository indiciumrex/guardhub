#!/usr/bin/env bash
# Manual trigger for the CD agent (ADR-0009). Nothing is built here or on the server: CI builds,
# signs and pushes the images; the server pulls and verifies them. Normally cron does this.
#   ops/deploy/deploy.sh root@host            # the newest main commit (must be green + signed)
#   ops/deploy/deploy.sh root@host <sha>      # an exact main commit (no downgrades)
#   ops/deploy/deploy.sh root@host status
set -Eeuo pipefail
HOST=${1:?usage: deploy.sh user@host [sha|status]}
cd "$(git rev-parse --show-toplevel)"
git fetch -q origin main
ARG=${2:-$(git rev-parse origin/main)}
# first install (or repair) of the agent: the copy from origin/main
ssh "$HOST" 'test -f /opt/guardhub/cd/cd.sh' ||
  git show origin/main:ops/deploy/cd.sh | ssh "$HOST" 'install -D -m 700 /dev/stdin /opt/guardhub/cd/cd.sh'
if [[ $ARG == status ]]; then exec ssh "$HOST" 'bash /opt/guardhub/cd/cd.sh status'; fi
[[ $ARG =~ ^[0-9a-f]{40}$ ]] || ARG=$(git rev-parse "$ARG")
ssh "$HOST" "bash /opt/guardhub/cd/cd.sh deploy $ARG"
