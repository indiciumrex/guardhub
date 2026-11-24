#!/usr/bin/env bash
# CD, CI half (ADR-0009): build the three production images from this commit, push them to GHCR
# and sign each DIGEST with Sigstore keyless signing (GitHub OIDC; no key exists anywhere).
# Runs only in the `release` job of ci.yml: on a push to main, after every other gate passed.
# The signature is what makes an image deployable: the server (ops/deploy/cd.sh) pulls only digests
# signed by this workflow on refs/heads/main for exactly the commit it deploys.
#
# Builds use plain `docker build` with no .env in the context: every Dockerfile COPYs explicit
# paths of the (gitleaks-scanned) checkout, so no secret can enter an image.
set -Eeuo pipefail
: "${GITHUB_SHA:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_REPOSITORY_OWNER:?}"
cd "$(git rev-parse --show-toplevel)"
COSIGN=ghcr.io/sigstore/cosign/cosign:v2.4.1@sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31
V=${GITHUB_SHA::12}
REG=ghcr.io/${GITHUB_REPOSITORY_OWNER,,}
SRC=https://github.com/$GITHUB_REPOSITORY
[[ ! -e .env ]] || { echo "refusing to build with a .env in the context" >&2; exit 1; }

declare -A CONTEXT=([api]=. [scanner]=apps/scanner [web]=.)
declare -A FILE=([api]=apps/api/Dockerfile [scanner]=apps/scanner/Dockerfile [web]=apps/web/Dockerfile)
: >release-digests.txt
for s in api scanner web; do
  img=$REG/guardhub-$s:$V
  echo "== $s -> $img"
  docker build --pull -f "${FILE[$s]}" -t "$img" \
    --label "org.opencontainers.image.source=$SRC" \
    --label "org.opencontainers.image.revision=$GITHUB_SHA" \
    --label "org.opencontainers.image.description=GuardHub $s" \
    "${CONTEXT[$s]}"
  # an image must never carry an env file or a private key
  # (listed from an exported filesystem: the scanner image is distroless, with no shell to ask)
  cid=$(docker create "$img")
  bad=$(docker export "$cid" | tar -t | grep -E '(^|/)(\.env(\.(local|production|prod))?|id_rsa[^/]*|id_ed25519[^/]*)$|^app/.*\.(pem|key)$' || true)
  docker rm "$cid" >/dev/null
  [[ -z $bad ]] || { echo "$img contains an env file or key: $bad" >&2; exit 1; }
  docker push "$img"
  digest=$(docker inspect --format '{{index .RepoDigests 0}}' "$img")
  [[ $digest == "$REG/guardhub-$s@sha256:"* ]] || { echo "no registry digest for $img" >&2; exit 1; }
  docker run --rm -e ACTIONS_ID_TOKEN_REQUEST_URL -e ACTIONS_ID_TOKEN_REQUEST_TOKEN \
    -e DOCKER_CONFIG=/dcfg -v "$HOME/.docker:/dcfg:ro" "$COSIGN" sign --yes "$digest"
  echo "$s $digest" | tee -a release-digests.txt
done
