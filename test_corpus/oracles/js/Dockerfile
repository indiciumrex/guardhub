# Independent ground truth for js_libraries (ADR-0007). Lab only, never shipped.
# retire.js 6.1.1 (its own matchers, unmodified) with its vulnerability repository pinned to a
# commit and checked by sha256, so a CI run never depends on today's live list.
#
#   docker build -t gh-oracle-js test_corpus/oracles/js
#   docker run --rm --network guardhub-lab_lab -v guardhub-lab_pki:/pki:ro \
#     -e NODE_EXTRA_CA_CERTS=/pki/ca.pem gh-oracle-js https://js-jquery.lab.test ...
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
WORKDIR /o
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
ARG RETIRE_REPO_COMMIT=0a997046b9a38c073dea8c864b015e515fc677ec
ARG RETIRE_REPO_SHA256=f97d00752635a5309b27fabffbece8e0a1a964711a7b2452e2e8a91b2fee5e49
RUN wget -q -O jsrepository.json "https://raw.githubusercontent.com/RetireJS/retire.js/${RETIRE_REPO_COMMIT}/repository/jsrepository-v5.json" \
 && echo "${RETIRE_REPO_SHA256}  jsrepository.json" | sha256sum -c -
COPY oracle_js.mjs ./
ENTRYPOINT ["node", "/o/oracle_js.mjs"]
