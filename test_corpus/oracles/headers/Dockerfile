# Independent ground truth for header_quality (ADR-0007). Lab only, never shipped.
# Mozilla HTTP Observatory scanner + Google CSP Evaluator, versions locked in package-lock.json.
#
#   docker build -t gh-oracle-headers test_corpus/oracles/headers
#   docker run --rm --network guardhub-lab_lab -v guardhub-lab_pki:/pki:ro \
#     -e NODE_EXTRA_CA_CERTS=/pki/ca.pem gh-oracle-headers https://hq-eval.lab.test ...
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
WORKDIR /o
COPY package.json package-lock.json ./
# --ignore-scripts: the Observatory's install scripts download live lists and build a
# Postgres client the oracle does not use.
RUN npm ci --no-audit --no-fund --ignore-scripts
# Observatory loads the Chromium HSTS preload list at start-up (normally downloaded by an
# install script). Only its CSP verdicts are used here, and they do not read that list.
RUN echo '{}' > node_modules/@mdn/mdn-http-observatory/conf/hsts-preload.json
COPY oracle_headers.mjs ./
ENTRYPOINT ["node", "/o/oracle_headers.mjs"]
