# Independent ground truth for content_signals' mixed content (ADR-0007). Lab only, never shipped.
# Chromium (the build Playwright 1.65.1 ships, inside Microsoft's image pinned by digest) loads
# each home page; its DevTools "Audits" domain reports every mixed-content decision the browser
# itself makes (blocked, automatically upgraded, warned). Nothing here decides what is mixed.
#
#   docker build -t gh-oracle-content test_corpus/oracles/content
#   docker run --rm --network guardhub-lab_lab gh-oracle-content https://cs-script.lab.test ...
FROM mcr.microsoft.com/playwright:v1.65.1-noble@sha256:1507cbfc550a63a6b7396791ca4f00df17beb56342d2447b3f106c306f525579
WORKDIR /o
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY oracle_content.mjs ./
ENTRYPOINT ["node", "/o/oracle_content.mjs"]
