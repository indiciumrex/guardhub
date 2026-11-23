# js_libraries lab content (ADR-0007): the libraries' real distribution files, from npm at
# exact versions (npm checks each tarball's registry integrity), baked into an nginx image.
# Nothing third-party is committed. One directory per js-*.lab.test target (nginx/js.conf).
FROM node:22.11.0-alpine AS fetch
WORKDIR /pkg
RUN npm pack --silent jquery@1.12.4 jquery@3.7.1 bootstrap@3.3.7 moment@2.18.1 \
 && for f in *.tgz; do mkdir -p "x/${f%.tgz}" && tar -xzf "$f" -C "x/${f%.tgz}"; done
COPY build.sh /build.sh
RUN sh /build.sh /pkg/x /srv/js

FROM nginx:1.27-alpine
COPY --from=fetch /srv/js /srv/js
