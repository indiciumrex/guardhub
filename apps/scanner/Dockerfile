# GuardHub scanner — multi-stage build. Build context: apps/scanner.
# Stage 1 builds a static binary; stage 2 is distroless (no shell, no package
# manager) and runs as the non-root user 65532.

FROM golang:1.25-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go build -ldflags="-s -w" -o /out/scanner ./cmd/scanner

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/scanner /usr/local/bin/scanner
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/scanner"]
