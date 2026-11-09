# syntax=docker/dockerfile:1
# Build: docker build -f deploy/docker/relay.Dockerfile -t wiremesh-relay .
FROM golang:1.24-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w \
      -X github.com/siv151992-lang/network-connector/internal/version.Version=${VERSION} \
      -X github.com/siv151992-lang/network-connector/internal/version.Commit=${COMMIT} \
      -X github.com/siv151992-lang/network-connector/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /out/wiremesh-relay ./cmd/wiremesh-relay

# Distroless static image: no shell, no package manager, runs as non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wiremesh-relay /usr/local/bin/wiremesh-relay
USER nonroot:nonroot
EXPOSE 3478/udp
ENTRYPOINT ["/usr/local/bin/wiremesh-relay"]
CMD ["--stun-addr", ":3478"]
