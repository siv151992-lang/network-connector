# syntax=docker/dockerfile:1
# Build: docker build -f deploy/docker/server.Dockerfile -t wiremesh-server .
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
    -o /out/wiremesh-server ./cmd/wiremesh-server

# Distroless static image: no shell, no package manager, runs as non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wiremesh-server /usr/local/bin/wiremesh-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/wiremesh-server"]
CMD ["serve"]
