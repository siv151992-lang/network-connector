# Caddy with the dashboard baked in.
# Build: docker build -f deploy/docker/caddy.Dockerfile -t wiremesh-caddy .
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM caddy:2-alpine
COPY --from=web /web/dist /srv/web
COPY deploy/caddy/Caddyfile /etc/caddy/Caddyfile
