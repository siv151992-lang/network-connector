import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the API runs separately; proxy it so the app stays
// same-origin (session cookie + CSRF work exactly as in production).
const api = process.env.WIREMESH_API ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": { target: api, ws: true }, "/healthz": api } },
  // Same CSP as production (deploy/caddy/Caddyfile), so E2E proves compliance.
  preview: {
    proxy: { "/api": { target: api, ws: true }, "/healthz": api },
    headers: {
      "Content-Security-Policy":
        "default-src 'self'; img-src 'self' data:; connect-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    },
  },
  build: { sourcemap: false },
});
