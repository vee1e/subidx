#!/bin/sh
# subidx on Render (and plain docker). PORT and RENDER_EXTERNAL_HOSTNAME
# are provided by Render automatically; the rest have safe defaults.
set -e
exec subidx serve \
  -store "${STORE_DIR:-/var/data/subidx}" \
  -addr ":${PORT:-8080}" \
  -no-drain \
  -trusted-proxy-hops "${TRUSTED_HOPS:-1}" \
  -rate-limit "${RATE_LIMIT:-2000}" \
  -allowed-hosts "${ALLOWED_HOSTS:-$RENDER_EXTERNAL_HOSTNAME}" \
  -cors-origins "${CORS_ORIGINS:-}"
