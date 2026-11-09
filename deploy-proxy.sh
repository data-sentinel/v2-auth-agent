#!/usr/bin/env bash
# Deploy oauth2-proxy to the swarm using values from .env.
# (The `backend` overlay network is not attachable, so `docker compose up`
# cannot be used; run it as a swarm service in the same stack as ds-auth.)
set -euo pipefail
cd "$(dirname "$0")"

ENV_FILE="${ENV_FILE:-.env}"
KEYS="AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET OAUTH2_COOKIE_SECRET SSO_REDIRECT_URL"

for k in $KEYS; do
  line=$(grep -E "^${k}=" "$ENV_FILE" | tail -n1 || true)
  [ -n "$line" ] || { echo "Missing $k in $ENV_FILE" >&2; exit 1; }
  export "$k=${line#*=}"
done

docker stack deploy -c ds-oauth2-proxy.yml "${STACK_NAME:-ds}"
