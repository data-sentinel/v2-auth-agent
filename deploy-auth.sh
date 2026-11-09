#!/usr/bin/env bash
# Deploy ds-auth to the swarm using settings from .env.
# `docker stack deploy` does not read .env on its own, so export the
# non-secret keys that ds-auth.yml substitutes, then deploy.
set -euo pipefail
cd "$(dirname "$0")"

ENV_FILE="${ENV_FILE:-.env}"
KEYS="DS_AUTH_IMAGE DS_AUTH_PORT DS_AUTH_MODE DS_API_BASE_URL SSO_LOGIN_URL \
SSO_POST_LOGIN_REDIRECT_URL COOKIE_SECURE SSO_DEBUG CORS_ALLOW_ORIGIN \
DS_AUTH_DEV_LOCALHOST_SSO_FRAGMENT JWT_EXP_MIN"

for k in $KEYS; do
  line=$(grep -E "^${k}=" "$ENV_FILE" | tail -n1 || true)
  [ -n "$line" ] && export "$k=${line#*=}"
done

echo "Deploying ds-auth (DS_AUTH_MODE=${DS_AUTH_MODE:-local})"
docker stack deploy -c ds-auth.yml "${STACK_NAME:-ds}"
