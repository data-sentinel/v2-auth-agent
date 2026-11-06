#!/usr/bin/env python3
"""
ds_auth.py

DS-auth microservice for Data Sentinel

- LOCAL mode:
    * React posts username/password to /auth/local/login
    * Service validates credentials in the database via sentinel.sys_verify_login()
    * On success, issues a DS JWT and sets ds_token cookie

- SSO mode:
    * oauth2-proxy forwards authenticated identity to /auth/sso/callback
    * Service issues DS JWT and sets ds_token cookie

Common:
    * JWTs are RS256-signed with a private key from JWT_PRIVATE_KEY
    * DB credentials are loaded from Docker Swarm secrets using the
      same pattern as other workers (repository_* secrets)
"""


# define version global
# global_app_version = '2024.51.01'    # Initial Version
# global_app_version = '2024.51.02'    # Updated to use private pem from DS SECRETS
global_app_version = '2026.45.01'    # Login stamp for the activity log; application_name on the DB pool
global_app_version = '2026.45.02'    # v2: sys_verify_login, SSO errors redirect to /login, COOKIE_SECURE, DS_AUTH_MODE, no stamp_login


# Base imports
import os
import sys
import json
import base64
import asyncio
import datetime
from typing import Union
import logging


import urllib.parse

import asyncpg
import jwt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from quart import Quart, request, jsonify, redirect
from quart_cors import cors

# ---------------------------------------------------------------------------
# Standard DS worker globals and paths
# ---------------------------------------------------------------------------

env_ext_mnt_log = "/mnt/logs"
env_ext_config = "/mnt/config"
env_ext_mnt_parquet = "/mnt/datasets"
env_ext_mnt_secrets = "/run/secrets"

#env_agent_name = os.environ.get("DS_SERVICE", "ds_auth")
env_agent_name = "ds_auth"

# Global status and connection pool (worker standard)
global_status: dict = {}
global_conn_pool: Union[asyncpg.Pool, None] = None

# ---------------------------------------------------------------------------
# DS Logger standard
# ---------------------------------------------------------------------------

def create_logger(logger_name, log_file, level=logging.INFO) -> bool:
    try:
        log = logging.getLogger(logger_name)
        log.setLevel(level)

        # Prevent accidental propagation to root
        log.propagate = False

        # Remove closed file handlers
        for h in list(log.handlers):
            if isinstance(h, logging.FileHandler) and h.stream.closed:
                log.removeHandler(h)

        # Attach file handler only if not already present
        if not any(
            isinstance(h, logging.FileHandler) and h.baseFilename == log_file
            for h in log.handlers
        ):
            formatter = logging.Formatter(
                '%(asctime)s|%(levelname)s|%(message)s'
            )
            handler = logging.FileHandler(
                log_file, mode='a', encoding='utf-8'
            )
            handler.setFormatter(formatter)
            log.addHandler(handler)

        return True

    except Exception:
        # Logging must never throw upward during startup
        return False



def logger(msg, level, log_scope):
    log = logging.getLogger(log_scope)
    lvl = (level or "").lower()

    if lvl == 'info':
        log.info(msg)
    elif lvl in ('warning', 'warn'):
        log.warning(msg)
    elif lvl == 'error':
        log.error(msg)
    else:
        log.debug(msg)

    return True


def close_logger(log_scope):
    log = logging.getLogger(log_scope)
    for h in list(log.handlers):
        log.removeHandler(h)
        h.close()
    return True


global_worker_log_file = env_ext_mnt_log+'/'+env_agent_name+'_core.log'

create_logger('worker_scope', global_worker_log_file)
logger('Starting DS-AUTH Service - agent name: ' + env_agent_name + 'version: ' + global_app_version, 'info', 'worker_scope')

# ---------------------------------------------------------------------------
# Secret helpers (DS standard)
# ---------------------------------------------------------------------------

def aes_decrypt(enc, key, iv):
    iv_enc = iv.encode("utf-8")
    enc = base64.b64decode(enc)
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv_enc)
    return unpad(cipher.decrypt(enc), 16).decode("utf-8", "ignore")


def get_secret(secret_name):
    # Read from Docker secrets in /run/secrets/
    try:
        with open(env_ext_mnt_secrets + "/" + secret_name, "r") as f:
            json_content = json.load(f)
        return json_content[secret_name]
    except Exception as e:
        logger(f"Failed to read secret {secret_name}: {e}", "warn", "worker_scope")
        return False


def get_encrypted_secret(secret_name):
    try:
        _aes_key = get_secret("aeskey")
        _aes_iv = get_secret("aesiv")
        _encrypt_text = get_secret(secret_name)
        return aes_decrypt(_encrypt_text, _aes_key, _aes_iv)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Load Docker Swarm DB secrets (repository_*), same as other workers
# ---------------------------------------------------------------------------

try:
    env_repo_host = get_secret("repository_host")
    env_repo_port = get_secret("repository_port")
    env_repo_db = get_secret("repository_name")
    env_repo_user = get_secret("repository_username")
    env_repo_pswd = get_encrypted_secret("repository_password_encrypt")

    if not all([env_repo_host, env_repo_port, env_repo_db, env_repo_user]) or env_repo_pswd is False:
        raise RuntimeError("One or more repository_* secrets are missing or invalid in /run/secrets/.")

    global_status["secrets_loaded"] = "SUCCESS"
    global_status["database_info"] = (
        "host: "
        + str(env_repo_host)
        + ", port: "
        + str(env_repo_port)
        + ", db_name: "
        + str(env_repo_db)
    )
    logger("Docker Secrets loaded from /run/secrets/...", "info", "worker_scope")
except Exception as e:
    logger("Docker Secrets NOT loaded - shutting down", "error", "worker_scope")
    logger("Returned Error: " + str(e), "error", "worker_scope")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Postgres Functions (DS standard)
# ---------------------------------------------------------------------------

async def init_connection_pool(max_retries=3, retry_interval=30):
    """
    Initializes or validates the global asyncpg connection pool.
    Tries up to `max_retries` times before failing.
    Returns: {status: 200/400, message: str}
    """
    global global_conn_pool

    attempt = 0
    while attempt < max_retries:
        attempt += 1

        if global_conn_pool is None:
            try:
                logger(
                    f"init_connection_pool|attempt {attempt}: trying to connect...",
                    "info",
                    "worker_scope",
                )
                global_conn_pool = await asyncpg.create_pool(
                    user=env_repo_user,
                    password=env_repo_pswd,
                    database=env_repo_db,
                    host=env_repo_host,
                    port=env_repo_port,
                    min_size=5,
                    max_size=20,
                    server_settings={"application_name": env_agent_name},
                )
            except Exception as e:
                logger(
                    f"init_connection_pool|attempt {attempt}: failed to create pool - {str(e)}",
                    "error",
                    "worker_scope",
                )
                global_conn_pool = None
                if attempt < max_retries:
                    logger(
                        "Waiting for DB to become available...",
                        "warning",
                        "worker_scope",
                    )
                    await asyncio.sleep(retry_interval)
                continue

        # Try to validate the pool
        try:
            async with global_conn_pool.acquire() as conn:
                await conn.execute("SELECT 1")
            return {"status": 200, "message": "success"}
        except Exception as e:
            logger(
                f"init_connection_pool|attempt {attempt}: pool test failed - {str(e)}",
                "error",
                "worker_scope",
            )
            global_conn_pool = None
            if attempt < max_retries:
                logger(
                    "Waiting for DB to become available...",
                    "warning",
                    "worker_scope",
                )
                await asyncio.sleep(retry_interval)

    # If we got here, all attempts failed
    logger(
        "init_connection_pool|All retries failed. Shutting down worker.",
        "critical",
        "worker_scope",
    )
    return {"status": 400, "message": "Database connection failed after multiple attempts"}


# ---------------------------------------------------------------------------
# JWT / auth configuration
# ---------------------------------------------------------------------------

def _read_auth_mode() -> str:
    mode = (os.environ.get("DS_AUTH_MODE") or os.environ.get("AUTH_MODE") or "local").strip().lower()
    return mode if mode in ("local", "sso", "both") else "local"


AUTH_MODE = _read_auth_mode()  # "local", "sso" or "both"
LOCAL_ENABLED = AUTH_MODE in ("local", "both")
SSO_ENABLED = AUTH_MODE in ("sso", "both")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# Cookie "secure" flag. Default true; only a plain-http local setup sets it false.
COOKIE_SECURE = _env_bool("COOKIE_SECURE", True)

# /sso/debug is only registered when SSO_DEBUG=true (default false).
SSO_DEBUG = _env_bool("SSO_DEBUG", False)

JWT_PRIVATE_KEY_SECRET = "auth_private_key"
JWT_PUBLIC_KEY_SECRET  = "auth_public_key"
JWT_ISS = "datasentinel-auth"
JWT_AUD = "datasentinel-api"
JWT_ALGO = "RS256"
JWT_EXP_MIN = os.environ.get("JWT_EXP_MIN", "480")  # minutes (default 8 hours)

JWT_PRIVATE_KEY: Union[str, None] = None
JWT_PUBLIC_KEY: Union[str, None] = None

# JWT blacklist for immediate token invalidation on logout
# In production, this should be Redis/database-backed for scalability
JWT_BLACKLIST = set()

# SSO redirect URL (oauth2-proxy start endpoint)
SSO_LOGIN_URL = os.environ.get("SSO_LOGIN_URL", "/oauth2/start")

# Post-login redirect URL — where the browser is sent after a successful SSO login
SSO_POST_LOGIN_REDIRECT_URL = os.environ.get("SSO_POST_LOGIN_REDIRECT_URL", "/")

# No Azure logout - keeping logout simple (local cookies only)

# Dev-only: append JWT to redirect URL fragment (#ds_token=...) when redirect target is
# localhost or 127.0.0.1. A remote host cannot Set-Cookie for localhost; the SPA must
# read the hash and persist the token (e.g. memory or non-httponly storage). Default off.
DS_AUTH_DEV_LOCALHOST_SSO_FRAGMENT = os.environ.get(
    "DS_AUTH_DEV_LOCALHOST_SSO_FRAGMENT", ""
).strip().lower() in ("1", "true", "yes")

# Base URL of the DS PostgREST API — used to auto-provision SSO users on first login
DS_API_BASE_URL = os.environ.get("DS_API_BASE_URL", "http://localhost:37963")

# Access lists for auto-provisioned SSO users keyed by role
_SSO_ACCESS_ADMIN = [
    "mapping", "remediation", "assessment", "operate",
    "configure", "projects", "policies", "reporting", "program",
]
_SSO_ACCESS_USER = [
    "mapping", "remediation", "assessment",
    "projects", "policies", "reporting", "program",
]

# CORS configuration (comma-separated origins, or empty to disable)
# Default is empty: the app is served same-origin through nginx.
CORS_ALLOW_ORIGIN = os.environ.get("CORS_ALLOW_ORIGIN", "")
_allowed_origins = [o.strip() for o in CORS_ALLOW_ORIGIN.split(",") if o.strip()]

app = Quart(__name__)
app = cors(
    app,
    allow_origin=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


def get_raw_secret(secret_name):
    """Read a Docker Swarm secret file as raw text (for non-JSON secrets like PEM keys)."""
    try:
        with open(env_ext_mnt_secrets + "/" + secret_name, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        logger(f"Failed to read raw secret {secret_name}: {e}", "warn", "worker_scope")
        return False


def load_jwt_keys() -> tuple:
    """
    Load RSA key pair from Docker Swarm secrets as raw PEM files:
      /run/secrets/auth_private_key  — raw PEM private key
      /run/secrets/auth_public_key   — raw PEM public key

    Returns: (private_key_pem, public_key_pem)
    """
    try:
        private_key_pem = get_raw_secret(JWT_PRIVATE_KEY_SECRET)
        public_key_pem = get_raw_secret(JWT_PUBLIC_KEY_SECRET)

        if not private_key_pem or not public_key_pem:
            raise RuntimeError("JWT keys not available in Docker secrets.")

        logger("JWT keys loaded from Docker secrets", "info", "worker_scope")
        return private_key_pem, public_key_pem
    except Exception as exc:
        logger(
            f"Unable to load JWT keys from /run/secrets/: {exc}",
            "critical", 
            "worker_scope",
        )
        raise


def create_ds_jwt(user_id: int, email: str, name: str) -> str:
    """
    Create RS256-signed Data Sentinel JWT.

    Claims:
      role  — PostgREST DB role
      sub   — user_id (string) as the stable unique identifier
      email — user email address
      name  — display name (user_desc from DB)
      iss   — token issuer
      aud   — intended audience
      iat   — issued-at timestamp
      exp   — expiry timestamp
    """
    assert JWT_PRIVATE_KEY is not None

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    exp = now + datetime.timedelta(minutes=int(JWT_EXP_MIN))

    payload = {
        "role": "sentinel-anon",
        "sub": str(user_id),
        "email": email,
        "name": name,
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    return jwt.encode(payload, JWT_PRIVATE_KEY, algorithm=JWT_ALGO)


def attach_ds_cookie(response, token: str):
    """
    Attach ds_token cookie with secure defaults.
    """
    response.set_cookie(
        "ds_token",
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="Lax",
        path="/",
        max_age=int(JWT_EXP_MIN) * 60,
    )
    return response


def _append_jwt_fragment_for_localhost_dev(redirect_url: str, token: str) -> str:
    if not DS_AUTH_DEV_LOCALHOST_SSO_FRAGMENT:
        return redirect_url
    parsed = urllib.parse.urlparse(redirect_url)
    if parsed.hostname not in ("localhost", "127.0.0.1"):
        return redirect_url
    frag = f"ds_token={urllib.parse.quote(token, safe='')}"
    if parsed.fragment:
        frag = f"{parsed.fragment}&{frag}"
    return urllib.parse.urlunparse(parsed._replace(fragment=frag))


# ---------------------------------------------------------------------------
# SSO user auto-provisioning helpers
# ---------------------------------------------------------------------------

def create_service_jwt() -> str:
    """
    Create a short-lived RS256 JWT for internal service-to-service API calls.
    Used when ds-auth needs to provision a new SSO user via the PostgREST API.
    """
    assert JWT_PRIVATE_KEY is not None

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    exp = now + datetime.timedelta(minutes=5)

    payload = {
        "role": "sentinel-anon",
        "sub": "0",
        "email": "service@datasentinel",
        "name": "DS Auth Service",
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, JWT_PRIVATE_KEY, algorithm=JWT_ALGO)


def _decode_bearer_claims(auth_header: str) -> dict:
    """
    Decode the payload of the Bearer token forwarded by oauth2-proxy
    (via --pass-authorization-header=true) without signature verification.
    Returns the decoded claims dict, or {} on any error.
    """
    try:
        if not auth_header.startswith("Bearer "):
            return {}
        token = auth_header[7:]
        # JWT payload is the second segment, base64url-encoded
        payload_b64 = token.split(".")[1]
        # Add padding if needed
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}


def _infer_role_from_access(access_list) -> str:
    """
    Derive the DS role ('admin' or 'user') from the stored user_access list.

    Admin accounts carry the exclusive features 'operate' and 'configure' that
    are absent from the standard user access list.  Any account that has at
    least one of those features is treated as 'admin'.
    """
    if isinstance(access_list, str):
        try:
            access_list = json.loads(access_list)
        except Exception:
            return "user"
    if isinstance(access_list, list):
        admin_only = {"operate", "configure"}
        if admin_only.intersection(set(access_list)):
            return "admin"
    return "user"


def _determine_sso_role(auth_header: str, groups_header: str) -> str:
    """
    Derive a DS provisioning role ('admin' or 'user') by inspecting:
      1. The 'roles' claim in the OAuth2 Bearer access token (primary source).
      2. The X-Forwarded-Groups / X-Auth-Request-Groups header (fallback).

    Returns 'admin' if any role/group contains the word 'admin', else 'user'.
    """
    # Primary: check roles[] array in the access token JWT
    claims = _decode_bearer_claims(auth_header)
    token_roles = claims.get("roles", [])
    if isinstance(token_roles, list):
        if any("admin" in str(r).lower() for r in token_roles):
            logger(
                f"_determine_sso_role|admin role found in token roles: {token_roles}",
                "info",
                "worker_scope",
            )
            return "admin"
    elif isinstance(token_roles, str) and "admin" in token_roles.lower():
        return "admin"

    # Fallback: check groups header forwarded by oauth2-proxy
    if groups_header and "admin" in groups_header.lower():
        logger(
            f"_determine_sso_role|admin found in groups header: {groups_header}",
            "info",
            "worker_scope",
        )
        return "admin"

    return "user"


async def provision_sso_user(
    username: str, email: str, display_name: str, role: str
) -> dict:
    """
    Create a new user account in the DS database via the PostgREST RPC endpoint.

    Uses a short-lived service JWT for the Authorization header.
    Returns {"success": True} or {"success": False, "error": "..."}.
    """
    import aiohttp  # imported lazily — only needed in SSO mode

    access_list = _SSO_ACCESS_ADMIN if role == "admin" else _SSO_ACCESS_USER

    payload = {
        "v_transaction": {
            "iud": "i",
            "user_name": username,
            "user_pswd": None,
            "user_desc": display_name,
            "user_email": email,
            "user_access": access_list,
        }
    }

    url = DS_API_BASE_URL.rstrip("/") + "/rpc/post_user_accounts_data"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {create_service_jwt()}",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status in (200, 201, 204):
                    logger(
                        f"provision_sso_user|Created user '{username}' (role: {role})",
                        "info",
                        "worker_scope",
                    )
                    return {"success": True}
                body = await resp.text()
                logger(
                    f"provision_sso_user|API returned {resp.status} for '{username}': {body}",
                    "error",
                    "worker_scope",
                )
                return {"success": False, "error": f"API returned {resp.status}: {body}"}
    except Exception as exc:
        logger(f"provision_sso_user|Exception for '{username}': {exc}", "error", "worker_scope")
        return {"success": False, "error": str(exc)}


async def sync_sso_user_role(user_id: int, username: str, new_role: str) -> bool:
    """
    Update the user_access column in the DB to match the role currently held in
    Azure AD.  Called on every SSO login when the Azure role differs from what
    is stored in DS.

    Returns True on success, False on error (non-fatal — the login still
    proceeds with the now-stale access list and is retried on the next login).
    """
    if global_conn_pool is None:
        return False

    access_list = _SSO_ACCESS_ADMIN if new_role == "admin" else _SSO_ACCESS_USER
    try:
        async with global_conn_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE sentinel.user_accounts
                SET user_access = $1
                WHERE user_id = $2
                """,
                json.dumps(access_list),
                user_id,
            )
        logger(
            f"sync_sso_user_role|Updated '{username}' (id={user_id}) "
            f"to role '{new_role}' with access {access_list}",
            "info",
            "worker_scope",
        )
        return True
    except Exception as exc:
        logger(
            f"sync_sso_user_role|Failed to update '{username}' (id={user_id}): {exc}",
            "error",
            "worker_scope",
        )
        return False


# ---------------------------------------------------------------------------
# Quart lifecycle hooks
# ---------------------------------------------------------------------------

@app.before_serving
async def startup():
    global JWT_PRIVATE_KEY, JWT_PUBLIC_KEY
    logger("DS-auth startup: loading JWT key and initializing DB pool...", "info", "worker_scope")
    
    # Debug: Check if secrets directory exists
    import os
    secrets_dir = "/run/secrets"
    if os.path.exists(secrets_dir):
        secrets_list = os.listdir(secrets_dir)
        logger(f"Found secrets directory with files: {secrets_list}", "info", "worker_scope")
    else:
        logger(f"Secrets directory {secrets_dir} does not exist!", "error", "worker_scope")
    
    # Debug: Check database configuration
    logger(f"Database config - Host: {env_repo_host}, Port: {env_repo_port}, DB: {env_repo_db}, User: {env_repo_user}", "info", "worker_scope")
    
    try:
        JWT_PRIVATE_KEY, JWT_PUBLIC_KEY = load_jwt_keys()
        logger("JWT keys loaded successfully", "info", "worker_scope")
    except Exception as e:
        logger(f"Failed to load JWT keys: {e}", "critical", "worker_scope")
        sys.exit(1)

    # Initialize DB pool with faster startup parameters (shorter retry interval, fewer retries)
    try:
        logger("Starting database connection initialization...", "info", "worker_scope")
        result = await init_connection_pool(max_retries=2, retry_interval=5)
        logger(f"Database connection result: {result}", "info", "worker_scope")
        if result.get("status") != 200:
            logger("Failed to initialize DB pool on startup. Exiting.", "critical", "worker_scope")
            sys.exit(1)
        logger("Database connection pool initialized successfully", "info", "worker_scope")
    except Exception as e:
        logger(f"Database connection failed during startup: {e}", "critical", "worker_scope")
        sys.exit(1)

    logger("DS-auth startup complete.", "info", "worker_scope")


@app.after_serving
async def shutdown():
    global global_conn_pool
    logger("DS-auth shutdown: closing DB pool...", "info", "worker_scope")
    if global_conn_pool is not None:
        await global_conn_pool.close()
        global_conn_pool = None
    logger("DS-auth shutdown complete.", "info", "worker_scope")


# ---------------------------------------------------------------------------
# Helper: verify JWT token
# ---------------------------------------------------------------------------

def blacklist_jwt_token(token: str) -> None:
    """
    Add a JWT token to the blacklist to immediately invalidate it.
    This prevents token reuse after logout.
    """
    # For production: store in Redis with TTL = token's remaining lifetime
    JWT_BLACKLIST.add(token)
    
    # Clean up expired entries periodically (optional optimization)
    if len(JWT_BLACKLIST) > 10000:  # Prevent memory bloat
        _cleanup_expired_blacklist_entries()


def _cleanup_expired_blacklist_entries() -> None:
    """
    Remove naturally expired tokens from blacklist to prevent memory bloat.
    This is an optimization - blacklisted tokens would be rejected anyway if expired.
    """
    try:
        now = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
        tokens_to_remove = []
        
        for token in JWT_BLACKLIST:
            try:
                # Decode without verification to check expiry
                unverified = jwt.decode(token, options={"verify_signature": False})
                if unverified.get("exp", 0) < now:
                    tokens_to_remove.append(token)
            except Exception:
                # If token is malformed, remove it
                tokens_to_remove.append(token)
        
        for token in tokens_to_remove:
            JWT_BLACKLIST.discard(token)
            
    except Exception:
        # If cleanup fails, continue - blacklist will still work
        pass


def verify_jwt_token(token: str) -> dict:
    """
    Verify and decode a JWT token.
    Returns: {"valid": True, "payload": {...}} or {"valid": False, "error": "..."}
    """
    if not JWT_PUBLIC_KEY:
        return {"valid": False, "error": "JWT verification not configured"}
    
    # Check if token is blacklisted (logout invalidation)
    if token in JWT_BLACKLIST:
        return {"valid": False, "error": "Token has been invalidated"}
    
    try:
        payload = jwt.decode(
            token,
            JWT_PUBLIC_KEY,
            algorithms=[JWT_ALGO],
            issuer=JWT_ISS,
            audience=JWT_AUD,
        )
        return {"valid": True, "payload": payload}
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Token has expired"}
    except jwt.InvalidTokenError as e:
        return {"valid": False, "error": f"Invalid token: {str(e)}"}


# ---------------------------------------------------------------------------
# Helper: validate local credentials via PostgreSQL
# ---------------------------------------------------------------------------

def _client_address() -> str:
    """Client address as seen through nginx (X-Forwarded-For first hop), else the socket peer."""
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.headers.get("X-Real-IP") or request.remote_addr or ""


async def validate_local_credentials(username: str, password: str) -> dict:
    """
    Validate credentials inside the database with sentinel.sys_verify_login()
    (bcrypt check; ds-auth has no SELECT on user_pswd). One row = signed in,
    no row = refused. The client address and user agent are passed so the
    database logs 'user.sign_in_failed' with them.

    Returns:
        {"valid": True, "session_id": ..., "user_id": ..., "user_name": ...,
         "user_desc": ..., "access_list": [...]} on success
        {"valid": False, "error": "reason"} on failure
    """
    if global_conn_pool is None:
        logger("validate_local_credentials|global_conn_pool is None", "error", "worker_scope")
        raise RuntimeError("Database connection pool is not initialized.")

    try:
        async with global_conn_pool.acquire() as conn:
            user_row = await conn.fetchrow(
                "SELECT user_id, user_name, user_desc, user_access FROM sentinel.sys_verify_login($1, $2, $3, $4)",
                username,
                password,
                _client_address(),
                request.headers.get("User-Agent", ""),
            )

            if user_row is None:
                logger(f"validate_local_credentials|Sign-in refused for: {username}", "warning", "worker_scope")
                return {"valid": False, "error": "Invalid credentials"}

            session_id = await conn.fetchval("SELECT nextval('sentinel.seq_session')")

            raw_access = user_row["user_access"]
            if isinstance(raw_access, str):
                raw_access = json.loads(raw_access)

            return {
                "valid": True,
                "session_id": session_id,
                "user_id": user_row["user_id"],
                "user_name": user_row["user_name"],
                "user_desc": user_row["user_desc"],
                "access_list": raw_access,
            }
    except Exception as exc:
        logger(f"validate_local_credentials|DB error: {exc}", "error", "worker_scope")
        raise


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/config")
async def auth_config():
    """
    Informational endpoint — returns which auth method is active
    based on DS_AUTH_MODE ("local", "sso" or "both").
    Does not gate or block any other API.
    """
    return jsonify(
        {
            "auth_mode": AUTH_MODE,
            "local_enabled": LOCAL_ENABLED,
            "sso_enabled": SSO_ENABLED,
        }
    )


@app.post("/local/login")
async def auth_local_login():
    """
    Local login endpoint.

    React posts:
      { "username": "...", "password": "..." }

    DS-auth validates against PostgreSQL and, on success, issues
    a DS JWT and sets ds_token cookie.
    """
    if not LOCAL_ENABLED:
        return jsonify({"authenticated": False, "error": "Local sign-in is disabled"}), 403

    data = await request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"authenticated": False, "error": "Invalid JSON body"}), 400

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"authenticated": False, "error": "Missing username or password"}), 400

    try:
        result = await validate_local_credentials(username, password)
    except Exception as exc:
        logger(f"auth_local_login|Exception: {exc}", "error", "worker_scope")
        return jsonify({"authenticated": False, "error": "Authentication service error"}), 500

    if not result.get("valid"):
        error_msg = result.get("error", "Invalid credentials")
        return jsonify({"authenticated": False, "error": error_msg}), 401

    email = username if "@" in username else f"{username}@local"
    token = create_ds_jwt(result["user_id"], email, result["user_desc"] or result["user_name"])

    resp = jsonify(
        {
            "status": "OK",
            "session_id": result["session_id"],
            "user_id": result["user_id"],
            "user_name": result["user_name"],
            "user_desc": result["user_desc"],
            "access_list": result["access_list"],
        }
    )
    return attach_ds_cookie(resp, token)


def _sso_error(key: str):
    """Every SSO failure lands on the login page with a machine-readable key."""
    return redirect("/login?sso_error=" + urllib.parse.quote(key, safe=""))


_USER_COLUMNS = "user_id, user_name, user_desc, user_access, delete_dt"


async def _fetch_user_by_name(username: str):
    async with global_conn_pool.acquire() as conn:
        return await conn.fetchrow(
            f"SELECT {_USER_COLUMNS} FROM sentinel.user_accounts WHERE LOWER(user_name) = LOWER($1)",
            username,
        )


@app.get("/sso/callback")
async def auth_sso_callback():
    """
    SSO callback endpoint.

    oauth2-proxy forwards the verified identity via X-Forwarded-Email /
    X-Forwarded-Groups headers. On success: sets ds_token and redirects to
    SSO_POST_LOGIN_REDIRECT_URL. On any failure: redirects to
    /login?sso_error=<key> (no_identity, inactive, provisioning_failed,
    service_error, not_enabled).
    """
    if not SSO_ENABLED:
        return _sso_error("not_enabled")

    email = (
        request.headers.get("X-Forwarded-Email")
        or request.headers.get("X-Auth-Request-Email")
    )
    if not email:
        return _sso_error("no_identity")

    # Local username = left-hand part of the email.
    username = email.split("@", 1)[0]

    if global_conn_pool is None:
        return _sso_error("service_error")

    auth_header = request.headers.get("Authorization", "")
    groups_header = (
        request.headers.get("X-Forwarded-Groups")
        or request.headers.get("X-Auth-Request-Groups")
        or ""
    )

    # --- Step 1: look up user ---
    try:
        user_row = await _fetch_user_by_name(username)
    except Exception as exc:
        logger(f"auth_sso_callback|DB lookup error: {exc}", "error", "worker_scope")
        return _sso_error("service_error")

    # --- Step 2: reject deactivated accounts BEFORE any role sync ---
    if user_row is not None and user_row["delete_dt"] is not None:
        logger(f"auth_sso_callback|Deactivated account '{username}'", "warning", "worker_scope")
        return _sso_error("inactive")

    sso_role = _determine_sso_role(auth_header, groups_header)

    if user_row is None:
        # --- Step 3: auto-provision ---
        display_name = (
            request.headers.get("X-Forwarded-Preferred-Username")
            or request.headers.get("X-Auth-Request-User")
            or username
        )
        logger(
            f"auth_sso_callback|User '{username}' not in DS DB — provisioning (role: {sso_role})",
            "info",
            "worker_scope",
        )
        provision_result = await provision_sso_user(username, email, display_name, sso_role)
        if not provision_result.get("success"):
            logger(
                f"auth_sso_callback|Provisioning failed for '{username}': {provision_result.get('error')}",
                "error",
                "worker_scope",
            )
            return _sso_error("provisioning_failed")

        try:
            user_row = await _fetch_user_by_name(username)
        except Exception as exc:
            logger(f"auth_sso_callback|DB re-fetch error: {exc}", "error", "worker_scope")
            return _sso_error("service_error")

        if user_row is None:
            logger(
                f"auth_sso_callback|User '{username}' still not found after provisioning",
                "error",
                "worker_scope",
            )
            return _sso_error("provisioning_failed")
        if user_row["delete_dt"] is not None:
            return _sso_error("inactive")
    else:
        # --- Step 3a: sync role for existing, active users ---
        db_role = _infer_role_from_access(user_row["user_access"])
        if sso_role != db_role:
            logger(
                f"auth_sso_callback|Role change detected for '{username}': "
                f"DB='{db_role}' → Azure='{sso_role}'. Updating user_access...",
                "info",
                "worker_scope",
            )
            if await sync_sso_user_role(user_row["user_id"], username, sso_role):
                try:
                    async with global_conn_pool.acquire() as conn:
                        user_row = await conn.fetchrow(
                            f"SELECT {_USER_COLUMNS} FROM sentinel.user_accounts WHERE user_id = $1",
                            user_row["user_id"],
                        )
                except Exception as exc:
                    # Non-fatal: continue with the stale row; corrected next login.
                    logger(
                        f"auth_sso_callback|DB re-fetch after role sync error: {exc}",
                        "error",
                        "worker_scope",
                    )

    # --- Step 4: issue session and DS JWT ---
    try:
        async with global_conn_pool.acquire() as conn:
            await conn.fetchval("SELECT nextval('sentinel.seq_session')")
    except Exception as exc:
        logger(f"auth_sso_callback|DB session error: {exc}", "error", "worker_scope")
        return _sso_error("service_error")

    token = create_ds_jwt(user_row["user_id"], email, user_row["user_desc"] or user_row["user_name"])

    separator = "&" if "?" in SSO_POST_LOGIN_REDIRECT_URL else "?"
    redirect_url = (
        SSO_POST_LOGIN_REDIRECT_URL
        + separator
        + "username="
        + urllib.parse.quote(user_row["user_name"], safe="")
    )
    redirect_url = _append_jwt_fragment_for_localhost_dev(redirect_url, token)

    _log_url = redirect_url
    if urllib.parse.urlparse(redirect_url).fragment:
        _p = urllib.parse.urlparse(redirect_url)
        _log_url = urllib.parse.urlunparse(_p._replace(fragment="[redacted]"))

    logger(
        f"auth_sso_callback|Login successful for '{user_row['user_name']}' "
        f"(id={user_row['user_id']}) — redirecting to {_log_url}",
        "info",
        "worker_scope",
    )

    resp = redirect(redirect_url)
    return attach_ds_cookie(resp, token)


if SSO_DEBUG:
    @app.get("/sso/debug")
    async def auth_sso_debug():
        """
        DEBUG ONLY (SSO_DEBUG=true; off by default). Returns every request
        header, INCLUDING the Azure access token — never enable in production.
        """
        def _decode_jwt_payload(token: str) -> dict:
            try:
                payload_b64 = token.split(".")[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)
                return json.loads(base64.urlsafe_b64decode(payload_b64))
            except Exception as exc:
                return {"decode_error": str(exc)}

        access_token_payload = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            access_token_payload = _decode_jwt_payload(auth_header[7:])

        return jsonify({
            "sso_identity": {
                "email": request.headers.get("X-Auth-Request-Email"),
                "user": request.headers.get("X-Auth-Request-User"),
                "groups": request.headers.get("X-Auth-Request-Groups"),
                "preferred_username": request.headers.get("X-Forwarded-User"),
            },
            "access_token_claims": access_token_payload,
            "all_headers": dict(request.headers),
        })


@app.get("/sso/login")
async def auth_sso_login():
    """Redirects the user to OAuth2-Proxy to start SSO (or to /login if SSO is off)."""
    if not SSO_ENABLED:
        return _sso_error("not_enabled")
    return redirect(SSO_LOGIN_URL)


@app.route("/logout", methods=["GET", "POST"])
async def auth_logout():
    """
    Logout endpoint - behavior depends on AUTH_MODE.
    
    LOCAL mode: Simple logout (clear ds_token cookie only)
    SSO mode: Enhanced logout (JWT blacklisting + oauth2-proxy cookie clearing)
    """

    # Check if this looks like a fetch request
    sec_fetch_mode = (request.headers.get("Sec-Fetch-Mode") or "").strip().lower()
    accept = (request.headers.get("Accept") or "").lower()
    x_requested_with = (request.headers.get("X-Requested-With") or "").strip().lower()
    looks_like_fetch = (
        sec_fetch_mode == "cors"
        or "application/json" in accept
        or x_requested_with in ("xmlhttprequest", "fetch")
    )

    # Get current AUTH_MODE from environment (fixes issue with global variable)
    current_auth_mode = AUTH_MODE

    # Create response and clear cookies
    if looks_like_fetch:
        resp = jsonify({
            "authenticated": False,
            "message": "Successfully logged out"
        })
    else:
        # Redirect behavior depends on AUTH_MODE
        if not SSO_ENABLED:
            # LOCAL mode: redirect to frontend home page
            # Use absolute URL to avoid relative path issues
            frontend_url = f"{request.scheme}://{request.host}/"
            resp = redirect(frontend_url)
        else:
            # SSO mode: redirect to logout confirmation page
            resp = redirect("/logged-out")

    # Always clear ds_token cookie
    resp.delete_cookie("ds_token", path="/")
    
    # SSO mode: Additional security measures
    if SSO_ENABLED:
        # Blacklist the current JWT token to immediately invalidate it
        current_token = request.cookies.get("ds_token")
        if current_token:
            blacklist_jwt_token(current_token)
        
        # Clear oauth2-proxy cookies (multiple variants)
        for suffix in ["", "_0", "_1", "_2", "_3"]:
            resp.delete_cookie(f"_oauth2_proxy{suffix}", path="/")
    
    return resp


@app.get("/logged-out")
async def logged_out():
    """
    Public logged-out confirmation page.
    This route is unprotected (oauth2-proxy skips it) so users land here
    after logout without triggering re-authentication.
    """
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Logged Out - Data Sentinel</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .container { max-width: 400px; margin: 0 auto; }
            .success { color: #28a745; }
            .btn { background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="success">✓ Successfully Logged Out</h1>
            <p>You have been logged out of Data Sentinel and Microsoft Azure.</p>
            <a href="/" class="btn">Sign In Again</a>
        </div>
    </body>
    </html>
    """


@app.get("/verify")
async def auth_verify():
    """
    Verify JWT token endpoint.
    
    Checks if the current ds_token cookie contains a valid JWT.
    Returns token payload if valid, error if invalid or missing.
    """
    token = request.cookies.get("ds_token")
    
    if not token:
        return jsonify({
            "valid": False,
            "authenticated": False,
            "error": "No authentication token found"
        }), 401
    
    result = verify_jwt_token(token)
    
    if result.get("valid"):
        payload = result.get("payload", {})
        return jsonify({
            "valid": True,
            "authenticated": True,
            "role": payload.get("role"),
            "sub": payload.get("sub"),
            "email": payload.get("email"),
            "name": payload.get("name"),
            "iss": payload.get("iss"),
            "aud": payload.get("aud"),
            "iat": payload.get("iat"),
            "expires_at": payload.get("exp"),
        })
    else:
        return jsonify({
            "valid": False,
            "authenticated": False,
            "error": result.get("error", "Invalid token")
        }), 401


@app.get("/health")
async def health():
    """
    Basic health check.
    """
    return jsonify({"status": "ok"})


@app.get("/secrets-test")
async def secrets_test():
    """
    Test endpoint to verify secret loading and password decryption.
    """
    try:
        # Test reading secrets
        aes_key = get_secret("aeskey")
        aes_iv = get_secret("aesiv")
        repo_host = get_secret("repository_host")
        repo_port = get_secret("repository_port")
        repo_name = get_secret("repository_name")
        repo_user = get_secret("repository_username")
        
        # Test password decryption
        decrypted_password = get_encrypted_secret("repository_password_encrypt")
        
        # Test JWT keys
        try:
            private_key = get_raw_secret("auth_private_key")
            public_key = get_raw_secret("auth_public_key")
            jwt_keys_loaded = bool(private_key and public_key)
        except Exception:
            jwt_keys_loaded = False
            
        return jsonify({
            "secrets_status": "loaded",
            "aes_key_loaded": bool(aes_key),
            "aes_iv_loaded": bool(aes_iv),
            "repository_secrets": {
                "host": bool(repo_host),
                "port": bool(repo_port),
                "name": bool(repo_name), 
                "user": bool(repo_user),
                "password_decrypted": bool(decrypted_password)
            },
            "jwt_keys_loaded": jwt_keys_loaded,
            "database_config": {
                "host": str(repo_host) if repo_host else None,
                "port": str(repo_port) if repo_port else None,
                "name": str(repo_name) if repo_name else None,
                "user": str(repo_user) if repo_user else None,
                "password_length": len(str(decrypted_password)) if decrypted_password else 0
            }
        })
    except Exception as e:
        return jsonify({"error": str(e), "secrets_status": "failed"}), 500


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Quart uses asyncio; this is fine for Python 3.11
    # Configure with longer startup timeout to handle database initialization
    import hypercorn.config
    config = hypercorn.config.Config()
    config.bind = ["0.0.0.0:7000"]
    config.startup_timeout = 60  # Increase startup timeout to 60 seconds
    
    # Run with custom config to handle startup timeout
    try:
        app.run(host="0.0.0.0", port=7000, debug=False)
    except Exception as e:
        logger(f"Application failed to start: {e}", "critical", "worker_scope")
        sys.exit(1)
