#!/usr/bin/env bash
# Installs or updates the panel on the server with Docker. Run it from the repository root.
#   deploy/install.sh            first install, or update (after git pull)
set -euo pipefail
cd "$(dirname "$0")/.."

say() { echo "==> $*"; }
docker compose version >/dev/null 2>&1 || { echo "Docker with the compose plugin is required"; exit 1; }

# A variable from the environment, else from this folder's .env (Compose reads that file for
# ${...} in compose.yaml too), else the default.
setting() {
  local name=$1 default=$2 value=${!1:-}
  if [[ -z $value && -r .env ]]; then
    value=$(sed -n "s/^[[:space:]]*\(export[[:space:]]\{1,\}\)\{0,1\}$name[[:space:]]*=[[:space:]]*//p" .env | tail -n 1 \
            | sed "s/[[:space:]]#.*$//; s/^[\"']//; s/[\"'][[:space:]]*$//")
  fi
  echo "${value:-$default}"
}

# Settings and master key: .env in the repository folder, unless MULTICDN_ENV_FILE points elsewhere.
ENV_FILE=$(setting MULTICDN_ENV_FILE .env)
# The panel's secrets (the values it manages): config/secrets.env, unless MULTICDN_SECRETS_DIR.
SECRETS_DIR=$(setting MULTICDN_SECRETS_DIR config)
SECRETS_FILE="${SECRETS_DIR%/}/secrets.env"
ME="$(id -u):$(id -g)"

if [[ ! -f $ENV_FILE ]]; then
  say "Creating $ENV_FILE with a new master key"
  key=$(openssl rand -base64 32 | tr '+/' '-_')
  mkdir -p "$(dirname "$ENV_FILE")"
  (umask 077; sed "s|^MULTICDN_SECRET_KEY=.*|MULTICDN_SECRET_KEY=$key|" .env.example > "$ENV_FILE")
  echo "    Save this key outside the server too (password manager): without it, nothing can be restored."
  echo "    MULTICDN_SECRET_KEY=$key"
  echo "    Edit $ENV_FILE (ORIGIN_VPS1_IPV4, MULTICDN_ACME_EMAIL) and run this script again."
  exit 0
fi
[[ -r $ENV_FILE ]] || { echo "Cannot read $ENV_FILE: make it yours (sudo chown $(id -u):$(id -g) $ENV_FILE) and run this again."; exit 1; }
grep -q '^MULTICDN_SECRET_KEY=.\+' "$ENV_FILE" || { echo "MULTICDN_SECRET_KEY is empty in $ENV_FILE"; exit 1; }
if [[ -f data/.secret_key ]]; then
  echo "There is a key in data/.secret_key: move it to MULTICDN_SECRET_KEY in $ENV_FILE and delete it from data/ (one source for the key)."
  exit 1
fi

# The container runs as you (compose.yaml: user MULTICDN_UID:MULTICDN_GID), so data/ and config/
# are yours. As root it would run as root: then it keeps the image's own user, uid 10001.
if [[ $(id -u) -eq 0 ]]; then
  RUN_UID=10001 RUN_GID=10001
  echo "    Running as root: the container keeps its own user (uid 10001). Prefer a normal user with docker access."
else
  RUN_UID=$(id -u) RUN_GID=$(id -g)
fi
# Compose reads ${MULTICDN_UID} from ./.env (next to compose.yaml).
set_project_var() {
  local name=$1 value=$2 file=.env
  [[ -e $file ]] || (umask 077; : > "$file")
  if grep -qE "^[[:space:]]*$name=" "$file"; then
    [[ $(grep -E "^[[:space:]]*$name=" "$file" | tail -n 1 | cut -d= -f2-) == "$value" ]] && return 0
    local tmp; tmp=$(mktemp "$file.XXXXXX")
    awk -v k="$name" -v v="$value" 'BEGIN{FS=OFS="="} $0 ~ "^[[:space:]]*"k"=" {print k"="v; next} {print}' "$file" > "$tmp"
    cat "$tmp" > "$file" && rm -f "$tmp"
  else
    printf '%s=%s\n' "$name" "$value" >> "$file"
  fi
}
set_project_var MULTICDN_UID "$RUN_UID"
set_project_var MULTICDN_GID "$RUN_GID"

say "Preparing data/ for the panel (owner uid $RUN_UID)"
mkdir -p data
if [[ $(stat -c %u data 2>/dev/null || stat -f %u data) != "$RUN_UID" ]] || find data ! -user "$RUN_UID" -print -quit 2>/dev/null | grep -q .; then
  sudo chown -R "$RUN_UID:$RUN_GID" data
fi
chmod 700 data 2>/dev/null || sudo chmod 700 data

say "Keeping $ENV_FILE private: the container only receives its values (env_file), it cannot change it"
if ! chmod 600 "$ENV_FILE" 2>/dev/null; then
  echo "    $ENV_FILE is not yours, so its permissions were not changed. Make sure only you can read it:"
  echo "    sudo chown $ME $ENV_FILE && chmod 600 $ENV_FILE"
fi
# 0.3.1 development builds let the container write .env: take that back.
if command -v setfacl >/dev/null 2>&1; then
  sudo setfacl -x u:10001 "$ENV_FILE" 2>/dev/null || true
fi

say "Preparing $SECRETS_DIR/ for the panel's secrets (the container may write only there)"
mkdir -p "$SECRETS_DIR"
[[ -e $SECRETS_FILE ]] || (umask 077; : > "$SECRETS_FILE")
if find "$SECRETS_DIR" ! -user "$RUN_UID" -print -quit 2>/dev/null | grep -q .; then
  sudo chown -R "$RUN_UID:$RUN_GID" "$SECRETS_DIR"
fi
chmod 700 "$SECRETS_DIR" 2>/dev/null || sudo chmod 700 "$SECRETS_DIR"
chmod 600 "$SECRETS_FILE" 2>/dev/null || sudo chmod 600 "$SECRETS_FILE"
# 0.3.1 gave the container user an ACL on config/: not needed any more.
if command -v setfacl >/dev/null 2>&1; then
  sudo setfacl -b "$SECRETS_DIR" "$SECRETS_FILE" 2>/dev/null || true
fi

say "Moving the panel-managed variables from $ENV_FILE to $SECRETS_FILE (if any are left there)"
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
  if ! python3 -m app.migrate_secrets "$ENV_FILE" "$SECRETS_FILE"; then
    echo "    They were not moved and nothing was changed; see deploy/README.md, \"Panel secrets file\"."
    exit 1
  fi
  [[ $(id -u) -eq 0 ]] && chown "$RUN_UID:$RUN_GID" "$SECRETS_FILE"
else
  echo "    python3 (3.9 or later) is not installed: move these lines from $ENV_FILE to $SECRETS_FILE by hand,"
  echo "    then run this script again:"
  grep -nE '^[[:space:]]*(export[[:space:]]+)?(TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|SMTP_URL|ALERT_EMAIL_TO|FOOTBALL_DATA_TOKEN|MULTICDN_HEARTBEAT_URL|MULTICDN_SENTRY_DSN|CLOUDFLARE_API_TOKEN|GCORE_API_TOKEN)[[:space:]]*=' "$ENV_FILE" \
    | cut -d= -f1 | sed 's/^/      line /' || echo "      (none)"
fi

say "Building and starting"
docker compose up -d --build

say "Waiting for the panel to answer"
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8765/healthz >/dev/null 2>&1; then
    say "Panel running on 127.0.0.1:8765"
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1:8765/healthz >/dev/null || { docker compose logs --tail 50 panel; exit 1; }

cat <<'TXT'

Next steps (first time only), see deploy/README.md:
  2. Create your user:    docker compose exec panel python -m app.cli create-user <user>
  3. Open the panel (it only listens on 127.0.0.1:8765), from your computer:
       ssh -N -L 8765:127.0.0.1:8765 <user>@<server>   and open http://localhost:8765
  4. Continue in the panel: Settings → Provider accounts.
To update later: git pull && deploy/install.sh
TXT
