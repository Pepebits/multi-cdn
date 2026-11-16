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

say "Preparing data/ for the container user (uid 10001)"
mkdir -p data
sudo chown -R 10001:10001 data
sudo chmod 700 data

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
# The panel reads its secrets only from this file (it is not an env_file), so the container
# user must be able to read it BEFORE any value is moved here.
# macOS (Docker Desktop) shares files with the container whatever their owner: no ACL needed.
NEED_ACL=1
[[ $(uname -s) == Darwin ]] && NEED_ACL=0
if (( NEED_ACL )) && ! command -v setfacl >/dev/null 2>&1; then
  echo "    setfacl is not installed. Without it the panel could not read $SECRETS_FILE."
  if command -v apt-get >/dev/null 2>&1; then echo "    Install it with: sudo apt install acl"
  elif command -v dnf >/dev/null 2>&1; then echo "    Install it with: sudo dnf install acl"
  elif command -v yum >/dev/null 2>&1; then echo "    Install it with: sudo yum install acl"
  elif command -v apk >/dev/null 2>&1; then echo "    Install it with: sudo apk add acl"
  elif command -v pacman >/dev/null 2>&1; then echo "    Install it with: sudo pacman -S acl"
  elif command -v zypper >/dev/null 2>&1; then echo "    Install it with: sudo zypper install acl"
  else echo "    Install your system's acl package (it provides setfacl)."
  fi
  echo "    Nothing was changed: install it and run this script again."
  exit 1
fi
acl() { if (( NEED_ACL )); then sudo setfacl "$@"; fi; }
mkdir -p "$SECRETS_DIR"
[[ -e $SECRETS_FILE ]] || (umask 077; : > "$SECRETS_FILE")
# The panel replaces the file when it saves (so its owner becomes uid 10001): yours again.
if (( NEED_ACL )); then sudo chown "$ME" "$SECRETS_DIR" "$SECRETS_FILE"; fi
# Owner-only for everyone else; the folder and the file (and files created there later, by the
# panel or by an editor that saves with a rename) give access to uid 10001 and to you via ACL.
# chmod first: it resets the ACL mask, which setfacl then sets again.
chmod 700 "$SECRETS_DIR" && chmod 600 "$SECRETS_FILE"
acl -m "u:10001:rwx,u:$(id -u):rwx,d:u:10001:rw,d:u:$(id -u):rw" "$SECRETS_DIR"
acl -m "u:10001:rw,u:$(id -u):rw" "$SECRETS_FILE"

say "Moving the panel-managed variables from $ENV_FILE to $SECRETS_FILE (if any are left there)"
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
  if ! python3 -m app.migrate_secrets "$ENV_FILE" "$SECRETS_FILE"; then
    echo "    They were not moved and nothing was changed; see deploy/README.md, \"Panel secrets file\"."
    exit 1
  fi
  # The migration rewrites the file: give it the ACL again.
  acl -m "u:10001:rw,u:$(id -u):rw" "$SECRETS_FILE"
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
