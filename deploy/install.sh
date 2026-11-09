#!/usr/bin/env bash
# Installs or updates the panel on the server with Docker. Run it from the repository root.
#   deploy/install.sh            first install, or update (after git pull)
set -euo pipefail
cd "$(dirname "$0")/.."

say() { echo "==> $*"; }
docker compose version >/dev/null 2>&1 || { echo "Docker with the compose plugin is required"; exit 1; }

# Settings and master key: .env in the repository folder, unless MULTICDN_ENV_FILE points elsewhere.
ENV_FILE=${MULTICDN_ENV_FILE:-.env}
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
grep -q '^MULTICDN_SECRET_KEY=.\+' "$ENV_FILE" || { echo "MULTICDN_SECRET_KEY is empty in $ENV_FILE"; exit 1; }
if [[ -f data/.secret_key ]]; then
  echo "There is a key in data/.secret_key: move it to MULTICDN_SECRET_KEY in $ENV_FILE and delete it from data/ (one source for the key)."
  exit 1
fi

say "Preparing data/ for the container user (uid 10001)"
mkdir -p data
sudo chown -R 10001:10001 data
sudo chmod 700 data

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
  4. Continue in the panel: Settings → Accounts.
To update later: git pull && deploy/install.sh
TXT
