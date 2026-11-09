#!/usr/bin/env bash
# Instala o actualiza el panel en el VPS con Docker. Ejecútalo desde la raíz del repo.
#   deploy/install.sh            primera instalación o actualización (git pull antes)
set -euo pipefail
cd "$(dirname "$0")/.."

say() { echo "==> $*"; }
docker compose version >/dev/null 2>&1 || { echo "Falta Docker con el plugin compose"; exit 1; }

# Configuración y clave maestra: .env en la carpeta del repo, salvo que MULTICDN_ENV_FILE indique otra ruta.
ENV_FILE=${MULTICDN_ENV_FILE:-.env}
if [[ ! -f $ENV_FILE ]]; then
  say "Creando $ENV_FILE con una clave maestra nueva"
  key=$(openssl rand -base64 32 | tr '+/' '-_')
  mkdir -p "$(dirname "$ENV_FILE")"
  (umask 077; sed "s|^MULTICDN_SECRET_KEY=.*|MULTICDN_SECRET_KEY=$key|" .env.example > "$ENV_FILE")
  echo "    Guarda esta clave también fuera del VPS (gestor de contraseñas): sin ella no se puede restaurar."
  echo "    MULTICDN_SECRET_KEY=$key"
  echo "    Revisa $ENV_FILE (ORIGIN_VPS1_IPV4, MULTICDN_ACME_EMAIL) y vuelve a ejecutar este script."
  exit 0
fi
grep -q '^MULTICDN_SECRET_KEY=.\+' "$ENV_FILE" || { echo "MULTICDN_SECRET_KEY está vacía en $ENV_FILE"; exit 1; }
if [[ -f data/.secret_key ]]; then
  echo "Hay una clave en data/.secret_key: pásala a MULTICDN_SECRET_KEY en $ENV_FILE y bórrala de data/ (una sola fuente de la clave)."
  exit 1
fi

say "Preparando data/ para el usuario del contenedor (uid 10001)"
mkdir -p data
sudo chown -R 10001:10001 data
sudo chmod 700 data

say "Construyendo y arrancando"
docker compose up -d --build

say "Esperando a que el panel responda"
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8765/healthz >/dev/null 2>&1; then
    say "Panel en marcha en 127.0.0.1:8765"
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1:8765/healthz >/dev/null || { docker compose logs --tail 50 panel; exit 1; }

cat <<'TXT'

Siguientes pasos (solo la primera vez):
  1. Usuario del panel:   docker compose exec panel python -m app.cli crear-usuario <usuario>
  2. Acceso (el panel solo escucha en 127.0.0.1:8765; ver «Acceso al panel» en deploy/README.md):
       túnel SSH desde tu máquina:  ssh -N -L 8765:127.0.0.1:8765 <usuario>@<IP del VPS>
                                    y abre http://localhost:8765
       o Tailscale en el VPS:       sudo tailscale serve --bg 8765
  3. Entra y configura el TOTP.
Para actualizar más adelante: git pull && deploy/install.sh
TXT
