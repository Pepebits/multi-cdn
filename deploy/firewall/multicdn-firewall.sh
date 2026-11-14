#!/usr/bin/env bash
# Firewall del origen y proxies de confianza de Caddy, con una sola lista de rangos.
#
#  - nftables: los puertos web del VPS (80/443, TCP y UDP/QUIC) solo aceptan conexiones
#    desde los CDN (Cloudflare, Gcore y, opcionalmente, Fastly). Solo afecta al tráfico
#    dirigido al propio VPS: las conexiones salientes de los contenedores no se tocan.
#    SSH, Tailscale y el resto de puertos tampoco.
#  - Caddy: escribe los mismos rangos como trusted_proxies para que la IP real del cliente
#    se lea de X-Forwarded-For (deploy/caddy/README en deploy/README.md).
#  - Estado: deja un JSON con el resultado que el panel muestra y vigila.
#
# Uso (como root):
#   multicdn-firewall.sh apply         descarga, valida y aplica (nftables + Caddy + estado)
#   multicdn-firewall.sh print         muestra las reglas nftables que aplicaría
#   multicdn-firewall.sh print-caddy   muestra el fichero de rangos para Caddy
#   multicdn-firewall.sh status        reglas cargadas y contadores
#   multicdn-firewall.sh remove        quita la tabla (vuelve a dejar los puertos abiertos)
#
# Configuración opcional en /etc/multicdn/firewall.env (ver firewall.env.example).
set -euo pipefail
export LC_ALL=C  # mismo orden en sort y comm

CONFIG=${MULTICDN_FIREWALL_CONFIG:-/etc/multicdn/firewall.env}
[[ -f $CONFIG ]] && source "$CONFIG"

PORTS=${PORTS:-"80, 443"}
ALLOW_INTERFACES=${ALLOW_INTERFACES:-'"lo", "tailscale0"'}
EXTRA_ALLOW_V4=${EXTRA_ALLOW_V4:-}
EXTRA_ALLOW_V6=${EXTRA_ALLOW_V6:-}
INCLUDE_FASTLY=${INCLUDE_FASTLY:-0}
STATE_DIR=${STATE_DIR:-/var/lib/multicdn-firewall}
MIN_RATIO=${MIN_RATIO:-50}
CADDY_RANGES=${CADDY_RANGES:-/etc/caddy/cdn-ranges.caddy}   # vacío: no tocar Caddy
CADDYFILE=${CADDYFILE:-/etc/caddy/Caddyfile}
CADDY_ENVFILE=${CADDY_ENVFILE:-/etc/caddy/caddy.env}
CADDY_RELOAD=${CADDY_RELOAD:-1}
PANEL_DATA=${PANEL_DATA:-}                                   # p. ej. /var/www/multi-cdn/data
CF_V4_URL=${CF_V4_URL:-https://www.cloudflare.com/ips-v4}
CF_V6_URL=${CF_V6_URL:-https://www.cloudflare.com/ips-v6}
GCORE_URL=${GCORE_URL:-https://api.gcore.com/cdn/public-ip-list}
FASTLY_URL=${FASTLY_URL:-https://api.fastly.com/public-ip-list}
TABLE=multicdn
PRIVATE_V4="127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10"
PRIVATE_V6="::1/128, fc00::/7, fe80::/10"

log() { echo "multicdn-firewall: $*" >&2; }

STATUS_ERROR=""
die() {
  log "$*"
  STATUS_ERROR="$*"
  write_status || true
  exit 1
}

# Tras un reinicio la tabla no persiste: si apply falla antes de cargar las reglas nuevas (descarga
# o comprobaciones), se cargan las últimas buenas para no dejar 80/443 abiertos hasta la próxima
# ejecución. Si la tabla ya está cargada no se toca: siguen valiendo las reglas actuales.
restore_previous() {
  [[ $EUID -eq 0 || ${MULTICDN_FIREWALL_TEST:-0} == 1 ]] || return 1
  nft list table inet $TABLE >/dev/null 2>&1 && return 1
  if [[ ! -s $STATE_DIR/rules.nft ]]; then
    log "no hay reglas anteriores que restaurar: los puertos web siguen abiertos"
    return 1
  fi
  if nft -c -f "$STATE_DIR/rules.nft" && nft -f "$STATE_DIR/rules.nft"; then
    log "restauradas las reglas anteriores ($STATE_DIR/rules.nft, lista del $(cat "$STATE_DIR/last_ok" 2>/dev/null || echo '?'))"
    return 0
  fi
  log "las reglas anteriores no validan: los puertos web siguen abiertos"
  return 1
}

# Ficheros en la carpeta de datos del panel: el contenedor (otro usuario) puede escribir en ella
# y dejar enlaces simbólicos para que root sobrescriba ficheros del host. Se escribe en un fichero
# nuevo con nombre aleatorio creado con O_EXCL (noclobber: nunca sigue un enlace) y ya con 644
# (umask, sin chmod), y se renombra encima del destino: rename sustituye un enlace, no lo sigue.
panel_write() {  # panel_write NOMBRE < contenido
  local dest="$PANEL_DATA/$1" tmpf
  tmpf=$(mktemp -u "$PANEL_DATA/.$1.XXXXXXXXXX") || return 1
  if ! (set -C; umask 022; cat > "$tmpf"); then
    log "no se pudo escribir $dest"
    return 1
  fi
  if [[ -d $dest && ! -L $dest ]]; then
    rm -f "$tmpf"; log "$dest es una carpeta: no se actualiza"; return 1
  fi
  mv -f "$tmpf" "$dest" || { rm -f "$tmpf"; log "no se pudo actualizar $dest"; return 1; }
}
need() { command -v "$1" >/dev/null || die "falta el comando $1"; }
fetch() { curl -fsS --retry 3 --max-time 30 "$1"; }

valid_v4() { grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$' || true; }
valid_v6() { grep -E '^[0-9a-fA-F:]+:[0-9a-fA-F:]*(/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?$' || true; }

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n'; }

# Estado para el panel: cuándo se aplicó la última lista buena, cuántos rangos y el último error.
write_status() {
  [[ -n $PANEL_DATA || $EUID -eq 0 || ${MULTICDN_FIREWALL_TEST:-0} == 1 ]] || return 0
  mkdir -p "$STATE_DIR" 2>/dev/null || return 0
  local last_ok="" v4=0 v6=0 caddy="${CADDY_STATE:-}" added="${ADDED:-0}" removed="${REMOVED:-0}"
  [[ -f $STATE_DIR/last_ok ]] && last_ok=$(cat "$STATE_DIR/last_ok")
  [[ -f $STATE_DIR/all4 ]] && v4=$(wc -l < "$STATE_DIR/all4" | tr -d ' ')
  [[ -f $STATE_DIR/all6 ]] && v6=$(wc -l < "$STATE_DIR/all6" | tr -d ' ')
  local json
  json=$(printf '{"checked_at": "%s", "last_ok": "%s", "ipv4": %s, "ipv6": %s, "added": %s, "removed": %s, "caddy": "%s", "error": "%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$last_ok" "$v4" "$v6" "$added" "$removed" "$(json_escape "$caddy")" "$(json_escape "$STATUS_ERROR")")
  echo "$json" > "$STATE_DIR/status.json"
  if [[ -n $PANEL_DATA && -d $PANEL_DATA ]]; then
    echo "$json" | panel_write firewall-status.json || true
  fi
}

download() {
  local tmp=$1
  fetch "$CF_V4_URL" | valid_v4 > "$tmp/cf4" || die "no se pudo descargar la lista IPv4 de Cloudflare"
  fetch "$CF_V6_URL" | valid_v6 > "$tmp/cf6" || die "no se pudo descargar la lista IPv6 de Cloudflare"
  fetch "$GCORE_URL" > "$tmp/gcore.json" || die "no se pudo descargar la lista de Gcore"
  jq -r '.addresses[]' "$tmp/gcore.json" | valid_v4 > "$tmp/gc4"
  jq -r '.addresses_v6[]' "$tmp/gcore.json" | valid_v6 > "$tmp/gc6"
  : > "$tmp/fa4"; : > "$tmp/fa6"
  if [[ $INCLUDE_FASTLY == 1 ]]; then
    fetch "$FASTLY_URL" > "$tmp/fastly.json" || die "no se pudo descargar la lista de Fastly"
    jq -r '.addresses[]' "$tmp/fastly.json" | valid_v4 > "$tmp/fa4"
    jq -r '.ipv6_addresses[]' "$tmp/fastly.json" | valid_v6 > "$tmp/fa6"
  fi
  for f in cf4 cf6 gc4 gc6; do
    [[ -s $tmp/$f ]] || die "la lista $f ha llegado vacía: se mantienen las reglas actuales"
  done
  for x in $EXTRA_ALLOW_V4; do echo "$x"; done | valid_v4 > "$tmp/ex4"
  for x in $EXTRA_ALLOW_V6; do echo "$x"; done | valid_v6 > "$tmp/ex6"
  sort -u "$tmp/cf4" "$tmp/gc4" "$tmp/fa4" "$tmp/ex4" > "$tmp/all4"
  sort -u "$tmp/cf6" "$tmp/gc6" "$tmp/fa6" "$tmp/ex6" > "$tmp/all6"
  # Para Caddy solo los CDN (las IPs extra no son proxies).
  sort -u "$tmp/cf4" "$tmp/gc4" "$tmp/fa4" "$tmp/cf6" "$tmp/gc6" "$tmp/fa6" > "$tmp/proxies"
}

# Una lista que encoge de golpe (respuesta parcial, cambio de formato) no se aplica.
sanity() {
  local tmp=$1 f old new
  for f in all4 all6; do
    [[ -f $STATE_DIR/$f ]] || continue
    old=$(wc -l < "$STATE_DIR/$f"); new=$(wc -l < "$tmp/$f")
    if (( old > 0 && new * 100 < old * MIN_RATIO )); then
      die "la lista $f ha bajado de $old a $new entradas (< $MIN_RATIO %): se mantienen las reglas actuales"
    fi
  done
}

elements() { paste -sd, "$1" | sed 's/,/, /g'; }

ruleset() {
  local tmp=$1
  cat <<NFT
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
  set cdn4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { $(elements "$tmp/all4") }
  }
  set cdn6 {
    type ipv6_addr
    flags interval
    auto-merge
    elements = { $(elements "$tmp/all6") }
  }
  chain ingress {
    type filter hook prerouting priority -150; policy accept;
    # Solo el tráfico dirigido al propio VPS: lo que reenvía (contenedores hacia fuera) no se toca.
    fib daddr type != local accept
    iifname { $ALLOW_INTERFACES } accept
    ip saddr { $PRIVATE_V4 } accept
    ip6 saddr { $PRIVATE_V6 } accept
    meta l4proto { tcp, udp } th dport { $PORTS } ip saddr @cdn4 accept
    meta l4proto { tcp, udp } th dport { $PORTS } ip6 saddr @cdn6 accept
    meta l4proto { tcp, udp } th dport { $PORTS } ct state new counter drop comment "web directo sin CDN"
  }
}
NFT
}

caddy_ranges() {
  local tmp=$1
  echo "# Generado por multicdn-firewall.sh: no editar a mano. Rangos de los CDN (proxies de confianza)."
  echo "trusted_proxies static $(paste -sd' ' "$tmp/proxies")"
}

# Actualiza el fichero de rangos de Caddy y recarga solo si cambia y la configuración valida.
apply_caddy() {
  local tmp=$1
  [[ -n $CADDY_RANGES ]] || { CADDY_STATE="desactivado"; return 0; }
  caddy_ranges "$tmp" > "$tmp/caddy"
  if [[ -f $CADDY_RANGES ]] && cmp -s "$tmp/caddy" "$CADDY_RANGES"; then
    CADDY_STATE="sin cambios"; return 0
  fi
  local backup=""
  if [[ -f $CADDY_RANGES ]]; then backup="$tmp/caddy.prev"; cp "$CADDY_RANGES" "$backup"; fi
  install -m 644 "$tmp/caddy" "$CADDY_RANGES"
  if ! grep -q "$(basename "$CADDY_RANGES")" "$CADDYFILE" 2>/dev/null; then
    CADDY_STATE="fichero escrito; el Caddyfile aún no lo importa"; return 0
  fi
  local envflag=()
  [[ -f $CADDY_ENVFILE ]] && envflag=(--envfile "$CADDY_ENVFILE")
  if ! caddy validate --config "$CADDYFILE" ${envflag[@]+"${envflag[@]}"} >"$tmp/validate.log" 2>&1; then
    if [[ -n $backup ]]; then install -m 644 "$backup" "$CADDY_RANGES"; else rm -f "$CADDY_RANGES"; fi
    CADDY_STATE="validación fallida: se mantiene el fichero anterior"
    die "Caddy no valida con los rangos nuevos: $(tail -n 3 "$tmp/validate.log" | tr '\n' ' ')"
  fi
  if [[ $CADDY_RELOAD == 1 ]]; then
    systemctl reload caddy || die "no se pudo recargar Caddy"
    CADDY_STATE="actualizado y recargado"
  else
    CADDY_STATE="actualizado (sin recargar)"
  fi
}

cmd=${1:-}
case $cmd in
  apply|print|print-caddy)
    # La petición del panel se atiende ya: si se borrara al final y algo fallara, la unidad
    # .path relanzaría el servicio una y otra vez.
    [[ $cmd == apply && -n $PANEL_DATA ]] && rm -f "$PANEL_DATA/firewall-refresh-request"
    need curl; need jq
    [[ $cmd == apply ]] && need nft
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    if [[ $cmd == apply ]]; then
      # Cualquier salida con error antes de cargar las reglas nuevas (die o set -e) intenta
      # restaurar las anteriores si la tabla no está cargada (p. ej. descarga fallida al arrancar).
      trap 'rc=$?
        if (( rc != 0 )) && restore_previous; then
          STATUS_ERROR="${STATUS_ERROR:-fallo inesperado (código $rc)} · restauradas las reglas anteriores"
          write_status || true
        fi
        rm -rf "$tmp"' EXIT
    fi
    download "$tmp"
    [[ $cmd == apply ]] && sanity "$tmp"
    ruleset "$tmp" > "$tmp/rules.nft"
    if [[ $cmd == print ]]; then cat "$tmp/rules.nft"; exit 0; fi
    if [[ $cmd == print-caddy ]]; then caddy_ranges "$tmp"; exit 0; fi
    [[ $EUID -eq 0 || ${MULTICDN_FIREWALL_TEST:-0} == 1 ]] || die "ejecuta apply como root"
    # Cuántos rangos entran y salen respecto a la última lista buena: con el tiempo dice cada
    # cuánto cambian de verdad (registro en changes.log y, si hay panel, firewall-changes.log).
    cat "$tmp/all4" "$tmp/all6" | sort -u > "$tmp/all"
    if [[ -f $STATE_DIR/all4 ]]; then
      cat "$STATE_DIR/all4" "$STATE_DIR/all6" 2>/dev/null | sort -u > "$tmp/prev"
      ADDED=$(comm -13 "$tmp/prev" "$tmp/all" | wc -l | tr -d ' ')
      REMOVED=$(comm -23 "$tmp/prev" "$tmp/all" | wc -l | tr -d ' ')
    else
      ADDED=$(wc -l < "$tmp/all" | tr -d ' '); REMOVED=0
    fi
    nft -c -f "$tmp/rules.nft" || die "las reglas no validan: no se ha cambiado nada"
    nft -f "$tmp/rules.nft"   # carga atómica: o todo o nada
    trap 'rm -rf "$tmp"' EXIT  # reglas nuevas cargadas: un fallo posterior (Caddy) no las cambia
    mkdir -p "$STATE_DIR"
    cp "$tmp/all4" "$tmp/all6" "$tmp/rules.nft" "$STATE_DIR/"
    date -u +%Y-%m-%dT%H:%M:%SZ > "$STATE_DIR/last_ok"
    line="$(cat "$STATE_DIR/last_ok") +$ADDED -$REMOVED"
    echo "$line" >> "$STATE_DIR/changes.log"
    if [[ -n $PANEL_DATA && -d $PANEL_DATA ]]; then
      # Copia del registro de root (no se añade al del panel: podría ser un enlace).
      tail -n 1000 "$STATE_DIR/changes.log" | panel_write firewall-changes.log || true
    fi
    apply_caddy "$tmp"
    write_status
    log "aplicado: $(wc -l < "$tmp/all4") rangos IPv4 y $(wc -l < "$tmp/all6") IPv6 (Cloudflare $(wc -l < "$tmp/cf4")+$(wc -l < "$tmp/cf6"), Gcore $(wc -l < "$tmp/gc4")+$(wc -l < "$tmp/gc6")) · Caddy: ${CADDY_STATE:-—}"
    ;;
  status)
    nft list chain inet $TABLE ingress 2>/dev/null || { echo "sin reglas cargadas"; exit 1; }
    [[ -f $STATE_DIR/status.json ]] && cat "$STATE_DIR/status.json"
    ;;
  remove)
    nft delete table inet $TABLE 2>/dev/null && log "reglas quitadas: los puertos web vuelven a estar abiertos" || log "no había reglas"
    ;;
  *)
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
