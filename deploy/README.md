# Despliegue en el VPS

## Panel y controlador (Docker)

Requisitos: Docker con el plugin compose.

```bash
cd /var/www && git clone <repo> multi-cdn && cd multi-cdn   # o la carpeta que prefieras
deploy/install.sh          # la primera vez crea .env (600) con una clave maestra nueva y se para
nano .env                  # ORIGIN_VPS1_IPV4, MULTICDN_ACME_EMAIL; deja MULTICDN_DRY_RUN=true de momento
deploy/install.sh          # construye la imagen y arranca
docker compose exec panel python -m app.cli crear-usuario <usuario>
```

- El contenedor corre con un usuario sin privilegios, sistema de ficheros de solo lectura y sin
  capacidades. Escribe solo en `data/` (base de datos, certificados de Gcore, copias) y `/tmp`.
- El puerto 8765 solo escucha en `127.0.0.1` del VPS: no se publica en Internet ni pasa por Caddy
  ni por ningún CDN. Cómo llegar a él, en *Acceso al panel*.
- Copias: el panel hace una al día en `data/backups/` y guarda las 14 últimas
  (`docker compose exec panel python -m app.cli copia-seguridad` para una manual). Llévalas fuera
  del VPS si quieres sobrevivir a la pérdida del servidor; sin `MULTICDN_SECRET_KEY` no se pueden
  leer las credenciales que contienen.
- **Configuración y clave maestra en `.env`** de la carpeta del repo (permisos 600). Si prefieres
  guardarlas en otra ruta (p. ej. para que tus copias de la carpeta no lleven la clave), define
  `MULTICDN_ENV_FILE=/ruta/que/quieras` en el entorno o en ese mismo `.env`; `install.sh` y
  `docker compose` la usan. Guarda la clave también en tu gestor de contraseñas: sin ella no se
  pueden leer las credenciales de una copia.
- Cambios reales: cuando lo hayas revisado, `MULTICDN_DRY_RUN=false` en ese fichero y `docker compose up -d`.
- Actualizar: `git pull && deploy/install.sh`.

## Acceso al panel

El panel tiene que seguir accesible **durante un bloqueo de LaLiga**, que es cuando más falta
puede hacer. Por eso no se publica en un hostname de Cloudflare: se llega por la IP del VPS,
que no está en las listas de bloqueo, a través de un canal cifrado y autenticado. Además del
canal, el panel pide su propio usuario, contraseña y TOTP.

### Opción 1 (por defecto): túnel SSH

No hay que instalar nada: usa el SSH que ya tienes.

```bash
ssh -N -L 8765:127.0.0.1:8765 <usuario>@<IP del VPS>
# y abre http://localhost:8765
```

Para no escribirlo cada vez, en `~/.ssh/config` de tu máquina:

```
Host multicdn
    HostName <IP del VPS>
    User <usuario>
    LocalForward 8765 127.0.0.1:8765
    ExitOnForwardFailure yes
```

y después `ssh -N multicdn`. Desde el móvil sirve cualquier cliente SSH con reenvío de puertos
(p. ej. Termius). La conexión va directa al VPS: no pasa por Cloudflare ni por ningún tercero.

**Que se reconecte solo (autossh).** Un túnel `ssh -N` se cae cuando la red cambia o el equipo
se duerme. `autossh` lo vuelve a levantar:

```bash
brew install autossh            # macOS; en Linux: apt install autossh
autossh -M 0 -N multicdn        # con la entrada de ~/.ssh/config de arriba
```

`-M 0` desactiva el puerto de control de autossh y deja que sea SSH quien detecte la conexión
caída; para eso añade a la entrada `multicdn` de `~/.ssh/config`:

```
    ServerAliveInterval 30
    ServerAliveCountMax 3
```

Si el puerto local ya está ocupado (`bind [127.0.0.1]:8765: Address already in use`), hay otro
túnel o un panel local escuchando: ciérralo o usa otro puerto local (`-L 8766:127.0.0.1:8765`).

### Opción 2: Tailscale (o similar)

Más cómodo desde el móvil y permite cerrar SSH al público. El tráfico va directo entre tus
dispositivos y el VPS (WireGuard); el servidor de Tailscale solo autentica y reparte claves.

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up                  # abre el enlace que imprime e inicia sesión con tu cuenta
sudo ufw allow in on tailscale0    # ufw deniega por defecto lo entrante
sudo tailscale serve --bg 8765     # https://<nombre-del-vps>.<tu-tailnet>.ts.net con certificado
```

Instala Tailscale también en el Mac y el móvil con la misma cuenta. El firewall del origen ya
deja pasar la interfaz `tailscale0`. Anota el nombre del VPS en *Ajustes → Servidores*.

Cerrar SSH al público (opcional, cuando el acceso por Tailscale funcione): comprueba antes
`ssh <usuario>@<nombre-del-vps>` por la tailnet y ten a mano la consola web de tu proveedor del VPS como acceso
de emergencia; después `sudo ufw allow in on tailscale0 to any port 22` y `sudo ufw delete allow 22/tcp`.

Alternativas equivalentes: WireGuard propio, Headscale o NetBird autoalojados (sin depender de
un tercero, a cambio de gestionar las claves).

### Cloudflare Zero Trust: solo como acceso adicional

Cloudflare Access + Tunnel es gratuito y cómodo, pero el panel quedaría detrás de las IPs de
Cloudflare, que son las que se bloquean durante los partidos: justo entonces no podrías entrar.
Si lo usas, que sea además de una de las opciones anteriores, nunca la única.

### Pasar el panel que ya usas en local

1. Para el panel local (las dos copias no deben funcionar a la vez: las dos tomarían decisiones
   y enviarían avisos).
2. Copia una instantánea consistente de la base de datos y los certificados de Gcore:

   ```bash
   python3 -c "import sqlite3; s=sqlite3.connect('data/multicdn.db'); d=sqlite3.connect('/tmp/multicdn.db'); s.backup(d)"
   scp /tmp/multicdn.db <usuario>@<IP del VPS>:/var/www/multi-cdn/data/
   scp -r data/certbot <usuario>@<IP del VPS>:/var/www/multi-cdn/data/
   ```

3. Los ficheros de renovación de certbot guardan rutas absolutas de la máquina de origen; en el
   VPS deben apuntar a las del contenedor:

   ```bash
   sed -i "s|<ruta local del repo>/data/certbot|/app/data/certbot|g" /var/www/multi-cdn/data/certbot/config/renewal/*.conf
   ```

4. La clave maestra (`data/.secret_key` en local, o `MULTICDN_SECRET_KEY`) va en
   `MULTICDN_SECRET_KEY` del `.env` del VPS (o del fichero que indique `MULTICDN_ENV_FILE`),
   no en `data/`.

Después ejecuta `deploy/install.sh` en el VPS. Las sesiones abiertas siguen valiendo.

## Si el panel no está disponible

**Cambiar un dominio desde la terminal** (mismo código y salvaguardas que el panel; queda en el
historial, avisa por Telegram/email y pausa 1 h el automático de ese dominio):

```bash
cd /var/www/multi-cdn
docker compose exec panel python -m app.cli estado                         # dónde se sirve cada dominio
docker compose exec panel python -m app.cli cambiar example.com gcore      # pide escribir el dominio
docker compose exec panel python -m app.cli cambiar example.com cloudflare
# con el contenedor parado o colgado:
docker compose run --rm panel python -m app.cli cambiar example.com gcore
```

Antes de pasar a Gcore comprueba que sirve el dominio en todos sus bordes; si falla, no cambia
salvo con `--forzar`. `--si` omite la confirmación.

**Enterarte de que se ha caído:** crea un chequeo en healthchecks.io (periodo 5 min, margen
10 min) y pega su URL de ping en *Ajustes → Notificaciones → Aviso si el panel deja de funcionar*.
El panel la llama cada 5 min si sus tareas siguen vivas y `<URL>/fail` con el motivo si alguna se
para; si el panel o el VPS caen, deja de llamar y healthchecks.io te avisa.

# Protección del origen

Objetivo: que el VPS solo responda en los puertos web a los CDN, aunque alguien conozca su IP.
Dos capas independientes:

1. **Firewall (nftables):** 80/443 (TCP y UDP) solo desde los rangos publicados de Cloudflare
   y Gcore. SSH, Tailscale y el resto del tráfico no se tocan.
2. **Cabecera secreta en Caddy:** cada CDN añade `X-Origin-Auth` con su propio secreto y Caddy
   responde 403 a lo que no la traiga. Así otro cliente de Cloudflare o Gcore no puede usar
   su cuenta para llegar a tu origen saltándose el firewall.

Los hostnames servidos por Cloudflare Tunnel no usan los puertos públicos: no les afecta nada de esto.

## 1. Firewall y proxies de confianza de Caddy

Un solo script mantiene las dos cosas con la misma lista de rangos (Cloudflare + Gcore):

- **nftables:** 80/443 (TCP y UDP) solo desde los CDN, y solo para el tráfico dirigido al propio
  VPS. Las conexiones salientes de los contenedores, SSH, Tailscale, fail2ban y ufw no se tocan.
- **Caddy:** `trusted_proxies` con esos rangos, para que la IP real del cliente se lea de
  `X-Forwarded-For` (los dos CDN la añaden al final; en modo estricto no se puede falsificar).
- **Panel:** deja `firewall-status.json` en la carpeta de datos; el panel lo muestra en
  *Ajustes → Servidores* y avisa si una actualización falla o la lista pasa 48 h sin renovarse.

```bash
sudo install -m 755 deploy/firewall/multicdn-firewall.sh /usr/local/sbin/
sudo mkdir -p /etc/multicdn && sudo cp deploy/firewall/firewall.env.example /etc/multicdn/firewall.env
sudo nano /etc/multicdn/firewall.env        # PANEL_DATA = carpeta data/ del panel

sudo multicdn-firewall.sh print             # revisa las reglas
sudo multicdn-firewall.sh print-caddy       # y los rangos para Caddy
```

**Caddy primero** (todavía sin firewall): copia `deploy/caddy/real-ip.caddy` a `/etc/caddy/`,
añade al principio del Caddyfile las opciones globales que indica ese fichero, `import real_ip`
dentro de cada `reverse_proxy` y cambia `{http.request.header.CF-Connecting-IP}` por `{client_ip}`.
Después, para que exista el fichero de rangos:

```bash
sudo CADDY_RELOAD=0 multicdn-firewall.sh apply   # carga el firewall y escribe cdn-ranges.caddy
sudo caddy validate --config /etc/caddy/Caddyfile --envfile /etc/caddy/caddy.env
sudo systemctl reload caddy
sudo multicdn-firewall.sh status                 # el contador «web directo sin CDN» sube con cada intento bloqueado
```

Comprueba que las webs responden por Cloudflare y que en el log de Caddy `client_ip` ya no es
la IP del borde. Luego deja la actualización automática:

```bash
sudo install -m 644 deploy/firewall/multicdn-firewall.{service,timer} deploy/firewall/multicdn-firewall-refresh.path /etc/systemd/system/
sudo nano /etc/systemd/system/multicdn-firewall-refresh.path    # ruta de data/ si no es /var/www/multi-cdn
sudo systemctl daemon-reload
sudo systemctl enable --now multicdn-firewall.timer multicdn-firewall-refresh.path
```

- **Cada 24 h**, **justo antes de cada cambio a Gcore** y **cada hora mientras algún dominio se sirve por Gcore** (el panel crea `data/firewall-refresh-request`
  y la unidad `.path` lanza el script).
- La carga de nftables es atómica y se valida antes (`nft -c`). Si una descarga falla, llega vacía
  o encoge más de la mitad, se mantienen las reglas anteriores.
- Caddy solo se recarga si el fichero de rangos cambia y `caddy validate` pasa; si no valida,
  se restaura el anterior.
- Para deshacerlo: `sudo multicdn-firewall.sh remove`.

**Certificados de Caddy:** este VPS ya usa DNS-01 con Cloudflare en todos los sitios, así que el
firewall no afecta a las renovaciones.

## 2. Cabecera secreta

Cada CDN añade `X-Origin-Auth` con su propio secreto; Caddy rechaza (403) lo que no la traiga.
Así ni siquiera otra cuenta de Cloudflare o Gcore puede usar su CDN para llegar a tu origen.
Los secretos los genera y guarda (cifrados) el panel.

1. **Que no acaben en los logs.** Un log de Caddy en JSON guarda todas las cabeceras. En cada
   sitio con `log { ... format json }` cambia el formato por:

   ```
   format filter {
       request>headers>X-Origin-Auth hash
       wrap json
   }
   ```

   (`hash` guarda solo los 4 primeros bytes del SHA-256: se ve qué versión del secreto llegó,
   comparándola con la huella que muestra `secretos-origen`, sin exponer el valor.)

   Haz lo mismo con el log general de Caddy (journald), que incluye las cabeceras en avisos como
   «aborting with incomplete response»: en las opciones globales,

   ```
   log default {
       format filter {
           request>headers>X-Origin-Auth hash
           wrap json
       }
   }
   ```

   Ojo: `caddy validate` ejecutado como root crea los ficheros de log que falten con dueño root, y
   después `systemctl reload caddy` falla porque Caddy (usuario `caddy`) no puede abrirlos:
   `sudo chown caddy:caddy /var/log/caddy/*.log` antes de recargar.
2. **Gcore** la envía en los dominios preparados desde el panel (*Actualizar en Gcore* la pone al día).
3. **Cloudflare:** en la ficha de cada dominio, *Cabecera secreta hacia el origen → Aplicar en
   Cloudflare* crea la regla de transformación de la zona. El token necesita el permiso
   *Zona · Transform Rules · Editar*. La ficha indica si cada CDN tiene el secreto actual.
4. **Fichero de Caddy** con los valores aceptados, generado en el VPS (los secretos no se muestran):

   ```bash
   cd /var/www/multi-cdn
   docker compose exec -T panel python -m app.cli secretos-origen --caddy | sudo tee /etc/caddy/origin-auth.caddy >/dev/null
   sudo chown root:caddy /etc/caddy/origin-auth.caddy && sudo chmod 640 /etc/caddy/origin-auth.caddy
   ```

   Añade `import /etc/caddy/origin-auth.caddy` al principio del Caddyfile (solo define el snippet
   `origin_auth`; no cambia nada todavía), `caddy validate` y `systemctl reload caddy`.
5. **Comprueba que llega:** en los logs, las peticiones por Cloudflare y por Gcore llevan en
   `X-Origin-Auth` los 8 primeros caracteres de la huella de su secreto (`secretos-origen`).
6. **Exígela** sitio a sitio con `import origin_auth` dentro del bloque del sitio, solo en los
   dominios cuyos **dos** CDN estén *Al día* en el panel. `caddy validate` y `reload`, y comprueba
   que el sitio responde por los dos CDN.

**Rotar un secreto sin cortes** (p. ej. si se ha filtrado):

```bash
docker compose exec panel python -m app.cli rotar-secreto-origen gcore   # el anterior sigue aceptado
# regenera /etc/caddy/origin-auth.caddy (paso 4) y recarga Caddy: acepta el nuevo y el anterior
# aplica el nuevo en ese CDN (Actualizar en Gcore / Aplicar en Cloudflare) en todos los dominios
docker compose exec panel python -m app.cli retirar-secreto-anterior gcore
# regenera el fichero otra vez y recarga Caddy
```

## 3. Comprobación desde fuera

`curl` directo a la IP del VPS en 80/443 debe quedarse sin respuesta (firewall) y, desde una IP
permitida sin la cabecera, devolver 403 (Caddy).
