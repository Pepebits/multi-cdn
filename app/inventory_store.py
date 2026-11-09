"""Inventario editable desde el panel (SQLite). El YAML queda para importar/exportar.

Las IPs de origen no se guardan aquí sino en el SecretStore (cifradas) bajo
el nombre "origin_ipv4:<servidor>".
"""

from __future__ import annotations

import ipaddress
import json
import re
import yaml

from .config import Domain, Hostname, Inventory, Server, normalize_private_address
from .secrets_store import SecretStore

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    private_address TEXT
);
CREATE TABLE IF NOT EXISTS domains (
    name TEXT PRIMARY KEY,
    zone_id TEXT,
    policy TEXT NOT NULL,
    priority TEXT NOT NULL,
    cloudflare_credential INTEGER,
    gcore_credential INTEGER
);
CREATE TABLE IF NOT EXISTS hostnames (
    name TEXT PRIMARY KEY,
    domain TEXT NOT NULL REFERENCES domains(name) ON DELETE CASCADE,
    server TEXT NOT NULL,
    backups TEXT NOT NULL,
    gcore_target TEXT,
    cloudflare_record_id TEXT
);
"""

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_hostname(value: str) -> str:
    name = value.strip().lower().rstrip(".")
    labels = name.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise ValueError(f"nombre no válido: {value!r}")
    return name


def origin_key(server_id: str) -> str:
    return f"origin_ipv4:{server_id}"


class InventoryStore:
    def __init__(self, secrets: SecretStore):
        # Misma conexión que los secretos: los cambios que tocan ambos son atómicos y no se bloquean.
        self.conn = secrets.conn
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        # migraciones de bases creadas con versiones anteriores
        server_cols = {r[1] for r in self.conn.execute("PRAGMA table_info(servers)")}
        if "tailscale" in server_cols and "private_address" not in server_cols:
            self.conn.execute("ALTER TABLE servers RENAME COLUMN tailscale TO private_address")
        for table, col, kind in (("domains", "cloudflare_credential", "INTEGER"), ("domains", "gcore_credential", "INTEGER"),
                                 ("hostnames", "origin_kind", "TEXT"), ("hostnames", "tunnel_target", "TEXT"),
                                 ("domains", "gcore_resource_id", "INTEGER"), ("domains", "gcore_ssl_id", "INTEGER"),
                                 ("domains", "cert_not_after", "TEXT"), ("hostnames", "cname_target", "TEXT"),
                                 ("hostnames", "failover", "INTEGER NOT NULL DEFAULT 1")):
            if col not in {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {kind}")
        self.conn.commit()
        self.secrets = secrets

    # ---------- lectura ----------
    def is_empty(self) -> bool:
        return self.conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 0 and \
            self.conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0] == 0

    def load(self) -> Inventory:
        servers = {}
        for sid, private in self.conn.execute("SELECT id, private_address FROM servers ORDER BY id"):
            servers[sid] = Server(origin_ipv4=self.secrets.get(origin_key(sid)), private_address=private)
        domains = {}
        for name, zone_id, policy, priority, cf_cred, gc_cred, gres, gssl, cert_na in self.conn.execute(
                "SELECT name, zone_id, policy, priority, cloudflare_credential, gcore_credential,"
                " gcore_resource_id, gcore_ssl_id, cert_not_after FROM domains"):
            hosts = [
                Hostname(name=h, server=s, backups=json.loads(b), gcore_target=g, cloudflare_record_id=r,
                         origin_kind=ok, tunnel_target=tt, cname_target=ct, failover=bool(fo))
                for h, s, b, g, r, ok, tt, ct, fo in self.conn.execute(
                    "SELECT name, server, backups, gcore_target, cloudflare_record_id, origin_kind, tunnel_target, cname_target,"
                    " failover FROM hostnames"
                    " WHERE domain = ? ORDER BY length(name), name", (name,))
            ]
            domains[name] = Domain(zone_id=zone_id, policy=policy, priority=priority, hostnames=hosts,
                                   cloudflare_credential=cf_cred, gcore_credential=gc_cred,
                                   gcore_resource_id=gres, gcore_ssl_id=gssl, cert_not_after=cert_na)
        return Inventory(servers=servers, domains=domains)

    # ---------- servidores ----------
    def upsert_server(self, server_id: str, origin_ipv4: str | None, private_address: str | None) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", server_id):
            raise ValueError("identificador de servidor no válido (minúsculas, números y guiones)")
        if origin_ipv4:
            ipaddress.IPv4Address(origin_ipv4.strip())
        private_address = normalize_private_address(private_address)  # valida antes de guardar nada
        if origin_ipv4:
            self.secrets.set(origin_key(server_id), origin_ipv4.strip())
        self.conn.execute(
            "INSERT INTO servers (id, private_address) VALUES (?, ?)"
            " ON CONFLICT(id) DO UPDATE SET private_address=excluded.private_address",
            (server_id, private_address),
        )
        self.conn.commit()

    def rename_server(self, old: str, new: str) -> None:
        new = new.strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", new):
            raise ValueError("identificador de servidor no válido (minúsculas, números y guiones)")
        if new == old:
            return
        if self.conn.execute("SELECT 1 FROM servers WHERE id = ?", (new,)).fetchone():
            raise ValueError(f"ya existe un servidor llamado {new}")
        ip = self.secrets.get(origin_key(old))
        with self.conn:
            self.conn.execute("UPDATE servers SET id = ? WHERE id = ?", (new, old))
            self.conn.execute("UPDATE hostnames SET server = ? WHERE server = ?", (new, old))
        if ip:
            self.secrets.set(origin_key(new), ip)
            self.secrets.delete(origin_key(old))

    def delete_server(self, server_id: str) -> None:
        used = self.conn.execute("SELECT COUNT(*) FROM hostnames WHERE server = ?", (server_id,)).fetchone()[0]
        if used:
            raise ValueError(f"el servidor {server_id} tiene {used} hostnames asignados")
        self.conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        self.secrets.delete(origin_key(server_id))
        self.conn.commit()

    # ---------- dominios ----------
    def upsert_domain(self, name: str, *, policy: str, priority: str, zone_id: str | None = None) -> str:
        name = normalize_hostname(name)
        Domain(policy=policy, priority=priority, hostnames=[])  # valida valores
        self.conn.execute(
            "INSERT INTO domains (name, zone_id, policy, priority) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(name) DO UPDATE SET zone_id=COALESCE(excluded.zone_id, domains.zone_id),"
            " policy=excluded.policy, priority=excluded.priority",
            (name, zone_id or None, policy, priority),
        )
        self.conn.commit()
        return name

    def set_credentials(self, name: str, cloudflare: int | None, gcore: int | None) -> None:
        self.conn.execute("UPDATE domains SET cloudflare_credential=?, gcore_credential=? WHERE name=?", (cloudflare, gcore, name))
        self.conn.commit()

    def assign_zone(self, name: str, zone_id: str, cloudflare: int) -> bool:
        """Asigna credencial y zone ID si el dominio aún no tiene credencial de Cloudflare."""
        cur = self.conn.execute(
            "UPDATE domains SET cloudflare_credential=?, zone_id=? WHERE name=? AND cloudflare_credential IS NULL",
            (cloudflare, zone_id, name))
        self.conn.commit()
        return cur.rowcount > 0

    def delete_domain(self, name: str) -> None:
        self.conn.execute("DELETE FROM domains WHERE name = ?", (name,))
        self.conn.commit()

    def upsert_hostname(
        self, domain: str, hostname: str, *, server: str, gcore_target: str | None = None,
        cloudflare_record_id: str | None = None, backups: list[str] | None = None,
    ) -> None:
        hostname = normalize_hostname(hostname)
        if hostname != domain and not hostname.endswith("." + domain):
            raise ValueError(f"{hostname} no pertenece a {domain}")
        if not self.conn.execute("SELECT 1 FROM servers WHERE id = ?", (server,)).fetchone():
            raise ValueError(f"servidor desconocido: {server}")
        if gcore_target:
            gcore_target = normalize_hostname(gcore_target)
        self.conn.execute(
            "INSERT INTO hostnames (name, domain, server, backups, gcore_target, cloudflare_record_id)"
            " VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET server=excluded.server,"
            " gcore_target=excluded.gcore_target,"
            " cloudflare_record_id=COALESCE(excluded.cloudflare_record_id, hostnames.cloudflare_record_id)",
            (hostname, domain, server, json.dumps(backups or ["gcore"]), gcore_target or None, cloudflare_record_id),
        )
        self.conn.commit()

    def set_cloudflare_record(self, hostname: str, record_id: str, origin_kind: str, tunnel_target: str | None,
                              cname_target: str | None = None) -> bool:
        cur = self.conn.execute(
            "UPDATE hostnames SET cloudflare_record_id=?, origin_kind=?, tunnel_target=?, cname_target=? WHERE name=?",
            (record_id, origin_kind, tunnel_target, cname_target, hostname))
        self.conn.commit()
        return cur.rowcount > 0

    def set_gcore(self, domain: str, resource_id: int, ssl_id: int, cert_not_after: str, target: str,
                  hostnames: list[str]) -> None:
        with self.conn:
            self.conn.execute("UPDATE domains SET gcore_resource_id=?, gcore_ssl_id=?, cert_not_after=? WHERE name=?",
                              (resource_id, ssl_id, cert_not_after, domain))
            for h in hostnames:
                self.conn.execute("UPDATE hostnames SET gcore_target=? WHERE name=?", (target, h))

    def set_failover(self, hostname: str, enabled: bool) -> None:
        self.conn.execute("UPDATE hostnames SET failover=? WHERE name=?", (int(enabled), hostname))
        self.conn.commit()

    def delete_hostname(self, hostname: str) -> None:
        self.conn.execute("DELETE FROM hostnames WHERE name = ?", (hostname,))
        self.conn.commit()

    # ---------- importar / exportar ----------
    def import_inventory(self, inv: Inventory) -> None:
        for sid, server in inv.servers.items():
            self.upsert_server(sid, str(server.origin_ipv4) if server.origin_ipv4 else None, server.private_address)
        for name, d in inv.domains.items():
            self.upsert_domain(name, policy=d.policy, priority=d.priority, zone_id=d.zone_id)
            for h in d.hostnames:
                self.upsert_hostname(name, h.name, server=h.server, gcore_target=h.gcore_target,
                                     cloudflare_record_id=h.cloudflare_record_id, backups=list(h.backups))

    def export_yaml(self) -> str:
        """Copia sin secretos: la IP de origen sale como referencia a variable de entorno."""
        inv = self.load()
        data = {
            "servers": {
                sid: {"origin_ipv4": "${ORIGIN_%s_IPV4}" % sid.upper().replace("-", "_"), "private_address": s.private_address}
                for sid, s in inv.servers.items()
            },
            "domains": {
                name: {
                    "zone_id": d.zone_id, "policy": d.policy, "priority": d.priority,
                    "hostnames": [h.model_dump(exclude_none=True) for h in d.hostnames],
                }
                for name, d in inv.domains.items()
            },
        }
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
