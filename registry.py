"""Registro persistente de dispositivos de la red (SQLite).

Guarda quién se ha visto, su estado (permitido/bloqueado) y la última vez que
apareció. Así la tabla de "quién puede conectarse y quién no" sobrevive entre
ejecuciones.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

DB_PATH = "anchorport.db"


@dataclass
class Device:
    mac: str
    ip: str
    hostname: str
    status: str  # "allowed" | "blocked"
    last_seen: float


class Registry:
    def __init__(self, path: str = DB_PATH):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS devices (
                mac       TEXT PRIMARY KEY,
                ip        TEXT,
                hostname  TEXT,
                status    TEXT DEFAULT 'allowed',
                last_seen REAL
            )"""
        )
        self.conn.commit()

    def seen(self, mac: str, ip: str, hostname: str = "") -> None:
        """Marca un dispositivo como visto ahora (upsert sin pisar su estado)."""
        self.conn.execute(
            """INSERT INTO devices (mac, ip, hostname, status, last_seen)
               VALUES (?, ?, ?, 'allowed', ?)
               ON CONFLICT(mac) DO UPDATE SET
                 ip=excluded.ip,
                 hostname=CASE WHEN excluded.hostname != ''
                               THEN excluded.hostname ELSE devices.hostname END,
                 last_seen=excluded.last_seen""",
            (mac, ip, hostname, time.time()),
        )
        self.conn.commit()

    def set_status(self, mac: str, status: str) -> None:
        self.conn.execute(
            "UPDATE devices SET status=? WHERE mac=?", (status, mac)
        )
        self.conn.commit()

    def all(self) -> list[Device]:
        rows = self.conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC"
        ).fetchall()
        return [Device(**dict(r)) for r in rows]

    def get(self, mac: str) -> Device | None:
        r = self.conn.execute(
            "SELECT * FROM devices WHERE mac=?", (mac,)
        ).fetchone()
        return Device(**dict(r)) if r else None

    def close(self) -> None:
        self.conn.close()
