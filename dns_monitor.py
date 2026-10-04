"""Monitor automático de dominios por dispositivo (vía DNS).

No hay que escribir IPs: descubre la red solo, pone al equipo en medio (MITM
por ARP) con IP forwarding activado para que el tráfico siga fluyendo, y
escucha las consultas DNS para registrar a qué dominios accede cada
dispositivo. Re-escanea periódicamente para captar dispositivos nuevos.

No descifra HTTPS: solo lee los nombres que los dispositivos resuelven.
MONITOREAR es lo contrario de BLOQUEAR: aquí la conexión sigue viva.
Solo en tu propia red.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict

from rich.text import Text
from scapy.all import DNSQR, IP, sniff
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Static

from logo import ELISA_ASCII
from net import (
    get_gateway_ip,
    get_local_ip,
    ip_forwarding_enabled,
    scan_network,
    set_ip_forwarding,
)
from registry import Registry

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

LEYENDA_DNS = (
    "[b]Teclas[/]\n"
    "  r   re-escanear\n"
    "  q   salir (restaura)\n\n"
    "[b]Qué ves[/]\n"
    "  dominios DNS que\n"
    "  consulta cada equipo\n"
    "  (no descifra HTTPS)"
)


def _ago(ts: float) -> str:
    d = int(time.time() - ts)
    if d < 60:
        return f"{d}s"
    if d < 3600:
        return f"{d // 60}m"
    return f"{d // 3600}h"


class DnsSniffer:
    """Sniffer de DNS reutilizable: registra dominios por IP de origen.

    No hace ARP ni forwarding; de eso se encarga quien lo use (p. ej. el panel
    cuando entra al detalle de un dispositivo). Guarda {ip: {dominio: (n, ts)}}.
    """

    def __init__(self):
        self.log: dict[str, dict[str, tuple[int, float]]] = defaultdict(dict)
        self.total = 0          # consultas DNS capturadas en total (cualquier IP)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _on_packet(self, pkt) -> None:
        if not pkt.haslayer(DNSQR) or not pkt.haslayer(IP):
            return
        try:
            src = pkt[IP].src
            dominio = pkt[DNSQR].qname.decode().rstrip(".")
        except Exception:
            return
        self.total += 1
        prev = self.log[src].get(dominio, (0, 0.0))
        self.log[src][dominio] = (prev[0] + 1, time.time())

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        sniff(
            filter="udp port 53", prn=self._on_packet, store=0,
            stop_filter=lambda _: self._stop.is_set(),
        )

    def stop(self) -> None:
        self._stop.set()

    def sources(self) -> list[str]:
        """IPs de las que se ha capturado DNS (copia atómica del dict externo)."""
        return list(dict(self.log).keys())

    def domains(self, ip: str) -> list[tuple[str, int, float]]:
        """[(dominio, veces, ultima_ts)] del dispositivo, más reciente primero."""
        # Copia atómica: el hilo de sniff puede estar escribiendo este dict.
        items = dict(self.log.get(ip, {}))
        orden = sorted(items.items(), key=lambda kv: kv[1][1], reverse=True)
        return [(dom, cnt, ts) for dom, (cnt, ts) in orden]


class DNSMonitor(App):
    """Monitor de dominios DNS de toda la red (tema salmón, estilo panel)."""

    TITLE = "AnchorPort — Monitor DNS"
    SUB_TITLE = "a qué dominios accede cada dispositivo"

    CSS = """
    Screen { background: $surface; }
    #status {
        height: 1; padding: 0 2;
        background: #d9766a; color: $text; text-style: bold;
    }
    #cuerpo { height: 1fr; padding: 1 1 0 1; }
    #dns-table {
        width: 1fr; height: 1fr;
        border: round #d9766a; padding: 0 1;
        border-title-color: #d9766a; border-title-align: center;
        border-subtitle-color: $text-muted; border-subtitle-align: right;
    }
    #dns-table > .datatable--header {
        background: #d9766a; color: $text; text-style: bold;
    }
    #dns-table > .datatable--cursor { background: #d9766a 45%; text-style: bold; }
    #sidebar {
        width: 34; height: 1fr; margin-left: 1;
        border: round #d9766a; padding: 1 1;
        border-title-color: #d9766a; border-title-align: center;
    }
    #logo { color: #d9766a; height: auto; content-align: center top; }
    #legend { height: auto; margin-top: 1; color: $text-muted; }
    """

    BINDINGS = [
        ("r", "rescan", "Re-escanear"),
        ("q", "quit", "Salir"),
    ]

    def __init__(self):
        super().__init__()
        self.gateway_ip = get_gateway_ip()
        self.local_ip = get_local_ip()
        self.registry = Registry()
        self.manager = None
        self.arp_error: str | None = None
        self.sniffer = DnsSniffer()
        self.monitored: set[str] = set()
        self._rows: set[str] = set()  # claves "ip|dominio" ya en la tabla
        self._stop = threading.Event()
        self._forwarding_ok = False

    # ---- Composición -------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="status")
        with Horizontal(id="cuerpo"):
            yield DataTable(id="dns-table", cursor_type="row", zebra_stripes=True)
            with Vertical(id="sidebar"):
                yield Static(Text(ELISA_ASCII, style="#d9766a"), id="logo")
                yield Static(LEYENDA_DNS, id="legend")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.border_title = "Dominios por dispositivo (DNS)"
        table.border_subtitle = "r re-escanear · q salir"
        table.add_column("Dispositivo", key="dev", width=24)
        table.add_column("Dominio", key="dom", width=42)
        table.add_column("Veces", key="cnt", width=7)
        table.add_column("Última", key="last", width=8)
        table.focus()

        try:
            from arp_manager import BlockManager
            self.manager = BlockManager(self.gateway_ip)
        except RuntimeError as e:
            self.arp_error = str(e)

        # Intentamos activar forwarding y CONFIRMAMOS que quedó activo. Solo si
        # está confirmado redirigimos el tráfico; si no, NO envenenamos (eso
        # cortaría la red de los dispositivos, justo lo que hay que evitar).
        set_ip_forwarding(True)
        self._forwarding_ok = ip_forwarding_enabled() is True
        threading.Thread(target=self._discover_loop, daemon=True).start()
        self.sniffer.start()
        self.set_interval(1.0, self._refresh)
        self._update_status()

    # ---- Datos en segundo plano -------------------------------------
    def _discover_loop(self, every: float = 15.0) -> None:
        while not self._stop.is_set():
            try:
                for ip, mac in scan_network(self.gateway_ip):
                    if ip in (self.gateway_ip, self.local_ip):
                        continue
                    self.registry.seen(mac, ip)
                    # Solo redirigir si el forwarding está confirmado: así
                    # monitorear nunca corta la conexión del dispositivo.
                    if (self._forwarding_ok and ip not in self.monitored
                            and self.manager
                            and self.manager.block(ip, mode="monitor")):
                        self.monitored.add(ip)
            except Exception:
                pass
            self._stop.wait(every)

    # ---- Render ------------------------------------------------------
    def _hostnames(self) -> dict[str, str]:
        """Mapa ip->hostname con UNA sola consulta (evita golpear la BD por ip)."""
        try:
            return {d.ip: (d.hostname or d.ip) for d in self.registry.all()}
        except Exception:
            return {}

    def _refresh(self) -> None:
        try:
            table = self.query_one(DataTable)
            nombres = self._hostnames()
            # Mostramos los redirigidos Y cualquier origen con DNS capturado,
            # menos nuestro propio equipo y el router. Copias atómicas para no
            # chocar con los hilos de descubrimiento y sniff.
            ips = (self.monitored.copy() | set(self.sniffer.sources())) - {
                self.local_ip, self.gateway_ip
            }
            for ip in sorted(ips):
                etiqueta = nombres.get(ip, ip)
                for dom, cnt, ts in self.sniffer.domains(ip):
                    clave = f"{ip}|{dom}"
                    last = _ago(ts)
                    if clave in self._rows:
                        table.update_cell(clave, "cnt", str(cnt))
                        table.update_cell(clave, "last", last)
                    else:
                        table.add_row(etiqueta, dom, str(cnt), last, key=clave)
                        self._rows.add(clave)
        except Exception:
            pass
        self._update_status()

    def _update_status(self) -> None:
        if not self._forwarding_ok:
            resumen = (f"modo pasivo · {self.sniffer.total} consultas captadas "
                       "(no se redirige para no cortar la red)")
        elif not self.monitored:
            resumen = f"{SPINNER[int(time.time() * 10) % len(SPINNER)]} buscando dispositivos..."
        else:
            resumen = (f"{len(self.monitored)} monitoreados · "
                       f"{self.sniffer.total} consultas DNS capturadas")
        base = f"📡 {self.gateway_ip}    🖥 {self.local_ip}    {resumen}"
        if self.arp_error:
            base = f"⚠ ARP no disponible (Npcap/admin)    {base}"
        elif not self._forwarding_ok:
            base = (f"⚠ IP forwarding no confirmado — monitoreo pasivo "
                    f"(para ver DNS de otros equipos: Linux/root)    {base}")
        self.query_one("#status", Static).update(base)

    # ---- Acciones ----------------------------------------------------
    def action_rescan(self) -> None:
        if not self.manager:
            self.notify("ARP no disponible (falta Npcap / admin).", severity="error")
            return
        self.notify("Re-escaneando...")
        threading.Thread(target=self._scan_once, daemon=True).start()

    def _scan_once(self) -> None:
        try:
            for ip, mac in scan_network(self.gateway_ip):
                if ip in (self.gateway_ip, self.local_ip):
                    continue
                self.registry.seen(mac, ip)
                if (self._forwarding_ok and ip not in self.monitored
                        and self.manager
                        and self.manager.block(ip, mode="monitor")):
                    self.monitored.add(ip)
        except Exception:
            pass

    def action_quit(self) -> None:
        self._stop.set()
        self.sniffer.stop()
        if self.manager:
            self.manager.unblock_all()
        if self._forwarding_ok:
            set_ip_forwarding(False)
        self.registry.close()
        self.exit()


if __name__ == "__main__":
    DNSMonitor().run()
