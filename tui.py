"""Panel interactivo de red (TUI) estilo vim/nvim.

Tabla persistente que se actualiza sola. Todo por teclado:
  j / ↓      bajar            k / ↑      subir
  espacio    bloquear/desbloquear el dispositivo seleccionado
  t          bloquear por un tiempo (minutos)
  u          desbloquear
  r          re-escanear ya
  q          salir (restaura toda la red)

Muestra estados (🟢 permitido / 🔴 bloqueado / ⏳ con cuenta regresiva),
no logs. Bloquear/monitorear requiere Npcap en Windows o root en Linux.
"""
from __future__ import annotations

import threading
import time

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, Static

from dns_monitor import DnsSniffer
from logo import logo_markup
from net import (
    get_gateway_ip,
    get_local_ip,
    get_vendor,
    reverse_dns,
    scan_network,
    set_ip_forwarding,
)
from registry import Registry

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

LEYENDA = (
    "[b]Teclas[/]\n"
    "  j / k   mover\n"
    "  espacio bloquear\n"
    "  t       por tiempo\n"
    "  u       desbloquear\n"
    "  d       detalle DNS\n"
    "  r       re-escanear\n"
    "  q       salir\n\n"
    "[b]Estados[/]\n"
    "  [green]🟢 permitido[/]\n"
    "  [red]🔴 bloqueado[/]\n"
    "  [yellow]⏳ temporizado[/]"
)


def _ago(ts: float) -> str:
    d = int(time.time() - ts)
    if d < 60:
        return f"{d}s"
    if d < 3600:
        return f"{d // 60}m"
    return f"{d // 3600}h"


def _dur(seg: float) -> str:
    seg = int(seg)
    m, s = divmod(seg, 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


class TimedBlockScreen(ModalScreen[float | None]):
    """Pide los minutos para un bloqueo temporizado."""

    BINDINGS = [("escape", "cancel", "Cancelar")]

    def __init__(self, ip: str):
        super().__init__()
        self.ip = ip

    def compose(self) -> ComposeResult:
        with Vertical(id="modal"):
            yield Label(f"Bloquear {self.ip} por cuántos minutos?")
            yield Input(placeholder="ej. 5", id="min", type="number")

    def on_mount(self) -> None:
        self.query_one("#min", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        try:
            minutos = float(event.value)
        except ValueError:
            minutos = 0
        self.dismiss(minutos * 60 if minutos > 0 else None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class DnsDetailScreen(Screen):
    """Segunda tabla: qué dominios consulta UN dispositivo (en vivo).

    Redirige ese dispositivo por nosotros (forwarding ON) y escucha su DNS.
    Al salir restaura. Nota: activar forwarding afecta temporalmente a otros
    bloqueos, por eso es una vista aparte.
    """

    BINDINGS = [("escape,q,d", "cerrar", "Volver")]

    CSS = """
    #detalle-info { height: auto; padding: 1 1; border: round $accent; }
    DataTable { height: 1fr; }
    """

    def __init__(self, dev, ip: str, manager):
        super().__init__()
        self.dev = dev
        self.ip = ip
        self.hostname = dev.hostname if dev else ""
        self.manager = manager
        self.sniffer = DnsSniffer()
        self._forwarding_ok = False
        self._ports_info = "[dim]escaneando puertos/SO...[/]"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="detalle-info")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Footer()

    def _info_markup(self) -> str:
        d = self.dev
        mac = d.mac if d else "—"
        vendor = (d.vendor if d and d.vendor else "—")
        host = self.hostname or "—"
        return (
            f"[b cyan]{host}[/]  ·  [b]{self.ip}[/]\n"
            f"MAC: {mac}   Fabricante: {vendor}\n"
            f"Puertos/SO: {self._ports_info}\n"
            "[dim]Dominios que consulta este dispositivo (DNS en vivo). "
            "escape/q/d para volver[/]"
        )

    def on_mount(self) -> None:
        self.query_one("#detalle-info", Static).update(self._info_markup())
        table = self.query_one(DataTable)
        table.add_column("Dominio", key="dom", width=44)
        table.add_column("Veces", key="cnt", width=7)
        table.add_column("Última", key="last", width=8)
        self._seen: set[str] = set()

        self._forwarding_ok = set_ip_forwarding(True)
        if self.manager and not self.manager.is_blocked(self.ip):
            self.manager.block(self.ip)  # con forwarding ON = redirigir
        self.sniffer.start()
        threading.Thread(target=self._scan_ports, daemon=True).start()
        self.set_interval(1.0, self._refresh)

    def _scan_ports(self) -> None:
        """Escaneo nmap de este dispositivo (puertos abiertos + SO)."""
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(hosts=self.ip, arguments="-F -O", sudo=True)
            data = nm[self.ip]
            puertos = [str(p) for p in sorted(data.get("tcp", {}))
                       if data["tcp"][p]["state"] == "open"]
            osm = data.get("osmatch") or []
            so = osm[0]["name"] if osm else "no detectado"
            txt = (f"SO {so} · puertos: "
                   + (", ".join(puertos) if puertos else "ninguno abierto"))
        except Exception:
            txt = "[dim]no disponible (requiere nmap + permisos)[/]"
        self._ports_info = txt
        self.app.call_from_thread(
            lambda: self.query_one("#detalle-info", Static).update(self._info_markup())
        )

    def _refresh(self) -> None:
        table = self.query_one(DataTable)
        for dom, cnt, ts in self.sniffer.domains(self.ip):
            last = f"{int(time.time() - ts)}s"
            if dom in self._seen:
                table.update_cell(dom, "cnt", str(cnt))
                table.update_cell(dom, "last", last)
            else:
                table.add_row(dom, str(cnt), last, key=dom)
                self._seen.add(dom)

    def action_cerrar(self) -> None:
        self.sniffer.stop()
        # Dejamos de redirigir este dispositivo y restauramos.
        if self.manager and self.manager.is_blocked(self.ip):
            self.manager.unblock(self.ip)
        if self._forwarding_ok:
            set_ip_forwarding(False)
        self.app.pop_screen()


class AnchorTUI(App):
    CSS = """
    #status { height: 1; color: $text-muted; padding: 0 1; }
    #cuerpo { height: 1fr; }
    #main-table { width: 1fr; }
    #sidebar { width: 34; padding: 0 1; }
    #logo { color: #d9766a; height: auto; }
    #legend { height: auto; margin-top: 1; }
    #modal {
        width: 50; height: auto; padding: 1 2;
        border: round $accent; background: $panel;
    }
    #modal Label { margin-bottom: 1; }
    """

    BINDINGS = [
        ("j,down", "down", "Bajar"),
        ("k,up", "up", "Subir"),
        ("space", "toggle", "Bloq/Desbloq"),
        ("t", "timed", "Bloq. temporizado"),
        ("u", "unblock", "Desbloquear"),
        ("d,enter", "details", "Detalle DNS"),
        ("r", "scan", "Re-escanear"),
        ("q", "quit", "Salir"),
    ]

    def __init__(self):
        super().__init__()
        self.gateway_ip = get_gateway_ip()
        self.local_ip = get_local_ip()
        self.registry = Registry()
        self.manager = None
        self.arp_error: str | None = None
        self._stop = threading.Event()
        self._rows: set[str] = set()  # ips ya presentes en la tabla
        self._pending: dict[str, str] = {}  # ip -> "bloqueando" | "cerrando"

    # ---- Composición -------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="status")
        with Horizontal(id="cuerpo"):
            yield DataTable(id="main-table", cursor_type="row", zebra_stripes=True)
            with Vertical(id="sidebar"):
                yield Static(logo_markup(), id="logo")
                yield Static(LEYENDA, id="legend")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#main-table", DataTable)
        table.add_column("IP", key="ip", width=16)
        table.add_column("Hostname", key="host", width=20)
        table.add_column("Fabricante", key="vendor", width=18)
        table.add_column("MAC", key="mac", width=19)
        table.add_column("Estado", key="estado", width=22)
        table.add_column("Visto", key="visto", width=7)
        table.focus()

        # BlockManager puede fallar sin Npcap/root: no reventar.
        try:
            from arp_manager import BlockManager
            self.manager = BlockManager(self.gateway_ip)
        except RuntimeError as e:
            self.arp_error = str(e)

        threading.Thread(target=self._scan_loop, daemon=True).start()
        self.set_interval(1.0, self._tick)
        self._update_status()

    # ---- Datos en segundo plano -------------------------------------
    def _scan_loop(self, every: float = 10.0) -> None:
        while not self._stop.is_set():
            try:
                for ip, mac in scan_network(self.gateway_ip):
                    self.registry.seen(mac, ip, reverse_dns(ip), get_vendor(mac))
            except Exception:
                pass
            self._stop.wait(every)

    def _tick(self) -> None:
        # Auto-desbloqueo de los temporizados vencidos (en segundo plano).
        if self.manager:
            for ip in self.manager.expired():
                self._start_unblock(ip)
        self._refresh_table()
        self._update_status()

    # ---- Render ------------------------------------------------------
    def _spinner(self) -> str:
        return SPINNER[int(time.time() * 10) % len(SPINNER)]

    def _estado(self, ip: str) -> Text:
        # Estado transitorio (cargando) tiene prioridad visual.
        if ip in self._pending:
            return Text(f"{self._spinner()} {self._pending[ip]}...", style="bold yellow")
        if self.manager and self.manager.is_blocked(ip):
            rem = self.manager.remaining(ip)
            if rem is not None:
                return Text(f"⏳ bloqueado {_dur(rem)}", style="yellow")
            return Text("🔴 bloqueado", style="bold red")
        if ip in (self.gateway_ip, self.local_ip):
            return Text("— tú / router", style="dim")
        return Text("🟢 permitido", style="green")

    def _refresh_table(self) -> None:
        table = self.query_one("#main-table", DataTable)
        for dev in self.registry.all():
            estado = self._estado(dev.ip)
            visto = _ago(dev.last_seen)
            host = dev.hostname or "—"
            vendor = dev.vendor or "—"
            if dev.ip in self._rows:
                table.update_cell(dev.ip, "estado", estado)
                table.update_cell(dev.ip, "visto", visto)
                table.update_cell(dev.ip, "host", host)
                table.update_cell(dev.ip, "vendor", vendor)
            else:
                table.add_row(dev.ip, host, vendor, dev.mac, estado, visto,
                              key=dev.ip)
                self._rows.add(dev.ip)

    def _update_status(self) -> None:
        bloqueados = len(self.manager.blocked_ips()) if self.manager else 0
        total = len(self._rows)
        base = (f"Gateway {self.gateway_ip} · Local {self.local_ip} · "
                f"{total} dispositivos · {bloqueados} bloqueados")
        if self.arp_error:
            base = (f"[b red]ARP no disponible[/] (instala Npcap / corre como "
                    f"admin) — solo lectura · {base}")
        self.query_one("#status", Static).update(base)

    # ---- Acciones de teclado ----------------------------------------
    def _selected_ip(self) -> str | None:
        table = self.query_one("#main-table", DataTable)
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            return key.value
        except Exception:
            return None

    def action_down(self) -> None:
        self.query_one("#main-table", DataTable).action_cursor_down()

    def action_up(self) -> None:
        self.query_one("#main-table", DataTable).action_cursor_up()

    def _guard(self, ip: str | None) -> bool:
        if not self.manager:
            self.notify("ARP no disponible (falta Npcap / admin).", severity="error")
            return False
        if not ip:
            return False
        if ip in (self.gateway_ip, self.local_ip):
            self.notify("No vas a bloquearte a ti ni al router.", severity="warning")
            return False
        return True

    def _set_status(self, ip: str, status: str) -> None:
        dev = next((d for d in self.registry.all() if d.ip == ip), None)
        if dev:
            self.registry.set_status(dev.mac, status)

    # -- Bloqueo/desbloqueo en segundo plano (con estado de carga) -----
    def _start_block(self, ip: str, duration: float | None = None) -> None:
        if ip in self._pending:
            return
        self._pending[ip] = "cortando"
        threading.Thread(
            target=self._worker_block, args=(ip, duration), daemon=True
        ).start()

    def _worker_block(self, ip: str, duration: float | None) -> None:
        ok = self.manager.block(ip, duration=duration)

        def done() -> None:
            self._pending.pop(ip, None)
            if ok:
                self._set_status(ip, "blocked")
                extra = f" por {_dur(duration)}" if duration else ""
                self.notify(f"Bloqueado {ip}{extra}", severity="warning")
            else:
                self.notify(f"No se pudo bloquear {ip}", severity="error")
            self._refresh_table()

        self.call_from_thread(done)

    def _start_unblock(self, ip: str) -> None:
        if ip in self._pending:
            return
        self._pending[ip] = "restaurando"
        threading.Thread(target=self._worker_unblock, args=(ip,), daemon=True).start()

    def _worker_unblock(self, ip: str) -> None:
        self.manager.unblock(ip)

        def done() -> None:
            self._pending.pop(ip, None)
            self._set_status(ip, "allowed")
            self.notify(f"Desbloqueado {ip}")
            self._refresh_table()

        self.call_from_thread(done)

    def action_toggle(self) -> None:
        ip = self._selected_ip()
        if not self._guard(ip) or ip in self._pending:
            return
        if self.manager.is_blocked(ip):
            self._start_unblock(ip)
        else:
            self._start_block(ip)

    def action_unblock(self) -> None:
        ip = self._selected_ip()
        if (self.manager and ip and ip not in self._pending
                and self.manager.is_blocked(ip)):
            self._start_unblock(ip)

    def action_timed(self) -> None:
        ip = self._selected_ip()
        if not self._guard(ip) or self.manager.is_blocked(ip) or ip in self._pending:
            return

        def _done(seg: float | None) -> None:
            if seg:
                self._start_block(ip, duration=seg)

        self.push_screen(TimedBlockScreen(ip), _done)

    def action_details(self) -> None:
        ip = self._selected_ip()
        if not ip:
            return
        if not self.manager:
            self.notify("DNS no disponible (falta Npcap / admin).", severity="error")
            return
        if ip in (self.gateway_ip, self.local_ip):
            self.notify("Ese es tu equipo / el router.", severity="warning")
            return
        dev = next((d for d in self.registry.all() if d.ip == ip), None)
        self.push_screen(DnsDetailScreen(dev, ip, self.manager))

    def action_scan(self) -> None:
        self.notify("Re-escaneando...")
        threading.Thread(
            target=lambda: [self.registry.seen(m, i)
                            for i, m in scan_network(self.gateway_ip)],
            daemon=True,
        ).start()

    def action_quit(self) -> None:
        self._stop.set()
        if self.manager:
            self.manager.unblock_all()
        self.registry.close()
        self.exit()


if __name__ == "__main__":
    AnchorTUI().run()
