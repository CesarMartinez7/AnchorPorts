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
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, Label, Static

from net import get_gateway_ip, get_local_ip, scan_network
from registry import Registry


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


class AnchorTUI(App):
    CSS = """
    #status { height: 1; color: $text-muted; padding: 0 1; }
    DataTable { height: 1fr; }
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

    # ---- Composición -------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="status")
        table = DataTable(cursor_type="row", zebra_stripes=True)
        yield table
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_column("IP", key="ip", width=16)
        table.add_column("Hostname", key="host", width=22)
        table.add_column("MAC", key="mac", width=19)
        table.add_column("Estado", key="estado", width=24)
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
                    self.registry.seen(mac, ip)
            except Exception:
                pass
            self._stop.wait(every)

    def _tick(self) -> None:
        # Auto-desbloqueo de los temporizados vencidos.
        if self.manager:
            for ip in self.manager.expired():
                self.manager.unblock(ip)
                dev = next((d for d in self.registry.all() if d.ip == ip), None)
                if dev:
                    self.registry.set_status(dev.mac, "allowed")
        self._refresh_table()
        self._update_status()

    # ---- Render ------------------------------------------------------
    def _estado(self, ip: str) -> Text:
        if self.manager and self.manager.is_blocked(ip):
            rem = self.manager.remaining(ip)
            if rem is not None:
                return Text(f"⏳ bloqueado {_dur(rem)}", style="yellow")
            return Text("🔴 bloqueado", style="bold red")
        if ip in (self.gateway_ip, self.local_ip):
            return Text("— tú / router", style="dim")
        return Text("🟢 permitido", style="green")

    def _refresh_table(self) -> None:
        table = self.query_one(DataTable)
        for dev in self.registry.all():
            estado = self._estado(dev.ip)
            visto = _ago(dev.last_seen)
            host = dev.hostname or "—"
            if dev.ip in self._rows:
                table.update_cell(dev.ip, "estado", estado)
                table.update_cell(dev.ip, "visto", visto)
                table.update_cell(dev.ip, "host", host)
            else:
                table.add_row(dev.ip, host, dev.mac, estado, visto, key=dev.ip)
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
        table = self.query_one(DataTable)
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            return key.value
        except Exception:
            return None

    def action_down(self) -> None:
        self.query_one(DataTable).action_cursor_down()

    def action_up(self) -> None:
        self.query_one(DataTable).action_cursor_up()

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

    def action_toggle(self) -> None:
        ip = self._selected_ip()
        if not self._guard(ip):
            return
        if self.manager.is_blocked(ip):
            self.manager.unblock(ip)
            self._set_status(ip, "allowed")
            self.notify(f"Desbloqueado {ip}")
        elif self.manager.block(ip):
            self._set_status(ip, "blocked")
            self.notify(f"Bloqueado {ip}", severity="warning")
        self._refresh_table()

    def action_unblock(self) -> None:
        ip = self._selected_ip()
        if self.manager and ip and self.manager.is_blocked(ip):
            self.manager.unblock(ip)
            self._set_status(ip, "allowed")
            self.notify(f"Desbloqueado {ip}")
            self._refresh_table()

    def action_timed(self) -> None:
        ip = self._selected_ip()
        if not self._guard(ip) or self.manager.is_blocked(ip):
            return

        def _done(seg: float | None) -> None:
            if seg and self.manager.block(ip, duration=seg):
                self._set_status(ip, "blocked")
                self.notify(f"Bloqueado {ip} por {_dur(seg)}", severity="warning")
                self._refresh_table()

        self.push_screen(TimedBlockScreen(ip), _done)

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
