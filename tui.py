"""Panel interactivo de red (TUI) estilo vim/nvim.

Tabla persistente que se actualiza sola. Todo por teclado:
  j / ↓      bajar            k / ↑      subir
  espacio    bloquear/desbloquear el dispositivo seleccionado
  t          bloquear por un tiempo (minutos)
  u          desbloquear
  r          re-escanear ya
  q          salir (restaura toda la red)

Muestra estados ([+] permitido / [x] bloqueado / [~] con cuenta regresiva),
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
    ip_forwarding_enabled,
    reverse_dns,
    scan_network,
    set_ip_forwarding,
)
from registry import Registry

SPINNER = "|/-\\"  # ASCII: se ve en cualquier terminal (cmd, powershell, bash)

LEYENDA = (
    "[b]Teclas[/]\n"
    "  j / k   mover\n"
    "  espacio bloquear\n"
    "  t       por tiempo\n"
    "  u       desbloquear\n"
    "  e       expulsar (aislar)\n"
    "  l       limitar MB\n"
    "  d       detalle DNS\n"
    "  n       renombrar\n"
    "  r       re-escanear\n"
    "  q       salir\n\n"
    "[b]Estados[/]\n"
    "  [green][+] permitido[/]\n"
    "  [red][x] bloqueado[/]\n"
    "  [red][X] expulsado[/]\n"
    "  [magenta][%] limitado[/]\n"
    "  [yellow][~] temporizado[/]\n"
    "  [cyan][o] monitoreando[/]"
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


class LimitScreen(ModalScreen[float | None]):
    """Pide el tope de datos (en MB) para el modo límite."""

    BINDINGS = [("escape", "cancel", "Cancelar")]

    def __init__(self, ip: str):
        super().__init__()
        self.ip = ip

    def compose(self) -> ComposeResult:
        with Vertical(id="modal"):
            yield Label(f"Limitar {self.ip} a cuántos MB de datos?")
            yield Input(placeholder="ej. 100", id="mb", type="number")

    def on_mount(self) -> None:
        self.query_one("#mb", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        try:
            mb = float(event.value)
        except ValueError:
            mb = 0
        self.dismiss(mb if mb > 0 else None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class RenameScreen(ModalScreen[str | None]):
    """Pide un nombre personalizado para el dispositivo."""

    BINDINGS = [("escape", "cancel", "Cancelar")]

    def __init__(self, ip: str, actual: str):
        super().__init__()
        self.ip = ip
        self.actual = actual

    def compose(self) -> ComposeResult:
        with Vertical(id="modal"):
            yield Label(f"Nombre para {self.ip}  [dim](Enter guarda · vacío borra)[/]")
            yield Input(value=self.actual, placeholder="ej. iPhone de Ana", id="nom")

    def on_mount(self) -> None:
        self.query_one("#nom", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip())

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
        if self._monitoring:
            modo = "[green][o] monitoreando (tráfico redirigido, sin cortar)[/]"
        else:
            modo = ("[yellow]modo pasivo — IP forwarding no confirmado, no se "
                    "redirige para no cortar la red (DNS de otros equipos solo "
                    "con Linux/root)[/]")
        cap = (f"[dim]DNS capturado: {self.sniffer.total} total · "
               f"{len(self.sniffer.log.get(self.ip, {}))} de este equipo[/]")
        return (
            f"[b cyan]{host}[/]  ·  [b]{self.ip}[/]    {modo}\n"
            f"MAC: {mac}   Fabricante: {vendor}    {cap}\n"
            f"Puertos/SO: {self._ports_info}\n"
            "[dim]Dominios que consulta este dispositivo (DNS en vivo). "
            "escape/q/d para volver[/]"
        )

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_column("Dominio", key="dom", width=44)
        table.add_column("Veces", key="cnt", width=7)
        table.add_column("Última", key="last", width=8)
        self._seen: set[str] = set()
        self._monitoring = False  # ¿llegamos a redirigir este dispositivo?

        # Pausa el re-escaneo ARP del panel para no des-redirigir al objetivo.
        self.app._scan_paused.set()

        # Activamos forwarding y CONFIRMAMOS que quedó activo. Solo entonces
        # redirigimos: con forwarding el tráfico fluye por nosotros (no se corta
        # la red). Si no se confirma, NO envenenamos (modo pasivo) para no dejar
        # sin Internet al dispositivo.
        set_ip_forwarding(True)
        self._forwarding_ok = ip_forwarding_enabled() is True
        if self._forwarding_ok and self.manager and not self.manager.is_active(self.ip):
            self.manager.block(self.ip, mode="monitor")  # redirige, no corta
            self._monitoring = True

        self.query_one("#detalle-info", Static).update(self._info_markup())
        self.sniffer.start()
        # nmap se difiere para no competir con la redirección al arrancar.
        self.set_timer(3.0, lambda: threading.Thread(
            target=self._scan_ports, daemon=True).start())
        self.set_interval(1.0, self._refresh)

    def _refresh_header(self) -> None:
        try:
            self.query_one("#detalle-info", Static).update(self._info_markup())
        except Exception:
            pass

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
        self._refresh_header()  # contador de capturas en vivo
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
        # Solo deshacemos lo que hicimos: si estábamos redirigiendo, paramos.
        if self._monitoring and self.manager and self.manager.is_monitoring(self.ip):
            self.manager.unblock(self.ip)
        if self._forwarding_ok:
            set_ip_forwarding(False)
        # Reanuda el re-escaneo del panel.
        self.app._scan_paused.clear()
        self.app.pop_screen()


class AnchorTUI(App):
    TITLE = "AnchorPort"
    SUB_TITLE = "control de red · teclado"

    CSS = """
    Screen { background: $surface; }

    #status {
        height: 1; padding: 0 2;
        background: #d9766a; color: $text; text-style: bold;
    }

    #cuerpo { height: 1fr; padding: 1 1 0 1; }

    #main-table {
        width: 1fr; height: 1fr;
        border: round #d9766a; padding: 0 1;
        border-title-color: #d9766a; border-title-align: center;
        border-subtitle-color: $text-muted; border-subtitle-align: right;
    }
    #main-table > .datatable--header {
        background: #d9766a; color: $text; text-style: bold;
    }
    #main-table > .datatable--cursor { background: #d9766a 45%; text-style: bold; }
    #main-table > .datatable--hover { background: #d9766a 20%; }

    #sidebar {
        width: 36; height: 1fr; margin-left: 1;
        border: round #d9766a; padding: 1 1;
        border-title-color: #d9766a; border-title-align: center;
    }
    #logo { color: #d9766a; height: auto; content-align: center top; }
    #legend { height: auto; margin-top: 1; color: $text-muted; }

    #modal {
        width: 50; height: auto; padding: 1 2;
        border: round #d9766a; background: $panel;
    }
    #modal Label { margin-bottom: 1; }
    """

    BINDINGS = [
        ("j,down", "down", "Bajar"),
        ("k,up", "up", "Subir"),
        ("space", "toggle", "Bloq/Desbloq"),
        ("t", "timed", "Bloq. temporizado"),
        ("u", "unblock", "Desbloquear"),
        ("e", "expel", "Expulsar"),
        ("l", "limit", "Limitar MB"),
        ("d,enter", "details", "Detalle DNS"),
        ("n", "rename", "Renombrar"),
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
        # Pausa el re-escaneo ARP mientras se monitorea un dispositivo, para no
        # refrescar las tablas ARP y "des-redirigir" al objetivo.
        self._scan_paused = threading.Event()

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
        table.border_title = "Dispositivos en la red"
        table.border_subtitle = ("j/k mover · espacio bloquear · e expulsar · "
                                  "l limitar MB · d detalle · n renombrar")
        table.add_column("IP", key="ip", width=16)
        table.add_column("Nombre", key="host", width=20)
        table.add_column("Fabricante", key="vendor", width=18)
        table.add_column("MAC", key="mac", width=19)
        table.add_column("Estado", key="estado", width=22)
        table.add_column("Visto", key="visto", width=7)
        table.focus()
        self.query_one("#sidebar", Vertical).border_title = "AnchorPort"

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
            if not self._scan_paused.is_set():
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
        if self.manager and self.manager.is_monitoring(ip):
            return Text("[o] monitoreando", style="bold cyan")
        if self.manager and self.manager.is_expelling(ip):
            return Text("[X] expulsado", style="bold red")
        if self.manager and self.manager.is_limiting(ip):
            info = self.manager.limit_info(ip)
            if info:
                usado, tope, over = info
                if over:
                    return Text(f"[x] cortado ({tope:.0f}MB)", style="bold red")
                return Text(f"[%] {usado:.1f}/{tope:.0f}MB", style="magenta")
        if self.manager and self.manager.is_blocked(ip):
            rem = self.manager.remaining(ip)
            if rem is not None:
                return Text(f"[~] bloqueado {_dur(rem)}", style="yellow")
            return Text("[x] bloqueado", style="bold red")
        if ip in (self.gateway_ip, self.local_ip):
            return Text("- tu / router", style="dim")
        return Text("[+] permitido", style="green")

    def _refresh_table(self) -> None:
        table = self.query_one("#main-table", DataTable)
        for dev in self.registry.all():
            estado = self._estado(dev.ip)
            visto = _ago(dev.last_seen)
            # Nombre a mostrar: alias (si se renombró) resaltado, si no hostname.
            if dev.alias:
                host = Text(dev.alias, style="bold")
            else:
                host = Text(dev.hostname or "—", style="dim")
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
        if total == 0:
            resumen = f"{self._spinner()} buscando dispositivos..."
        else:
            resumen = f"{total} dispositivos · {bloqueados} bloqueados"
        base = f"gw {self.gateway_ip}    local {self.local_ip}    {resumen}"
        if self.arp_error:
            base = f"! ARP no disponible (Npcap/admin) - solo lectura    {base}"
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
        ya_activo = self.manager.is_active(ip)
        ok = self.manager.block(ip, duration=duration)

        def done() -> None:
            self._pending.pop(ip, None)
            if ok:
                self._set_status(ip, "blocked")
                extra = f" por {_dur(duration)}" if duration else ""
                self.notify(f"Bloqueado {ip}{extra}", severity="warning")
            elif ya_activo:
                self.notify(f"{ip} ya estaba bloqueado o en monitoreo.",
                            severity="warning")
            else:
                self.notify(
                    f"No se pudo bloquear {ip}: no respondió al ARP "
                    "(desconectado, dormido, o el router aísla clientes).",
                    severity="error",
                )
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

    # -- Acción genérica en segundo plano (expulsar / limitar) ---------
    def _start_action(self, ip: str, label: str, kwargs: dict, ok_msg: str) -> None:
        if ip in self._pending:
            return
        self._pending[ip] = label
        threading.Thread(
            target=self._worker_action, args=(ip, kwargs, ok_msg), daemon=True
        ).start()

    def _worker_action(self, ip: str, kwargs: dict, ok_msg: str) -> None:
        ok = self.manager.block(ip, **kwargs)

        def done() -> None:
            self._pending.pop(ip, None)
            if ok:
                self._set_status(ip, "blocked")
                self.notify(ok_msg, severity="warning")
            else:
                self.notify(
                    f"No se pudo con {ip}: no respondió al ARP "
                    "(desconectado, dormido, o aislamiento de clientes).",
                    severity="error",
                )
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
                and self.manager.is_active(ip)):
            self._start_unblock(ip)

    def action_expel(self) -> None:
        ip = self._selected_ip()
        if not self._guard(ip) or ip in self._pending:
            return
        if self.manager.is_active(ip):
            self.notify(f"{ip} ya está activo; desbloquea con 'u' primero.",
                        severity="warning")
            return
        # Peers = todos los demás hosts conocidos (para aislarlo de la LAN).
        peers = [d.ip for d in self.registry.all()
                 if d.ip not in (ip, self.gateway_ip, self.local_ip)]
        self._start_action(ip, "expulsando", {"mode": "expel", "peers": peers},
                           f"Expulsado {ip} de la red (aislado)")

    def action_limit(self) -> None:
        ip = self._selected_ip()
        if not self._guard(ip) or ip in self._pending:
            return
        if self.manager.is_active(ip):
            self.notify(f"{ip} ya está activo; desbloquea con 'u' primero.",
                        severity="warning")
            return
        set_ip_forwarding(True)
        if ip_forwarding_enabled() is not True:
            self.notify(
                "Limitar requiere IP forwarding activo (Linux/root); si no, "
                "cortaría la red en vez de dejar pasar datos.", severity="error")
            return

        def _done(mb: float | None) -> None:
            if mb:
                self._start_action(ip, "limitando",
                                   {"mode": "limit", "cap_mb": mb},
                                   f"Limitando {ip} a {mb:.0f} MB")

        self.push_screen(LimitScreen(ip), _done)

    def action_timed(self) -> None:
        ip = self._selected_ip()
        if not self._guard(ip) or self.manager.is_blocked(ip) or ip in self._pending:
            return

        def _done(seg: float | None) -> None:
            if seg:
                self._start_block(ip, duration=seg)

        self.push_screen(TimedBlockScreen(ip), _done)

    def action_rename(self) -> None:
        ip = self._selected_ip()
        if not ip:
            return
        dev = next((d for d in self.registry.all() if d.ip == ip), None)
        if not dev:
            return

        def _done(nombre: str | None) -> None:
            if nombre is None:
                return
            self.registry.set_alias(dev.mac, nombre)
            table = self.query_one("#main-table", DataTable)
            mostrado = (Text(nombre, style="bold") if nombre
                        else Text(dev.hostname or "—", style="dim"))
            table.update_cell(ip, "host", mostrado)
            self.notify(f"{ip} renombrado a «{nombre}»" if nombre
                        else f"Nombre de {ip} borrado")

        self.push_screen(RenameScreen(ip, dev.alias), _done)

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
