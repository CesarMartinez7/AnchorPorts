import sys
from os import system
from time import sleep

import nmap
from colorama import Fore
from rich.console import Console
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Footer, Header, OptionList, Static
from textual.widgets.option_list import Option

from fonts import f
from get_host import _ip_default
from logo import ELISA_ASCII
from net import get_gateway_ip, get_local_ip

machine: str = sys.platform.title()

OPCIONES = [
    ("1", "Panel interactivo",
     "Ver, bloquear y expulsar dispositivos por teclado"),
    ("2", "Monitor de dominios",
     "A qué dominios (DNS) accede cada dispositivo"),
    ("3", "Escaneo detallado",
     "Puertos abiertos y sistema operativo"),
    ("0", "Salir", "Cerrar AnchorPort"),
]


def clear_console():
    if sys.platform.startswith("linux"):
        system("clear")
    else:
        system("cls")


def _safe(d: dict, *keys, default="—"):
    """Baja por un dict/lista anidado sin reventar si falta algo."""
    cur = d
    for k in keys:
        try:
            cur = cur[k]
        except (KeyError, IndexError, TypeError):
            return default
    return cur if cur not in (None, "", [], {}) else default


def escaneo_detallado() -> None:
    """Escanea toda la red (puertos + SO). Automático, sin escribir IPs."""
    clear_console()
    console = Console()
    red = f"{get_local_ip()}/24"
    print(Fore.GREEN + f"=========== Escaneando [{red}] =============")
    print("Esto puede tardar un poco (detección de SO)...")
    scan = nmap.PortScanner()
    scaneo = scan.scan(hosts=red, arguments="-O", sudo=True)
    array = scaneo.get("scan", {})
    total = len(array)

    if total == 0:
        console.print("[yellow]No se encontraron dispositivos.[/]")
        return

    for ip, info in array.items():
        table = Table(
            title=f"Dispositivo {ip}  —  Total conectados [{total}]"
        )
        table.add_column("Atributo", style="cyan")
        table.add_column("Valor", style="magenta")
        table.add_row("Dirección IP", ip)
        table.add_row("Nombre", _safe(info, "hostnames", 0, "name"))
        table.add_row("Tipo", _safe(info, "hostnames", 0, "type"))
        table.add_row("IPv4", _safe(info, "addresses", "ipv4"))
        table.add_row("Status", _safe(info, "status", "state"))
        table.add_row("Sistema", _safe(info, "osmatch", 0, "name",
                                       default="No detectado"))
        puertos = info.get("portused") or []
        table.add_row(
            "Puertos",
            str(puertos) if puertos else "Sin puertos abiertos/en uso",
        )
        console.print(table)
        sleep(0.8)


class MenuApp(App):
    """Menú de inicio interactivo: navega con j/k o flechas, Enter/número elige."""

    TITLE = "AnchorPort"
    SUB_TITLE = "elige una acción — todo automático, sin escribir IPs"

    CSS = """
    Screen { align: center middle; }
    #banner { color: #d9766a; height: auto; content-align: center top;
              margin-bottom: 1; }
    #fila { height: auto; align: center middle; }
    #logo { color: #d9766a; width: auto; height: auto; margin-right: 4; }
    #menu {
        width: 58; height: auto;
        border: round #d9766a; padding: 1 1;
        border-title-color: #d9766a; border-title-align: center;
    }
    #menu > .option-list--option { padding: 0 1; }
    #menu > .option-list--option-highlighted {
        background: #d9766a; color: $text; text-style: bold;
    }
    #info { color: $text-muted; height: auto; content-align: center top;
            margin-top: 1; }
    """

    BINDINGS = [
        ("j,down", "mover(1)", "Bajar"),
        ("k,up", "mover(-1)", "Subir"),
        ("1", "elegir('1')", ""),
        ("2", "elegir('2')", ""),
        ("3", "elegir('3')", ""),
        ("0,q", "elegir('0')", "Salir"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(Text(f.renderText("Anchor Port"), style="bold #d9766a"),
                     id="banner")
        with Horizontal(id="fila"):
            yield Static(Text(ELISA_ASCII, style="#d9766a"), id="logo")
            menu = OptionList(id="menu")
            for key, nombre, desc in OPCIONES:
                etiqueta = Text.assemble(
                    (f" {key}  ", "bold"), (nombre, "bold"),
                    ("\n     " + desc, "dim"),
                )
                menu.add_option(Option(etiqueta, id=key))
            yield menu
        yield Static(
            Text.assemble(
                ("SO ", "dim"), (machine, "bold"),
                ("    IP ", "dim"), (_ip_default, "#d9766a"),
                ("    gateway ", "dim"), (get_gateway_ip(), "#d9766a"),
            ),
            id="info",
        )
        yield Footer()

    def on_mount(self) -> None:
        menu = self.query_one(OptionList)
        menu.border_title = "¿Qué quieres hacer?"
        menu.focus()

    def action_mover(self, paso: int) -> None:
        menu = self.query_one(OptionList)
        if paso > 0:
            menu.action_cursor_down()
        else:
            menu.action_cursor_up()

    def action_elegir(self, key: str) -> None:
        self.exit(key)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.exit(event.option.id)


def _aviso_arp(console, error) -> None:
    """Mensaje claro cuando scapy no puede usar ARP (típico: falta Npcap)."""
    console.print(f"\n[red]No se pudo iniciar el control de red:[/] {error}\n")
    console.print(
        "[bold yellow]Causa más probable en Windows:[/] falta [bold]Npcap[/].\n"
        "  1. Descárgalo de https://npcap.com\n"
        "  2. Instálalo marcando [cyan]\"WinPcap API-compatible mode\"[/]\n"
        "  3. Abre esta terminal como [bold]Administrador[/] y reintenta.\n"
        "En Linux: ejecuta con [bold]sudo[/].\n"
    )
    input("Enter para volver al menú...")


def main() -> None:
    console = Console()
    while True:
        try:
            opcion = MenuApp().run()
        except KeyboardInterrupt:
            break
        if not opcion or opcion == "0":
            break
        if opcion == "1":
            from tui import AnchorTUI
            AnchorTUI().run()
        elif opcion == "2":
            try:
                from dns_monitor import DNSMonitor
                DNSMonitor().run()
            except RuntimeError as e:
                _aviso_arp(console, e)
        elif opcion == "3":
            escaneo_detallado()


if __name__ == "__main__":
    main()
