import sys
from os import system
from time import sleep

import nmap
from colorama import Fore
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from fonts import f
from get_host import _ip_default
from logo import ELISA_ASCII, ELISA_COLOR
from net import get_gateway_ip, get_local_ip

machine: str = sys.platform.title()
SALMON = ELISA_COLOR  # #d9766a, el color de la mascota

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


def render_inicio(console) -> None:
    """Dibuja la pantalla de inicio: banner, logo y menú de opciones."""
    clear_console()

    banner = Text(f.renderText("Anchor Port"), style=f"bold {SALMON}")
    console.print(Align.center(banner))

    logo = Text(ELISA_ASCII, style=SALMON, justify="center")

    opciones = Table.grid(padding=(0, 2))
    opciones.add_column(justify="center")
    opciones.add_column(justify="left")
    for key, nombre, desc in OPCIONES:
        opciones.add_row(
            Text(f" {key} ", style=f"bold white on {SALMON}"),
            Text.assemble((nombre + "\n", "bold"), (desc, "dim")),
        )
    panel = Panel(
        opciones,
        title="[bold]¿Qué quieres hacer?[/]",
        subtitle="[dim]todo automático · sin escribir IPs[/]",
        border_style=SALMON,
        padding=(1, 2),
    )

    console.print(Columns([logo, panel], padding=(0, 4), align="center"))
    console.print(
        Align.center(
            Text.assemble(
                ("SO ", "dim"), (f"{machine}", "bold"),
                ("    IP ", "dim"), (f"{_ip_default}", SALMON),
                ("    gateway ", "dim"), (get_gateway_ip(), SALMON),
            )
        )
    )


def main(console) -> None:
    render_inicio(console)
    try:
        entrada = console.input(
            f"\n  [bold {SALMON}]>[/] Elige una opción [dim](0-3)[/]: "
        ).strip()
        opcion = int(entrada)
    except ValueError:
        return

    match opcion:
        case 1:
            from tui import AnchorTUI
            AnchorTUI().run()
        case 2:
            try:
                from dns_monitor import DNSMonitor
                DNSMonitor().run()
            except RuntimeError as e:
                _aviso_arp(console, e)
        case 3:
            escaneo_detallado()
        case 0:
            sys.exit()


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


if __name__ == "__main__":
    console = Console()
    while True:
        try:
            main(console=console)
        except KeyboardInterrupt:
            sys.exit()
