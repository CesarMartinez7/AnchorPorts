import sys
from os import system
from time import sleep

import nmap
from colorama import Fore
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from fonts import f
from get_host import _ip_default
from net import get_local_ip

machine: str = sys.platform.title()


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


def main(console) -> None:
    menu = Panel(
        """
        [bold green]1.[/] Panel de control en vivo  (ver · bloquear · expulsar)
        [bold green]2.[/] Monitorear dominios de la red (DNS)
        [bold green]3.[/] Escaneo detallado (puertos y sistema operativo)
        [bold green]0.[/] Salir
        """,
        title="AnchorPort — todo automático, sin escribir IPs",
        expand=False,
    )
    console.print(menu)
    try:
        opcion = int(input(f" [{machine}] :: "))
    except ValueError:
        return

    match opcion:
        case 1:
            from dashboard import Dashboard
            Dashboard().run()
        case 2:
            from dns_monitor import DNSMonitor
            DNSMonitor().run()
        case 3:
            escaneo_detallado()
        case 0:
            sys.exit()


if __name__ == "__main__":
    while True:
        try:
            console = Console()
            print(f.renderText("Anchor Port"), end="\n")
            print(Fore.BLUE + f"Sistema operativo: {machine}")
            print(f"IP local/pública: {_ip_default}")
            main(console=console)
        except KeyboardInterrupt:
            sys.exit()
