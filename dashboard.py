"""Panel de control en vivo: ver, bloquear y expulsar dispositivos.

Junta el escaneo ARP de la red, el registro persistente y el BlockManager en
una sola tabla interactiva. Es la vista de "quién puede conectarse y quién no".

Solo para tu propia red.
"""
from __future__ import annotations

import threading
import time

from rich.console import Console
from rich.live import Live
from rich.prompt import Prompt
from rich.table import Table
from scapy.all import ARP, Ether, srp

from arp_manager import BlockManager
from net import get_gateway_ip, get_local_ip
from registry import Registry


def scan_network(gateway_ip: str, timeout: float = 2.0) -> list[tuple[str, str]]:
    """Barrido ARP del /24. Devuelve [(ip, mac), ...] de los que respondan."""
    red = gateway_ip.rsplit(".", 1)[0] + ".0/24"
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=red),
        timeout=timeout,
        verbose=0,
    )
    return [(rcv.psrc, rcv.hwsrc) for _snt, rcv in ans]


def _ago(ts: float) -> str:
    d = int(time.time() - ts)
    if d < 60:
        return f"{d}s"
    if d < 3600:
        return f"{d // 60}m"
    return f"{d // 3600}h"


class Dashboard:
    def __init__(self):
        self.console = Console()
        self.gateway_ip = get_gateway_ip()
        self.local_ip = get_local_ip()
        self.registry = Registry()
        self.manager = BlockManager(self.gateway_ip)
        self._stop = threading.Event()

    def _scan_loop(self, every: float = 10.0) -> None:
        """Escanea en segundo plano y actualiza el registro."""
        while not self._stop.is_set():
            for ip, mac in scan_network(self.gateway_ip):
                self.registry.seen(mac, ip)
            self._stop.wait(every)

    def render(self) -> Table:
        table = Table(
            title=f"AnchorPort — Gateway {self.gateway_ip} · Local {self.local_ip}"
        )
        table.add_column("#", justify="right", style="dim")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="blue")
        table.add_column("Hostname", style="white")
        table.add_column("Estado", justify="center")
        table.add_column("Visto", justify="right", style="dim")

        for i, dev in enumerate(self.registry.all(), 1):
            blocked = self.manager.is_blocked(dev.ip)
            estado = "[red]🔴 bloqueado[/]" if blocked else "[green]🟢 permitido[/]"
            es_tu_router = dev.ip in (self.gateway_ip, self.local_ip)
            table.add_row(
                str(i),
                dev.ip + (" [dim](tú/router)[/]" if es_tu_router else ""),
                dev.mac,
                dev.hostname or "—",
                estado,
                _ago(dev.last_seen),
            )
        return table

    def toggle(self, index: int) -> None:
        """Bloquea o desbloquea el dispositivo nº `index` de la tabla."""
        devices = self.registry.all()
        if not 1 <= index <= len(devices):
            return
        dev = devices[index - 1]
        if dev.ip in (self.gateway_ip, self.local_ip):
            self.console.print("[yellow]No vas a bloquearte a ti/al router.[/]")
            return
        if self.manager.is_blocked(dev.ip):
            self.manager.unblock(dev.ip)
            self.registry.set_status(dev.mac, "allowed")
        else:
            if self.manager.block(dev.ip):
                self.registry.set_status(dev.mac, "blocked")

    def run(self) -> None:
        scanner = threading.Thread(target=self._scan_loop, daemon=True)
        scanner.start()
        self.console.print(
            "[bold]Comandos:[/] número = bloquear/desbloquear · "
            "[cyan]r[/] refrescar · [cyan]q[/] salir y restaurar todo"
        )
        try:
            while True:
                with Live(self.render(), console=self.console, refresh_per_second=2):
                    time.sleep(2)
                cmd = Prompt.ask("AnchorPort", default="r").strip().lower()
                if cmd == "q":
                    break
                if cmd.isdigit():
                    self.toggle(int(cmd))
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self._stop.set()
        self.console.print("[yellow]Restaurando tablas ARP de la red...[/]")
        self.manager.unblock_all()
        self.registry.close()
        self.console.print("[green]Listo.[/]")


if __name__ == "__main__":
    Dashboard().run()
