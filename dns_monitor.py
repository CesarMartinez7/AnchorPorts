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

from rich.console import Console
from rich.live import Live
from rich.table import Table
from scapy.all import DNSQR, IP, sniff

from arp_manager import BlockManager
from net import get_gateway_ip, get_local_ip, set_ip_forwarding
from registry import Registry


def scan_network(gateway_ip: str, timeout: float = 2.0) -> list[tuple[str, str]]:
    """Barrido ARP del /24. Devuelve [(ip, mac), ...]."""
    from scapy.all import ARP, Ether, srp

    red = gateway_ip.rsplit(".", 1)[0] + ".0/24"
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=red),
        timeout=timeout, verbose=0,
    )
    return [(rcv.psrc, rcv.hwsrc) for _snt, rcv in ans]


class DNSMonitor:
    def __init__(self):
        self.console = Console()
        self.gateway_ip = get_gateway_ip()
        self.local_ip = get_local_ip()
        self.registry = Registry()
        self.manager = BlockManager(self.gateway_ip)
        self._stop = threading.Event()
        self.monitored: set[str] = set()
        # ip -> {dominio: (conteo, ultima_vez)}
        self.log: dict[str, dict[str, tuple[int, float]]] = defaultdict(dict)
        self._forwarding_ok = False

    def _discover_loop(self, every: float = 15.0) -> None:
        """Descubre dispositivos y empieza a redirigirlos automáticamente."""
        while not self._stop.is_set():
            for ip, mac in scan_network(self.gateway_ip):
                if ip in (self.gateway_ip, self.local_ip):
                    continue
                self.registry.seen(mac, ip)
                if ip not in self.monitored and self.manager.block(ip):
                    # block() aquí = redirigir, porque forwarding está ON
                    self.monitored.add(ip)
            self._stop.wait(every)

    def _on_packet(self, pkt) -> None:
        if not pkt.haslayer(DNSQR) or not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        if src not in self.monitored:
            return
        try:
            dominio = pkt[DNSQR].qname.decode().rstrip(".")
        except Exception:
            return
        prev = self.log[src].get(dominio, (0, 0.0))
        self.log[src][dominio] = (prev[0] + 1, time.time())

    def _sniff_loop(self) -> None:
        sniff(
            filter="udp port 53", prn=self._on_packet, store=0,
            stop_filter=lambda _: self._stop.is_set(),
        )

    def _hostname(self, ip: str) -> str:
        dev = next((d for d in self.registry.all() if d.ip == ip), None)
        return dev.hostname if dev and dev.hostname else ip

    def render(self) -> Table:
        table = Table(
            title=f"Dominios por dispositivo (DNS) — {len(self.monitored)} monitoreados"
        )
        table.add_column("Dispositivo", style="cyan")
        table.add_column("Dominio", style="white")
        table.add_column("Veces", justify="right", style="magenta")
        table.add_column("Última", justify="right", style="dim")

        if not self.monitored:
            table.add_row("[dim]buscando dispositivos...[/]", "", "", "")
            return table

        for ip in sorted(self.monitored):
            dominios = sorted(
                self.log[ip].items(), key=lambda kv: kv[1][1], reverse=True
            )
            etiqueta = self._hostname(ip)
            if not dominios:
                table.add_row(etiqueta, "[dim]— sin consultas aún —[/]", "", "")
                continue
            for i, (dom, (cnt, ts)) in enumerate(dominios[:10]):
                table.add_row(
                    etiqueta if i == 0 else "",
                    dom, str(cnt), f"{int(time.time() - ts)}s",
                )
        return table

    def run(self) -> None:
        self._forwarding_ok = set_ip_forwarding(True)
        if not self._forwarding_ok:
            self.console.print(
                "[yellow]Aviso:[/] no se pudo activar IP forwarding (en Windows "
                "necesita admin + servicio RemoteAccess). Sin él los dispositivos "
                "podrían quedarse sin Internet mientras monitoreas. En Linux, root."
            )
        threading.Thread(target=self._discover_loop, daemon=True).start()
        threading.Thread(target=self._sniff_loop, daemon=True).start()
        self.console.print("Monitoreando toda la red. Ctrl+C para detener y restaurar.\n")
        try:
            with Live(self.render(), console=self.console, refresh_per_second=1) as live:
                while not self._stop.is_set():
                    time.sleep(1)
                    live.update(self.render())
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self._stop.set()
        self.console.print("\n[yellow]Restaurando red y apagando forwarding...[/]")
        self.manager.unblock_all()
        if self._forwarding_ok:
            set_ip_forwarding(False)
        self.registry.close()
        self.console.print("[green]Listo.[/]")


if __name__ == "__main__":
    DNSMonitor().run()
