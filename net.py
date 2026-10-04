"""Utilidades de red: detección de gateway, interfaz y MACs.

Reemplaza los helpers rotos de get_host.py (get_addr_gateway devolvía la IP
local, no la del gateway). Usa scapy, que ya es dependencia del proyecto, para
no añadir nada nuevo.
"""
from __future__ import annotations

import socket
import subprocess
import sys

from scapy.all import ARP, Ether, conf, get_if_hwaddr, srp


def get_local_ip() -> str:
    """IP local con la que el equipo sale a Internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def get_default_route() -> tuple[str, str, str]:
    """Devuelve (interfaz, ip_origen, ip_gateway) de la ruta por defecto."""
    iface, src_ip, gateway = conf.route.route("0.0.0.0")
    return iface, src_ip, gateway


def get_gateway_ip() -> str:
    """IP real del gateway (router). ESTO es lo que get_host.py no hacía."""
    return get_default_route()[2]


def get_mac(ip: str, timeout: float = 2.0, retry: int = 2) -> str | None:
    """Resuelve la MAC de una IP con un ARP request (más fiable que getmacbyip)."""
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=timeout,
            retry=retry,
            verbose=0,
        )
        for _sent, received in ans:
            return received.hwsrc
    except Exception:
        pass
    return None


def scan_network(gateway_ip: str, timeout: float = 2.0) -> list[tuple[str, str]]:
    """Barrido ARP del /24. Devuelve [(ip, mac), ...] de quien responda."""
    red = gateway_ip.rsplit(".", 1)[0] + ".0/24"
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=red),
        timeout=timeout, verbose=0,
    )
    return [(rcv.psrc, rcv.hwsrc) for _snt, rcv in ans]


def get_own_mac() -> str:
    """MAC de nuestra interfaz de salida."""
    iface = get_default_route()[0]
    return get_if_hwaddr(iface)


def set_ip_forwarding(enable: bool) -> bool:
    """Activa/desactiva el reenvío de paquetes del SO.

    Necesario para MONITOREAR (que el tráfico pase por nosotros hacia el
    gateway). Sin esto, el envenenamiento ARP corta la conexión en vez de
    dejarla fluir. Devuelve True si cree haberlo logrado.
    """
    val = "1" if enable else "0"
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
                fh.write(val + "\n")
            return True
        if sys.platform == "darwin":
            subprocess.run(
                ["sysctl", "-w", f"net.inet.ip.forwarding={val}"], check=True
            )
            return True
        if sys.platform == "win32":
            # Windows: requiere la clave de registro + servicio RemoteAccess.
            subprocess.run(
                ["reg", "add",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouter", "/t", "REG_DWORD",
                 "/d", val, "/f"],
                check=True, capture_output=True,
            )
            action = "start" if enable else "stop"
            subprocess.run(["sc", action, "RemoteAccess"],
                           capture_output=True, check=False)
            return True
    except Exception:
        return False
    return False


if __name__ == "__main__":
    print("IP local :", get_local_ip())
    print("Gateway  :", get_gateway_ip())
    print("MAC prop.:", get_own_mac())
