"""Utilidades de red: detección de gateway, interfaz y MACs.

Reemplaza los helpers rotos de get_host.py (get_addr_gateway devolvía la IP
local, no la del gateway). Usa scapy, que ya es dependencia del proyecto, para
no añadir nada nuevo.
"""
from __future__ import annotations

import logging
import socket
import subprocess
import sys
import warnings

# Silenciar scapy ANTES de importarlo: evita que su "WARNING: No libpcap..."
# y los resúmenes de paquetes se cuelen por encima del panel y lo descuadren.
logging.getLogger("scapy").setLevel(logging.CRITICAL)
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
warnings.filterwarnings("ignore")

from scapy.all import (
    ARP,
    ICMPv6EchoRequest,
    IPv6,
    Ether,
    conf,
    get_if_hwaddr,
    srp,
)

conf.verb = 0  # nada de salida por defecto al enviar/recibir


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


def get_vendor(mac: str | None) -> str:
    """Fabricante del dispositivo a partir del OUI de su MAC."""
    if not mac:
        return "—"
    try:
        v = conf.manufdb._get_manuf(mac)
        # Si no lo conoce, scapy devuelve la propia MAC: lo tratamos como desconocido.
        return "—" if not v or v.lower() == mac.lower() else v
    except Exception:
        return "—"


def reverse_dns(ip: str) -> str:
    """Nombre del host por DNS inverso; '' si no resuelve."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


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


def get_ipv6_gateway() -> str | None:
    """IPv6 (link-local) del router por defecto, o None si no hay IPv6."""
    try:
        _iface, _src, nh = conf.route6.route("2001:4860:4860::8888")
        if nh and nh not in ("::", ""):
            return nh
    except Exception:
        pass
    return None


def discover_ipv6(mac: str, timeout: float = 3.0) -> str | None:
    """Descubre la IPv6 link-local de un dispositivo por su MAC.

    Hace ping ICMPv6 al multicast de todos los nodos (ff02::1) y empareja la
    respuesta cuya MAC de origen coincide con la del dispositivo.
    """
    if not mac:
        return None
    try:
        ans, _ = srp(
            Ether(dst="33:33:00:00:00:01")
            / IPv6(dst="ff02::1")
            / ICMPv6EchoRequest(),
            timeout=timeout, verbose=0,
        )
        for _sent, rcv in ans:
            if rcv[Ether].src.lower() == mac.lower():
                return rcv[IPv6].src
    except Exception:
        pass
    return None


def ip_forwarding_enabled() -> bool | None:
    """¿Está el IP forwarding REALMENTE activo ahora mismo?

    True/False cuando se puede leer el estado (Linux/macOS). None cuando no se
    puede confirmar (Windows: IPEnableRouter no surte efecto hasta reiniciar).
    Sirve para NO envenenar/redirigir si no hay forwarding, y así no cortar la
    red de los dispositivos.
    """
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/sys/net/ipv4/ip_forward") as fh:
                return fh.read().strip() == "1"
        if sys.platform == "darwin":
            out = subprocess.run(
                ["sysctl", "-n", "net.inet.ip.forwarding"],
                capture_output=True, text=True, check=True,
            )
            return out.stdout.strip() == "1"
    except Exception:
        return None
    return None  # Windows u otros: no se puede confirmar


if __name__ == "__main__":
    print("IP local :", get_local_ip())
    print("Gateway  :", get_gateway_ip())
    print("MAC prop.:", get_own_mac())
    print("Forwarding activo:", ip_forwarding_enabled())
