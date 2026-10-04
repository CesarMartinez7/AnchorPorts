"""Helpers de IP (compatibles con el código existente de main.py).

Se apoya en net.py para la lógica real. Mantiene los nombres que main.py
importa: _ip_default, get_addr_localhost, get_addr_gateway.
"""
from __future__ import annotations

import socket
import subprocess
import sys

from net import get_local_ip


def get_ip_for_machine() -> dict:
    """IP pública del equipo. Cae a la IP local si no hay salida a Internet."""
    try:
        if sys.platform.startswith("linux") or sys.platform == "darwin":
            resultado = subprocess.run(
                ["curl", "-s", "ifconfig.me"],
                capture_output=True, text=True, check=True, timeout=5,
            )
            return {"output": resultado.stdout.strip(),
                    "status_code": resultado.returncode}
        if sys.platform == "win32":
            resultado = subprocess.run(
                ["curl", "-s", "ifconfig.me"],
                capture_output=True, text=True, timeout=5,
            )
            if resultado.returncode == 0 and resultado.stdout.strip():
                return {"output": resultado.stdout.strip(), "status_code": 0}
    except Exception:
        pass
    # Fallback: IP local, siempre disponible y sin crashear.
    return {"output": get_local_ip(), "status_code": -1}


def get_addr_localhost() -> str:
    return socket.gethostbyname(socket.gethostname())


# IP de la subred local; main.py la usa con /24 para escanear la red.
def get_addr_gateway() -> str:
    return get_local_ip()


_ip_default: str = str(get_ip_for_machine().get("output", "output"))


if __name__ == "__main__":
    print("IP pública/local:", _ip_default)
    print("localhost       :", get_addr_localhost())
    print("subred          :", get_addr_gateway())
