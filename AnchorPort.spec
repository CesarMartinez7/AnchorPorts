# -*- mode: python ; coding: utf-8 -*-
"""Receta de empaquetado de AnchorPort en un ejecutable único.

Construir con:   pyinstaller AnchorPort.spec
Resultado:       dist/AnchorPort.exe  (Windows)  /  dist/AnchorPort (Linux)

Nota: Npcap (Windows) o permisos root (Linux) y, para el escaneo detallado,
el binario `nmap`, NO se empaquetan: son dependencias externas del sistema.
"""
from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], []
# Paquetes con datos/imports dinámicos que hay que recolectar completos.
for paquete in ("textual", "pyfiglet", "rich", "scapy"):
    d, b, h = collect_all(paquete)
    datas += d
    binaries += b
    hiddenimports += h

# Módulos locales que se importan de forma diferida dentro de funciones.
hiddenimports += [
    "tui", "dns_monitor", "arp_manager", "registry", "net",
    "get_host", "logo", "fonts", "nmap",
]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="AnchorPort",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=True,          # app de terminal (TUI)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets/elisa.ico",   # carita de la mascota Elisa
)
