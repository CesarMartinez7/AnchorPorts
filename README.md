# Anchor Port

Anchor Port es una herramienta para **administrar tu propia red local**: ver qué
dispositivos están conectados, bloquearlos/expulsarlos y monitorear a qué
dominios acceden. Usa `python-nmap` para escanear y `scapy` para el control por
ARP. Todo es automático desde tablas: **no hay que escribir direcciones IP a mano.**

> ⚠️ Úsalo solo en una red que posees o administras. Hacer ARP spoofing o
> inspeccionar tráfico en una red ajena es ilegal en la mayoría de países.

## Menú

1. **Panel de control en vivo** — tabla automática de dispositivos; escribes el
   número de uno para bloquearlo/expulsarlo o desbloquearlo.
2. **Monitorear dominios (DNS)** — descubre toda la red sola y muestra a qué
   dominios accede cada dispositivo.
3. **Escaneo detallado** — puertos y sistema operativo de cada dispositivo.
0. Salir (restaura las tablas ARP de la red).

## Requisitos

- **Permisos de administrador / root** (scapy envía paquetes en capa 2).
- **Windows:** instalar [Npcap](https://npcap.com) con *"WinPcap API-compatible
  mode"*. El monitoreo además necesita el servicio RemoteAccess para IP forwarding.
- **Linux:** correr como root; funciona directo.

## Instalación

```bash
python3 -m venv entorno
source entorno/bin/activate        # Windows: entorno\Scripts\activate
pip install -r requerimentos.txt
```

## Ejecución

```bash
# Linux/macOS
sudo python3 main.py

# Windows (terminal como Administrador)
python main.py
```

## Compilar a un ejecutable (.exe)

Para usarlo en otra máquina sin instalar Python:

```bash
pip install pyinstaller
pyinstaller AnchorPort.spec
```

Queda en `dist/AnchorPort.exe` (Windows) o `dist/AnchorPort` (Linux). Se ejecuta
como **Administrador/root**.

**Importante — dependencias externas que NO van dentro del ejecutable:**

- **Npcap** (Windows) o permisos **root** (Linux): obligatorio para enviar/recibir
  ARP y capturar DNS. El `.exe` lo necesita instalado en la máquina destino.
- **nmap**: solo para el "Escaneo detallado" (opción 3) y los puertos/SO del
  detalle. Si no está instalado, el resto funciona igual.
- **IP forwarding real** (root/Linux) para capturar DNS de otros equipos sin
  cortarles la red.
