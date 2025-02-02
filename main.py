import subprocess
import nmap
from colorama import Fore

from printt import formatter
import sys
from fonts import f
from get_host import _ip_default, get_addr_localhost, get_addr_gateway

machine: str = sys.platform


print(f.renderText("Scanner Ports"))
print(Fore.BLUE + f"Sistema operativo ${machine}")
print(f"Ip local ${_ip_default}")


def opcion_1(ip) -> None:
    print(Fore.GREEN + f"=========== Scaneo [{ip}] =============")
    scan = nmap.PortScanner()
    scaneo = scan.scan(hosts=f"{ip}/24", arguments="-O ", sudo=True)
    array = scaneo.get("scan")
    dispositivos_actuales: int = len(scaneo.get("scan").keys())
    print(f"Dispositivos Conectados a la red : [{dispositivos_actuales}]")

    for item in array.items():
        print("==========================================")
        print(f"Direccion IP: {item[0]}")
        print(
            f"Detalles {item[1]['hostnames'][0]['name']} Type {item[1]['hostnames'][0]['type']}"
        )
        print(f"ipv4: {item[1]['addresses']['ipv4']}")
        print(f"Status : {item[1]['status']['state']}")
        
        print(item[1]["portused"] if len(item[1]["portused"]) > 0 else "No hay puertos abiertos o en uso")
        


def opcion_2():
    pass


## Flujo normal del codigo
def main(machine: str) -> None:
    print(
        Fore.GREEN
        + f"1. Escaneo masivo de la red [route] : \n2. Escanear una red con un puerto especifico \n3. Escanear todos los  puertos [localhost ${machine} ]  \n4. Escaneo personalizado  \n5. Ver la cantidad de dispositivos en mi red"
    )
    opciones = int(input(f" [${machine}] :: "))
    try:
        if opciones == 1:
            ip = get_addr_gateway()
            opcion_1(ip=ip)
        elif opciones == 2:
            print("Escaneando la red con un puerto en especifico.")
        elif opciones == 3:
            ip = get_addr_localhost()
            nm = nmap.PortScanner()
            resultado = nm.scan(hosts=ip, sudo=True)
            print(resultado)
        elif opciones == 4:
            input_comand = str(input("Comando [] :: "))
            subprocess.run(
                args=["nmap", input_comand],
                capture_output=True,
                stdout=True,
                check=True,
            )
    except KeyboardInterrupt:
        response = input("Estas seguro que deseas salir  \n [] :: ")
        match response:
            case "y":
                sys.exit()
    else:
        print("Escaneo completado con exito ☕ ")


if __name__ == "__main__":
    main(machine=machine)
