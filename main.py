import subprocess
import nmap
from colorama import Fore
from printt import formatter
import sys
import numpy as np
from fonts import f
from get_host import _ip_default, get_addr_localhost, get_addr_gateway

machine: str = sys.platform.title()


print(f.renderText("Scanner Ports"))
print(Fore.BLUE + f"Sistema operativo ${machine}")
print(f"Ip local ${_ip_default}")


def opcion_1(ip : str ) -> None:
    print(Fore.GREEN + f"=========== Escaneando [{ip}] =============")
    scan = nmap.PortScanner()
    scaneo = scan.scan(hosts=f"{ip}/24", arguments="-O ", sudo=True)
    array = scaneo.get("scan")
    formatter(escaneo=array)
    dispositivos_actuales: int = len(scaneo.get("scan").keys())
    print(f"Dispositivos Conectados a la red : [{dispositivos_actuales}]")

    for item in array.items():
        print("\n ==========================================")
        print(f"Nmap Version: {scan.nmap_version()}")
        print(f"Direccion IP: {item[0]}")
        print(
            f"Nombre {item[1]['hostnames'][0]['name']} Type {item[1]['hostnames'][0]['type']}"
        )
        print(f"ipv4: {item[1]['addresses']['ipv4']}")
        print(f"Status : {item[1]['status']['state']}")
        
        print(item[1]["osmatch"][0]["name"] if len(item[1]["osmatch"]) > 0 else "No se encontro el sistema")
        print(item[1]["portused"] if len(item[1]["portused"]) > 0 else "No hay puertos abiertos o en uso")
        

    
## nmap -p- -O -sV <ip>

def opcion_3 () -> None:
    ip = get_addr_localhost()
    nm = nmap.PortScanner()
    resultado = nm.scan(hosts=ip, sudo=True,arguments="-p-",)
    print(resultado["nmap"]["scanstats"]["timestr"])
    print(f"Tiempo de respuesta {resultado['nmap']['scanstats']['elapsed']}")
    ports : list = list(resultado["scan"][ip]["tcp"].keys())
    print(f"Puerto {ports} tcp: {resultado['scan'][ip]["tcp"][ports[0]]["state"]}")
    formatter(ports[0])


def opcion_4 (machine:str) -> None:
    nm = nmap.PortScanner()
    input_comand = str(input(f"-> $[{machine}] :: "))
    array_input_comand = np.array(input_comand.split(" "))
    print(nm.scan(hosts=str(array_input_comand[-1]),arguments=str(array_input_comand[1:-1]),sudo=True))
    print(nm.all_hosts())


## Flujo normal del codigo
def main(machine:str) -> None:
    print(
        Fore.GREEN
        + f"1. Escaneo masivo de la red [route] : \n2. Escanear una red con un puerto especifico \n3. Escanear todos los  puertos [localhost ${machine} ]  \n4. Escaneo personalizado  \n5. Ver la cantidad de dispositivos en mi red \n6. Ver sistemas operativos de la red"
    )
    opciones = int(input(f" [${machine}] :: "))
    try:
        match opciones:
            case 1:
                ip = get_addr_gateway()
                opcion_1(ip=ip)
            case 2:
                print("Escaneando la red con un puerto en especifico.")
            case 3:
                opcion_3()
            case 4:
                opcion_4(machine=machine)
            case 5:
                nm = nmap.PortScanner()
                ip : str =f"{get_addr_gateway()}/24"
                nm.scan(hosts=ip)
                dispositivos : int= len(nm.all_hosts())
                cont: int = 0
                print(f"Dispositivo totales --> {dispositivos}")
                for host in nm.all_hosts():
                    cont = cont + 1
                    print(f"{ host} Dispositivo  --> {cont}")
            case 6:
                pass
                
    except KeyboardInterrupt:
        response = input("Estas seguro que deseas salir  \n [] :: ")
        match response:
            case "y":
                sys.exit()
    else:
        print("Escaneo ejecutado con exito  ☕ ")


if __name__ == "__main__":
    try:
        main(machine=machine)
    except KeyboardInterrupt:
        sys.exit()
