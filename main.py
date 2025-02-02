import subprocess
import nmap 
import socket
from printt import (formatter)
import sys
from fonts import f
from get_host import (_ip_default,get_addr_localhost,get_addr_gateway)

machine: str = sys.platform


print(f"Maquina o sistema operativo ${machine}")
print(f"Ip local ${_ip_default}")
print(f.renderText('Scanner Ports'))






## Flujo normal del codigo
def main (machine):
    print(f"1. Escaneo masivo de la red [route] : \n2. Escanear una red con un puerto especifico \n3. Escanear todos los  puertos [localhost ${machine} ]  \n4. Escaneo personalizado  \n5. Ver la cantidad de dispositivos en mi red")
    opciones = int(input(f"[${machine}] :: "))
    try:
        if(opciones == 1):
            ip = get_addr_gateway()
            print(f"=======Scaneo [{ip}]=======")
            scan = nmap.PortScanner()
            scaneo = scan.scan(hosts=f"{ip}/24", arguments="-O ",sudo=True)
            formatter(escaneo=scaneo)
        elif(opciones == 2):
            print("Escaneando la red con un puerto en especifico")
        elif (opciones == 3):
            ip = get_addr_localhost()
            nm = nmap.PortScanner()
            resultado = nm.scan(hosts=ip, sudo=True)
            print(resultado)
        elif(opciones == 4):
            input_comand = str(input("Comando [] :: "))
            subprocess.run(args=["nmap", input_comand],capture_output=True, stdout=True,check=True)
    except KeyboardInterrupt:
        response = input("Estas seguro que deseas salir  \n [] :: ")
        match response:
            case "y": 
                sys.exit() 
    else:
        print("Escaneo completado con exito ☕ ")


if __name__ == "__main__":
    main(machine=machine)

