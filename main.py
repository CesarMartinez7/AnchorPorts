import nmap 
import socket
import sys
import subprocess
from fonts import f

def get_ip_for_machine() -> dict[str]:
    print(sys.platform)
    if(sys.platform == "linux"):
        resultado = subprocess.run(args=["curl", "ifconfig.me"],capture_output=True)
        print(resultado.stdout)
        ip = resultado
    elif(sys.platform == "win32"):
        print("Equivo macOS")
    elif(sys.platform == "darwin"):
        print("Equipo de macOS")
    return {"output" : ip.stdout,"status_code" : ip.returncode} 

machine: str = sys.platform

print(f"Maquina ${machine}")
print(f"Ip local ${get_ip_for_machine()}")





print(f.renderText('Scanner Port'))





resultado = get_ip_for_machine()

# Obteners el array de valores que tiene los valores, el codigo de estado y la ip sacada de curl
print(f"{resultado.values()}")

## Obtener ip por medio de socket 
def get_ip() -> str:
    ip : str = socket.gethostbyname(socket.gethostname())
    print(f"Se obtuvo la siguiente : [{ip}]")
    return ip



## Flujo normal del codigo
def main (machine):
    print("1. Escaner todo la red actual : \n2. Escanear una red con un puerto especifico \n3. Escanear una red total \n4. Escaneo personalizado [command-line] \n5. Ver la cantidad de dispositivos en mi red")
    opciones = int(input(f"[${machine}] :: "))
    try:
        if(opciones == 1):
            ip = get_ip()
            scan = nmap.PortScanner()
            scaneo = scan.scan(hosts=ip, arguments="-p 1-65535")
            print(scaneo)
        elif(opciones == 2):
            print("Escaneando la red con un puerto en especifico")
        elif (opciones == 3):
            print("Escaner diferentes tipos de red")
        elif(opciones == 4):
            scan_input  = input("Input de su escaneo []: ")
            scan.command_line(scan_input)
    except Exception as e:
        print(f" Error: {e} ")
    else:
        print("Escaneo completado con exito ☕ ")


if __name__ == "__main__":
    main(machine=machine)

