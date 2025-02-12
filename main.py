import subprocess
import nmap
from colorama import Fore
from printt import formatter
import sys
from rich.panel import Panel
import numpy as np
from fonts import f
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
from time import sleep
from rich.progress import Progress
from get_host import _ip_default, get_addr_localhost, get_addr_gateway
from script import bloquear_trafico

machine: str = sys.platform.title()
from os import system


def clear_console():
    if sys.platform.lower() == "linux" or sys.platform.lower() == "linux2":
        system("clear")
    elif sys.platform.upper() == "win32" or "cygwin":
        system("cls")



def opcion_1(ip: str) -> None:
    clear_console()
    console = Console()
    print(Fore.GREEN + f"=========== Escaneando [{ip}] =============")
    scan = nmap.PortScanner()

    scaneo = scan.scan(hosts=f"{ip}/24", arguments="-O ", sudo=True)
    array = scaneo.get("scan")
    dispositivos_actuales: int = len(array.keys())

    
    for item in array.items():
        table = Table(title=f"Información del dispositivo {item[0]} -- Dispositivos Totales Conectados [{dispositivos_actuales}]")
        table.add_column("Atributo", style="cyan", justify="left")
        table.add_column("Valor", style="magenta", justify="left")

        table.add_row("Nmap Version", str(scan.nmap_version()))
        table.add_row("Direccion IP", item[0])
        table.add_row("Nombre", item[1]["hostnames"][0]["name"])
        table.add_row("Tipo", item[1]["hostnames"][0]["type"])
        table.add_row("IPv4", item[1]["addresses"]["ipv4"])
        table.add_row("Status", item[1]["status"]["state"])
        table.add_row(
            "Sistema",
            item[1]["osmatch"][0]["name"]
            if len(item[1]["osmatch"]) > 0
            else "No se encontro el sistema",
        )
        table.add_row(
            "Puertos",
            str(item[1]["portused"])
            if len(item[1]["portused"]) > 0
            else "No hay puertos abiertos o en uso",
        )

        console.print(table)
        print("Espera ...")
        sleep(1.5)


## nmap -p- -O -sV <ip>


def opcion_3() -> None:
    clear_console()
    ip = get_addr_localhost()
    nm = nmap.PortScanner()
    resultado = nm.scan(
        hosts=ip,
        sudo=True,
        arguments="-p-",
    )
    print(resultado["nmap"]["scanstats"]["timestr"])
    print(f"Tiempo de respuesta {resultado['nmap']['scanstats']['elapsed']}")
    ports: list = list(resultado["scan"][ip]["tcp"].keys())
    print(f"Puerto {ports} tcp: {resultado['scan'][ip]['tcp'][ports[0]]['state']}")
    formatter(ports[0])


def opcion_4(machine: str) -> None:
    clear_console()
    nm = nmap.PortScanner()
    input_comand = str(input(f"-> $[{machine}] :: "))
    array_input_comand = np.array(input_comand.split(" "))
    print(
        nm.scan(
            hosts=str(array_input_comand[-1]),
            arguments=str(array_input_comand[1:-1]),
            sudo=True,
        )
    )
    print(nm.all_hosts())


## Flujo normal del codigo
def main(machine: str, console) -> None:
    menu = Panel(
        """
        [bold green]1.[/] Escaneo masivo de la red [route]
        [bold green]2.[/] Escanear una red con un puerto especifico
        [bold green]3.[/] Escanear todos los puertos [localhost ${machine}]
        [bold green]4.[/] Escaneo personalizado
        [bold green]5.[/] Ver la cantidad de dispositivos en mi red
        [bold green]6.[/] Ver sistemas operativos de la red
        [bold green]7.[/] Terminar el trafico en un host local
        """,
        title="Opciones de Escaneo",
        expand=False,
    )

    console.print(menu)
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
                ip: str = f"{get_addr_gateway()}/24"
                nm.scan(hosts=ip)
                dispositivos: int = len(nm.all_hosts())
                cont: int = 0
                print(f"Dispositivo totales --> {dispositivos}")
                for host in nm.all_hosts():
                    cont = cont + 1
                    print(f"{host} Dispositivo  --> {cont}")
            case 6:
                pass
            case 7:
                target: str = str(input("Ip o Host : "))
                bloquear_trafico(ip_victima=target)
    except KeyboardInterrupt:
        response = input("Estas seguro que deseas salir  \n [] :: ")
        match response:
            case "y":
                sys.exit()
    else:
        print("Escaneo ejecutado con exito  ☕ ")


if __name__ == "__main__":
    while True:
        try:
            console = Console()
            print(f.renderText("Anchor Port"), end="\n")
            print(Fore.BLUE + f"Sistema operativo ${machine}")
            print(f"Ip local ${_ip_default}")
            main(machine=machine, console=console)
        except KeyboardInterrupt:
            sys.exit()
