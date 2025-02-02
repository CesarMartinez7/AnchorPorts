import subprocess
import sys
import socket


# def get_addr_gateway():
    


def get_ip_for_machine () :
    if(sys.platform == "linux"):
        resultado = subprocess.run(args=["curl", "ifconfig.me"],capture_output=True,check=True)
        ip = resultado
    elif(sys.platform == "win32"):
        print("Equivo macOS")
    elif(sys.platform == "darwin"):
        print("Equipo de macOS")
    return {"output" : str(ip.stdout),"status_code" : ip.returncode} 


def get_addr_localhost() -> str:
    ip : str = socket.gethostbyname(socket.gethostname())
    return ip



_ip_default : str = str(get_ip_for_machine().get("output", "output"))



# Se pone gateway por ahora para saber que es la local.
def get_addr_gateway() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    resultado : str = s.getsockname()[0]
    s.close()
    return resultado


print(get_addr_gateway())