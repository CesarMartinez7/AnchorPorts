import pprint
from colorama import Fore,Back,Style

def formatter(escaneo):
    # Crear un objeto PrettyPrinter con configuración personalizada
    pp = pprint.PrettyPrinter(indent=2, width=40, depth=4, compact=False)

    # Mostrar el escaneo formateado
    print(Fore.GREEN + "=== Resultado del Escaneo Nmap ===")
    pp.pprint(escaneo)


