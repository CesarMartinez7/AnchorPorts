# Anchor Port

Anchor Port es un escáner de puertos que utiliza la biblioteca `nmap-python` para ofrecer una herramienta sencilla y eficiente para escanear y visualizar puertos abiertos en una máquina.

## Características

- Escaneo de puertos utilizando `nmap-python y scapy`
- Comandos sencillos para escanear puertos
- Visualización de puertos abiertos en una máquina objetivo

## Instalación

Para instalar y configurar Anchor Port, es recomendable utilizar el script como __root__ sigue los siguientes pasos:

1. **Crear un entorno virtual**  
   Si intentas ejecutar el script directamente, es probable que te muestre errores de módulos faltantes. Para evitar esto, crea un entorno virtual:

   ```bash
   python3 -m venv <nombre_de_tu_entorno> 



3. **Instalar las dependencias**

    Para instalar las dependencias necesarias, utiliza el siguiente comando:
      ```bash
            pip install -r requerimentos.txt


4. **Ejecutar el script**

    Para ejecutar el script, solo tienes que correr el siguiente comando:
    ```bash
            sudo su && source <nombre_de_tu_entorno>/bin/activate &&  python3 main.py