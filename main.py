import sys
from os import system

from rich.console import Console
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Footer, Header, OptionList, Static
from textual.widgets.option_list import Option

from fonts import f
from get_host import _ip_default
from logo import ACCENT_COLOR, BRAND_COLOR, logo_text
from net import get_gateway_ip

machine: str = sys.platform.title()

OPCIONES = [
    ("1", "Panel interactivo",
     "Ver, bloquear y expulsar dispositivos por teclado"),
    ("2", "Monitor de dominios",
     "A qué dominios (DNS) accede cada dispositivo"),
    ("0", "Salir", "Cerrar Onitsuka"),
]


def clear_console():
    if sys.platform.startswith("linux"):
        system("clear")
    else:
        system("cls")


class MenuApp(App):
    """Menú de inicio interactivo: navega con j/k o flechas, Enter/número elige."""

    TITLE = "Onitsuka"
    SUB_TITLE = "herramientas claras para tu red local · sin nube"

    CSS = """
    Screen { align: center middle; background: #101820; color: #e6eee9; }
    Header { background: #18252e; color: #72dda0; }
    Footer { background: #18252e; color: #e6eee9; }
    #banner { color: #72dda0; height: auto; content-align: center top;
              margin-bottom: 0; }
    #fila { height: auto; align: center middle; }
    #logo { color: #72dda0; width: auto; height: auto; margin-right: 5; }
    #menu {
        width: 64; height: auto;
        border: round #3e5b4a; background: #18252e; padding: 1 2;
        border-title-color: #72dda0; border-title-align: center;
    }
    #menu > .option-list--option { padding: 1 1; color: #e6eee9; }
    #menu > .option-list--option-highlighted {
        background: #72dda0; color: #101820; text-style: bold;
    }
    #info { color: #a4b5aa; height: auto; content-align: center top;
            margin-top: 2; }
    """

    BINDINGS = [
        ("j,down", "mover(1)", "Bajar"),
        ("k,up", "mover(-1)", "Subir"),
        ("1", "elegir('1')", ""),
        ("2", "elegir('2')", ""),
        ("0,q", "elegir('0')", "Salir"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(Text(f.renderText("ONITSUKA"), style=f"bold {BRAND_COLOR}"),
                     id="banner")
        with Horizontal(id="fila"):
            yield Static(logo_text(), id="logo")
            menu = OptionList(id="menu")
            for key, nombre, desc in OPCIONES:
                etiqueta = Text.assemble(
                    (f" {key}  ", "bold"), (nombre, "bold"),
                    ("\n     " + desc, "dim"),
                )
                etiqueta.stylize(f"bold {ACCENT_COLOR}", 0, len(f" {key}  "))
                menu.add_option(Option(etiqueta, id=key))
            yield menu
        yield Static(
            Text.assemble(
                ("SO ", "dim"), (machine, "bold"),
                ("    IP ", "dim"), (_ip_default, BRAND_COLOR),
                ("    gateway ", "dim"), (get_gateway_ip(), BRAND_COLOR),
            ),
            id="info",
        )
        yield Footer()

    def on_mount(self) -> None:
        menu = self.query_one(OptionList)
        menu.border_title = "CENTRO DE CONTROL"
        menu.focus()

    def action_mover(self, paso: int) -> None:
        menu = self.query_one(OptionList)
        if paso > 0:
            menu.action_cursor_down()
        else:
            menu.action_cursor_up()

    def action_elegir(self, key: str) -> None:
        self.exit(key)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.exit(event.option.id)


def _aviso_arp(console, error) -> None:
    """Mensaje claro cuando scapy no puede usar ARP (típico: falta Npcap)."""
    console.print(f"\n[bold red]No se pudo iniciar el control de red:[/] {error}\n")
    console.print(
        "[bold yellow]Causa más probable en Windows:[/] falta [bold]Npcap[/].\n"
        "  1. Descárgalo de https://npcap.com\n"
        "  2. Instálalo marcando [cyan]\"WinPcap API-compatible mode\"[/]\n"
        "  3. Abre esta terminal como [bold]Administrador[/] y reintenta.\n"
        "En Linux: ejecuta con [bold]sudo[/].\n"
    )
    input("Enter para volver al menú...")


def main() -> None:
    console = Console()
    while True:
        try:
            opcion = MenuApp().run()
        except KeyboardInterrupt:
            break
        if not opcion or opcion == "0":
            break
        if opcion == "1":
            from tui import AnchorTUI
            AnchorTUI().run()
        elif opcion == "2":
            try:
                from dns_monitor import DNSMonitor
                DNSMonitor().run()
            except RuntimeError as e:
                _aviso_arp(console, e)


if __name__ == "__main__":
    main()
