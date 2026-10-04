"""Logo ASCII de la mascota Elisa (derivado de elisa-states.jpeg).

Generado convirtiendo una de las caritas a arte ASCII por brillo. Se muestra
en el panel interactivo con el color salmón de la mascota.
"""

ELISA_ASCII = r"""
        :--=========-:.
      -============-----:
    -================---==.
   ========================.
  -======- .=====-  ========
 .+======:  -====.  -=======-
 :+======-  -====-  ========-
 .+==----===+****+===--:-===-
  ====-=====++--++==========
   ==========+=============.
    -====================-
      -================-.
        .--=========-:
""".strip("\n")

# Color salmón aproximado de la mascota.
ELISA_COLOR = "#d9766a"


def logo_markup() -> str:
    """Logo como markup de Rich/Textual, coloreado."""
    cuerpo = f"[{ELISA_COLOR}]{ELISA_ASCII}[/]"
    titulo = "[b #d9766a]A N C H O R   P O R T[/]"
    return f"{cuerpo}\n\n{titulo}"
