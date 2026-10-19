"""Mascota ASCII de Onitsuka: un gato guardián de la red."""

from rich.text import Text

ONITSUKA_MARK = r"""
       /\_/\
      ( o.o )
       > ^ <
      /|___|\
     /_| @ |_\
""".strip("\n")

BRAND_COLOR = "#236b45"
ACCENT_COLOR = "#c16a12"


def logo_text() -> Text:
    """Logo como texto con estilo de Rich/Textual."""
    lineas = ONITSUKA_MARK.splitlines()
    logo = Text()
    for index, linea in enumerate(lineas):
        if index:
            logo.append("\n")
        if index == 4:
            before, after = linea.split("@", maxsplit=1)
            logo.append(before, style=BRAND_COLOR)
            logo.append("@", style=f"bold {ACCENT_COLOR}")
            logo.append(after, style=BRAND_COLOR)
        else:
            logo.append(linea, style=BRAND_COLOR)
    logo.append("\n\n")
    logo.append("O N I T S U K A", style=f"bold {BRAND_COLOR}")
    logo.append("\nnetwork guardian", style="dim")
    return logo
