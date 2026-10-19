"""Identidad visual de Onitsuka para las interfaces de terminal."""

ONITSUKA_MARK = r"""
      o---o
     /     \
    o---@---o
     \     /
      o---o
""".strip("\n")

BRAND_COLOR = "#236b45"
ACCENT_COLOR = "#c16a12"


def logo_markup() -> str:
    """Logo como markup de Rich/Textual, coloreado."""
    lineas = ONITSUKA_MARK.splitlines()
    cuerpo = "\n".join(
        f"[{BRAND_COLOR}]{linea}[/]" if index != 2 else
        f"[{BRAND_COLOR}]    o---[/][b {ACCENT_COLOR}]@[/][{BRAND_COLOR}]---o[/]"
        for index, linea in enumerate(lineas)
    )
    titulo = f"[b {BRAND_COLOR}]O N I T S U K A[/]"
    return f"{cuerpo}\n\n{titulo}"
