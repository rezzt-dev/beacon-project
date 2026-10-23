 # import libraries ->
from rich.console import Console
from rich.theme import Theme


 # theme ->
THEME = Theme(
  {
    "info": "dim",
    "warning": "yellow",
    "alert": "bold red",
    "ok": "green",
    "muted": "grey50",
    "accent": "bold cyan",
    "mac": "magenta",
    "ip": "bold",
  }
)

console = Console(theme=THEME, highlight=False)
err_console = Console(theme=THEME, highlight=False, stderr=True)


 # message helpers ->
def error(message: str) -> None:
  err_console.print(f"[alert]error:[/alert] {message}")


def warn(message: str) -> None:
  err_console.print(f"[warning]warning:[/warning] {message}")


def success(message: str) -> None:
  console.print(f"[ok]✓[/ok] {message}")
