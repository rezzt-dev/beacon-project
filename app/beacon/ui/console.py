 # import libraries ->
from rich.console import Console
from rich.theme import Theme


 # theme ->
# every state carries a symbol too (✓ ✗ ! ● ○), so nothing depends on color alone; rich already
# honours NO_COLOR and drops styles when the output is not a terminal
THEME = Theme(
  {
    "info": "dim",
    "warning": "yellow",
    "alert": "bold red",
    "ok": "green",
    "muted": "grey50",
    "accent": "bold cyan",
    "brand": "bold cyan",
    "cmd": "bold",
    "new": "bold black on yellow",
    "mac": "magenta",
    "ip": "bold",
    "host": "cyan",
  }
)

console = Console(theme=THEME, highlight=False)
err_console = Console(theme=THEME, highlight=False, stderr=True)


 # message helpers ->
def error(message: str, hint: str | None = None) -> None:
  """`✗ error: what went wrong` and, when there is one, `→ what to try next`."""
  err_console.print(f"[alert]✗ error:[/alert] {message}")
  if hint:
    err_console.print(f"  [muted]→[/muted] {hint}")


def warn(message: str) -> None:
  err_console.print(f"[warning]! warning:[/warning] {message}")


def success(message: str) -> None:
  console.print(f"[ok]✓[/ok] {message}")


def hint(message: str) -> None:
  console.print(f"[muted]→[/muted] {message}")
