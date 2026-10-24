 # import libraries ->
import json
import sys
from typing import Annotated

import typer
from rich.markup import escape
from rich.text import Text

from beacon.cli.commands.options import JsonOut
from beacon.cli.context import get_app
from beacon.core.risk import RiskLevel, suggest_alias
from beacon.services.review import ReviewAction, ReviewCase, apply_action, pending_cases
from beacon.storage import Repository
from beacon.ui.console import console, error, success
from beacon.ui.render import review_card, review_table


 # constants ->
EXIT_USAGE = 2
PROMPT = "[t]rust  [a] trust with alias  [i]gnore  [f]orget  [s]kip  [q]uit > "


 # presentation ->
def _interactive() -> bool:
  return sys.stdin.isatty() and sys.stdout.isatty()


def _read_action() -> ReviewAction:
  """one keypress; unknown keys are ignored. ctrl+c, ctrl+d and end of input leave the review."""
  while True:
    try:
      key = typer.getchar().lower()
    except (KeyboardInterrupt, EOFError):
      return ReviewAction.QUIT
    if key in ("", "\x03", "\x04"):  # nothing left to read, ctrl+c or ctrl+d
      return ReviewAction.QUIT
    try:
      return ReviewAction(key)
    except ValueError:
      continue


 # command ->
def review(
  ctx: typer.Context,
  list_only: Annotated[bool, typer.Option("--list", help="print the pending devices and exit.")] = False,
  trust_below: Annotated[
    RiskLevel | None,
    typer.Option("--trust-below", help="trust every pending device whose risk is at most this level.", show_default=False),
  ] = None,
  yes: Annotated[bool, typer.Option("--yes", "-y", help="skip the confirmation prompt.")] = False,
  json_out: JsonOut = False,
) -> None:
  """go through the devices that raised alerts, see why they matter and decide one by one."""
  app = get_app(ctx)
  cases = pending_cases(app.repository)

  if json_out:
    typer.echo(
      json.dumps(
        [{**c.device.to_dict(), **c.risk.to_dict(), "pending_events": [e.to_dict() for e in c.events]} for c in cases],
        indent=2,
        ensure_ascii=False,
      )
    )
    return
  if not cases:
    console.print("[muted]nothing pending review[/muted]")
    return
  if trust_below is not None:
    _trust_below(app.repository, cases, trust_below, yes)
    return
  if list_only:
    console.print(review_table([(c.device, c.risk) for c in cases]))
    console.print(f"[muted]{len(cases)} devices pending · run `beacon review` in a terminal to decide on them[/muted]")
    return
  if not _interactive():
    error("review is interactive; use --list or --json to read the pending devices without a terminal")
    raise typer.Exit(EXIT_USAGE)
  _walk(app.repository, cases)


def _trust_below(repo: Repository, cases: list[ReviewCase], level: RiskLevel, yes: bool) -> None:
  chosen = [c for c in cases if c.risk.level.rank <= level.rank]
  if not chosen:
    console.print(f"[muted]no pending device has a risk of {level} or lower[/muted]")
    return
  console.print(review_table([(c.device, c.risk) for c in chosen]))
  console.print("[muted]the score is a heuristic: a compromised network looks fine on a first scan.[/muted]")
  if not yes:
    typer.confirm(f"trust these {len(chosen)} devices?", abort=True)
  for case in chosen:
    repo.set_trusted(case.device.key, True)
  success(f"{len(chosen)} devices marked as trusted")


def _walk(repo: Repository, cases: list[ReviewCase]) -> None:
  tally: dict[str, int] = {}
  decided = 0
  for position, case in enumerate(cases, start=1):
    console.print(review_card(case.device, case.risk, case.events, position, len(cases)))
    console.print("[muted]risk is a heuristic from what beacon observed, not a verdict.[/muted]")
    console.print(Text(PROMPT, style="accent"), end="")
    action = _read_action()
    console.print(action.value)
    if action == ReviewAction.QUIT:
      break
    alias = None
    if action == ReviewAction.TRUST_ALIAS:
      alias = typer.prompt("alias", default=suggest_alias(case.device))
    outcome = apply_action(repo, case.device, action, alias)
    if outcome != "skipped":
      decided += 1
      success(f"{escape(case.device.display_name)} ({case.device.key}) {outcome}")
    tally[outcome] = tally.get(outcome, 0) + 1
  summary = " · ".join(f"{count} {name}" for name, count in tally.items())
  left = len(cases) - decided
  console.print(f"[muted]{summary or 'no changes'} · {left} still pending[/muted]")
