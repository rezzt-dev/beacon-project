 # import libraries ->
import json
import sys
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

import typer
from rich.markup import escape
from rich.text import Text

from beacon.cli.commands.options import JsonOut
from beacon.cli.context import AppContext, get_app
from beacon.core.events import Event
from beacon.core.models import Device
from beacon.core.risk import RiskAssessment, RiskLevel, suggest_alias
from beacon.storage import Repository
from beacon.ui.console import console, error, success
from beacon.ui.render import review_card, review_table


 # constants ->
EXIT_USAGE = 2
PROMPT = "[t]rust  [a] trust with alias  [i]gnore  [f]orget  [s]kip  [q]uit > "


 # review cases ->
class ReviewAction(StrEnum):
  TRUST = "t"
  TRUST_ALIAS = "a"
  IGNORE = "i"
  FORGET = "f"
  SKIP = "s"
  QUIT = "q"


@dataclass(slots=True)
class ReviewCase:
  """a device with events nobody has looked at yet, and why it matters."""

  device: Device
  risk: RiskAssessment
  events: list[Event]


def pending_cases(app: AppContext) -> list[ReviewCase]:
  """pending events grouped by device and sorted by risk, the riskiest first."""
  grouped: dict[str, list[Event]] = {}
  for event in app.repository.list_pending_events():
    if event.device_key:
      grouped.setdefault(event.device_key, []).append(event)
  devices = {k: d for k, d in app.repository.load_devices().items() if k in grouped}
  risks = app.assess_devices(devices.values())
  cases = [ReviewCase(device, risks[key], grouped[key]) for key, device in devices.items()]
  return sorted(cases, key=lambda c: (-c.risk.score, c.device.ip))


def apply_action(repo: Repository, device: Device, action: ReviewAction, alias: str | None = None) -> str:
  """carry out one decision on exactly one device and say what happened. an empty alias is a plain trust."""
  if action == ReviewAction.TRUST_ALIAS:
    if name := (alias or "").strip():
      repo.set_alias(device.key, name)
    action = ReviewAction.TRUST
  if action == ReviewAction.TRUST:
    repo.set_trusted(device.key, True)
    return "trusted"
  if action == ReviewAction.IGNORE:
    repo.ack_events(device.key)
    return "ignored"
  if action == ReviewAction.FORGET:
    repo.delete_device(device.key)
    return "forgotten"
  return "skipped"


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
  cases = pending_cases(app)

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
