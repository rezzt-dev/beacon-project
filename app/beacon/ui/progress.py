 # import libraries ->
from rich.console import Console
from rich.progress import (
  BarColumn,
  MofNCompleteColumn,
  Progress,
  SpinnerColumn,
  TaskID,
  TextColumn,
  TimeElapsedColumn,
)


 # progress reporter ->
class RichProgress:
  """rich implementation of `ProgressReporter`: one transient bar per pipeline stage."""

  def __init__(self, console: Console, enabled: bool = True) -> None:
    self._progress = Progress(
      SpinnerColumn(),
      TextColumn("[bold]{task.description}"),
      BarColumn(),
      MofNCompleteColumn(),
      TimeElapsedColumn(),
      console=console,
      transient=True,
      disable=not enabled,
    )
    self._task: TaskID | None = None

  def __enter__(self) -> "RichProgress":
    self._progress.start()
    return self

  def __exit__(self, *_exc: object) -> None:
    self._finish_task()
    self._progress.stop()

  def _finish_task(self) -> None:
    if self._task is not None:
      task = self._progress.tasks[-1]
      self._progress.update(self._task, completed=task.total or 1, total=task.total or 1)

  def stage(self, name: str, total: int | None = None) -> None:
    self._finish_task()
    self._task = self._progress.add_task(name, total=total)

  def advance(self, amount: int = 1) -> None:
    if self._task is not None:
      self._progress.advance(self._task, amount)
