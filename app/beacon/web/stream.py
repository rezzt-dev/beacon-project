 # import libraries ->
import asyncio
import json
import threading
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse

from beacon.storage import Repository


 # constants ->
POLL_SECONDS = 0.5
HEARTBEAT_SECONDS = 15.0
BATCH = 200
# a client this far behind is told to reload a snapshot instead of replaying everything
MAX_REPLAY = 2000
MAX_CLIENTS = 32
RETRY_MS = 3000


 # helpers ->
def _frame(event: str, data: Any, event_id: int | None = None) -> str:
  lines = []
  if event_id is not None:
    lines.append(f"id: {event_id}")
  lines.append(f"event: {event}")
  lines.append("data: " + json.dumps(data, separators=(",", ":"), default=str))
  return "\n".join(lines) + "\n\n"


def _start_id(request: Request) -> int | None:
  raw = request.headers.get("last-event-id") or request.query_params.get("after")
  if raw is None or raw == "":
    return None
  if not raw.isdigit():
    return -1
  return int(raw)


 # stream ->
class ChangeStream:
  """server-sent events over the database change feed.

  - every frame carries the change id, so a reconnecting client resumes exactly where it was
    (`Last-Event-ID` or `?after=`), without duplicates and in order.
  - when the requested id was already pruned, or the client is too far behind, it gets a
    `reset` frame and must reload a consistent snapshot through the normal api.
  - a heartbeat comment keeps proxies and the client's timeout happy; the reader loop is the
    only work per client and it never touches the scanner.
  """

  def __init__(self, repository: Callable[[], Repository], status: Callable[[], dict[str, Any]]) -> None:
    self._repository = repository
    self._status = status
    self._clients = 0
    self._lock = threading.Lock()
    self._closing = threading.Event()

  def close(self) -> None:
    """end every open stream at its next poll, so a shutdown does not wait for (or cancel) them."""
    self._closing.set()

  @property
  def clients(self) -> int:
    return self._clients

  async def endpoint(self, request: Request) -> StreamingResponse | JSONResponse:
    with self._lock:
      if self._clients >= MAX_CLIENTS:
        return JSONResponse({"error": {"code": "too_many_streams", "message": "too many live connections"}}, status_code=503)
      self._clients += 1
    return StreamingResponse(
      self._events(request, _start_id(request)),
      media_type="text/event-stream",
      headers={"cache-control": "no-store", "x-accel-buffering": "no"},
    )

  async def _events(self, request: Request, after: int | None) -> AsyncIterator[str]:
    try:
      oldest, newest = await run_in_threadpool(lambda: self._repository().change_bounds())
      yield f"retry: {RETRY_MS}\n\n"
      if after is None:
        after = newest
        yield _frame("hello", {"cursor": newest, "status": await run_in_threadpool(self._status)}, newest)
      elif after < 0 or after > newest or (oldest and after < oldest - 1) or newest - after > MAX_REPLAY:
        # the history cannot reproduce what the client missed: it reloads everything
        after = newest
        yield _frame("reset", {"cursor": newest, "reason": "history unavailable"}, newest)
      last_beat = time.monotonic()
      last_status = 0.0
      while not self._closing.is_set() and not await request.is_disconnected():
        changes = await run_in_threadpool(lambda a=after: self._repository().changes_since(a, BATCH))
        for change in changes:
          after = change["id"]
          yield _frame("change", change, after)
        now = time.monotonic()
        if now - last_status >= 2.0:
          last_status = now
          yield _frame("status", await run_in_threadpool(self._status))
          last_beat = now
        elif now - last_beat >= HEARTBEAT_SECONDS:
          last_beat = now
          yield ": keep-alive\n\n"
        if len(changes) < BATCH:
          await asyncio.sleep(POLL_SECONDS)
    finally:
      with self._lock:
        self._clients -= 1
