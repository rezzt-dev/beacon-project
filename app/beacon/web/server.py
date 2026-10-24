 # import libraries ->
import contextlib
import logging
import socket
from collections.abc import AsyncIterator
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from beacon.config import Settings
from beacon.core.models import utcnow
from beacon.scanners.network import list_interfaces
from beacon.web.api import Api
from beacon.web.jobs import ScanWorker
from beacon.web.security import Auth, GuardMiddleware
from beacon.web.stream import ChangeStream
from beacon.web.workspace import Workspace


log = logging.getLogger(__name__)


 # constants ->
DEFAULT_PORT = 8765
STATIC = Path(str(resources.files("beacon.web") / "static"))


 # configuration ->
@dataclass(slots=True)
class LiveConfig:
  host: str = "127.0.0.1"
  port: int = DEFAULT_PORT
  allow_lan: bool = False
  tls_cert: Path | None = None
  tls_key: Path | None = None
  rotate_token: bool = False
  monitor_profile: int | None = None
  monitor_interval: int | None = None

  @property
  def scheme(self) -> str:
    return "https" if self.tls_cert else "http"

  @property
  def is_loopback(self) -> bool:
    return self.host in ("127.0.0.1", "localhost", "::1")

  def allowed_hosts(self) -> set[str]:
    """the `Host` headers this server answers to: a rebinding domain never matches."""
    names = {f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"}
    if not self.is_loopback:
      names.add(f"{self.host}:{self.port}")
      names.add(f"{socket.gethostname().lower()}:{self.port}")
      for iface in list_interfaces():
        names.add(f"{iface.ip}:{self.port}")
    return names

  def validate(self) -> None:
    if not self.is_loopback and not self.allow_lan:
      raise ValueError("listening on a non-loopback address needs --allow-lan (and ideally --tls-cert/--tls-key)")
    if bool(self.tls_cert) != bool(self.tls_key):
      raise ValueError("--tls-cert and --tls-key go together")


 # application ->
def create_app(settings: Settings, config: LiveConfig, worker: ScanWorker | None = None) -> Starlette:
  workspace = Workspace(settings)
  settings.ensure_dirs()
  auth = Auth.from_dir(settings.data_dir, rotate=config.rotate_token, secure_cookie=config.tls_cert is not None)
  worker = worker or ScanWorker(workspace)
  api = Api(workspace, worker, auth, utcnow(), lan=not config.is_loopback)
  stream = ChangeStream(lambda: workspace.repository, api.status_snapshot)

  async def index(_request: Request) -> Response:
    return FileResponse(STATIC / "index.html", headers={"cache-control": "no-cache"})

  async def login(_request: Request) -> Response:
    return FileResponse(STATIC / "login.html", headers={"cache-control": "no-store"})

  async def not_found(_request: Request) -> Response:
    return JSONResponse({"error": {"code": "not_found", "message": "unknown api route"}}, status_code=404)

  @contextlib.asynccontextmanager
  async def lifespan(_app: Starlette) -> AsyncIterator[None]:
    worker.start()
    if config.monitor_interval:
      worker.start_monitor(config.monitor_profile, config.monitor_interval)
    try:
      yield
    finally:
      worker.stop()
      workspace.close()

  routes = [
    *api.routes(),
    Route("/api/v1/stream", stream.endpoint, methods=["GET"]),
    Route("/api/{rest:path}", not_found),
    Route("/login", login),
    Mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets"),
    Route("/{path:path}", index),
  ]
  guard = Middleware(GuardMiddleware, auth=auth, allowed_hosts=config.allowed_hosts())
  app = Starlette(routes=routes, lifespan=lifespan, middleware=[guard])
  app.state.api = api
  app.state.worker = worker
  app.state.auth = auth
  app.state.workspace = workspace
  app.state.stream = stream
  return app


def login_url(settings: Settings, config: LiveConfig) -> str:
  """the sign-in link: the token travels in the fragment, so it never reaches logs or referers."""
  auth = Auth.from_dir(settings.data_dir)
  host = "127.0.0.1" if config.is_loopback or config.host in ("0.0.0.0", "::") else config.host
  return f"{config.scheme}://{host}:{config.port}/login#token={auth.token}"


def serve(settings: Settings, config: LiveConfig) -> None:
  """run until ctrl+c or sigterm; the scan in progress is cancelled and recorded as such."""
  import uvicorn

  config.validate()
  app = create_app(settings, config)

  class Server(uvicorn.Server):
    def handle_exit(self, sig, frame) -> None:
      app.state.stream.close()
      super().handle_exit(sig, frame)

  Server(uvicorn.Config(
    app,
    host=config.host,
    port=config.port,
    log_level="warning",
    access_log=False,
    ssl_certfile=str(config.tls_cert) if config.tls_cert else None,
    ssl_keyfile=str(config.tls_key) if config.tls_key else None,
    proxy_headers=False,
    server_header=False,
    date_header=False,
    timeout_graceful_shutdown=5,
  )).run()
