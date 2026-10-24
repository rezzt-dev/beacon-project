 # import libraries ->
import asyncio
import errno
from datetime import timedelta

import pytest

from beacon.core.exposure import is_sensitive, observed_protocol
from beacon.core.models import PortInfo, PortState
from beacon.core.ports import PortSet, merge_ports
from beacon.scanners import ports as port_scanner
from beacon.scanners.ports import scan_host_ports
from conftest import T0


LATER = T0 + timedelta(hours=1)


def known(port, state=PortState.OPEN, **kwargs):
  return PortInfo(port, state, last_probe=state, checked_at=T0, open_seen_at=T0 if state == PortState.OPEN else None, first_seen=T0, **kwargs)


def states(ports):
  return {p.port: (str(p.state), str(p.last_probe) if p.last_probe else None) for p in ports}


 # port sets ->
def test_port_sets_are_compact_ranges():
  ports = PortSet([22, 80, 81, 82, 443])
  assert str(ports) == "22,80-82,443" and len(ports) == 5
  assert 81 in ports and 83 not in ports and "80" not in ports
  assert PortSet.parse("22,80-82,443") == ports
  assert len(PortSet.parse("1-65535")) == 65535 and 65535 in PortSet.parse("1-65535")
  assert not PortSet() and str(PortSet()) == "" and PortSet.parse(None) == PortSet()
  assert ports.union(PortSet([23])) == PortSet([22, 23, 80, 81, 82, 443])


def test_port_set_parsing_rejects_bad_ranges():
  with pytest.raises(ValueError):
    PortSet.parse("0-10")
  with pytest.raises(ValueError):
    PortSet.parse("90-80")


 # merging ->
def test_an_unexamined_port_keeps_its_state():
  merged = merge_ports([known(22)], {80: PortInfo(80, PortState.OPEN)}, PortSet([80]), LATER)
  assert states(merged) == {22: ("open", "open"), 80: ("open", "open")}
  assert next(p for p in merged if p.port == 22).checked_at == T0


def test_only_a_refusal_confirms_a_close():
  refused = merge_ports([known(22)], {22: PortInfo(22, PortState.CLOSED)}, PortSet([22]), LATER)
  assert states(refused) == {22: ("closed", "closed")}
  silent = merge_ports([known(22)], {22: PortInfo(22, PortState.FILTERED)}, PortSet([22]), LATER)
  assert states(silent) == {22: ("open", "filtered")} and silent[0].checked_at == LATER
  failed = merge_ports([known(22)], {22: PortInfo(22, PortState.ERROR)}, PortSet([22]), LATER)
  assert states(failed) == {22: ("open", "error")} and failed[0].checked_at == T0


def test_a_reopened_port_keeps_its_first_sighting_and_banner():
  merged = merge_ports([known(22, PortState.CLOSED, banner="SSH-2.0-old")], {22: PortInfo(22, PortState.OPEN)}, PortSet([22]), LATER)
  assert merged[0].state == PortState.OPEN and merged[0].first_seen == T0 and merged[0].banner == "SSH-2.0-old"
  assert merged[0].open_seen_at == LATER


def test_closed_results_for_unknown_ports_are_not_stored():
  assert merge_ports([], {23: PortInfo(23, PortState.CLOSED), 24: PortInfo(24, PortState.FILTERED)}, PortSet([23, 24]), LATER) == []


 # banners ->
@pytest.mark.parametrize(
  ("raw", "expected"),
  [
    (b"SSH-2.0-OpenSSH_9.6\r\n", "ssh"),
    (b"HTTP/1.1 200 OK\r\n", "http"),
    (b"\xff\xfd\x18\xff\xfd\x20", "telnet"),
    (b"\x16\x03\x03\x00\x2a", "tls"),
    (b"220 ProFTPD Server ready\r\n", "ftp"),
    (b"220 mail.example ESMTP Postfix\r\n", "smtp"),
    (b"RFB 003.008\n", "vnc"),
    (b"-NOAUTH Authentication required.\r\n", "redis"),
    (b"220 welcome\r\n", None),
    (b"", None),
    (None, None),
  ],
)
def test_observed_protocol_reads_the_first_bytes(raw, expected):
  assert observed_protocol(raw) == expected


def test_sensitive_ports_include_ssh_as_administration_but_not_https():
  assert is_sensitive(PortInfo(22, PortState.OPEN)) and is_sensitive(PortInfo(80, PortState.OPEN))
  assert not is_sensitive(PortInfo(443, PortState.OPEN)) and not is_sensitive(PortInfo(40000, PortState.OPEN))


 # scanner (loopback only) ->
async def _serve(banner: bytes = b"SSH-2.0-beacon-test\r\n"):
  async def handle(_reader, writer):
    writer.write(banner)
    await writer.drain()
    writer.close()

  server = await asyncio.start_server(handle, "127.0.0.1", 0)
  return server, server.sockets[0].getsockname()[1]


def _free_port() -> int:
  import socket

  with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    return sock.getsockname()[1]


def test_scan_reports_open_ports_and_tracked_ones_only():
  async def scenario():
    server, open_port = await _serve()
    closed_port, untracked = _free_port(), _free_port()
    async with server:
      return open_port, closed_port, untracked, await scan_host_ports(
        "127.0.0.1", [open_port, closed_port, untracked], timeout=1.0, banner_timeout=0.5, track=[closed_port]
      )

  open_port, closed_port, untracked, result = asyncio.run(scenario())
  by_port = {p.port: p for p in result.ports}
  assert set(by_port) == {open_port, closed_port}
  assert by_port[open_port].state == PortState.OPEN and by_port[open_port].protocol_observed == "ssh"
  assert by_port[closed_port].state == PortState.CLOSED
  assert result.counts["open"] == 1 and result.counts["closed"] == 2
  assert result.examined == PortSet([open_port, closed_port, untracked])


def test_a_local_network_error_is_a_probe_error_not_a_filtered_port(monkeypatch):
  async def unreachable(*_args, **_kwargs):
    raise OSError(errno.EHOSTUNREACH, "no route to host")

  monkeypatch.setattr(port_scanner.asyncio, "open_connection", unreachable)
  result = asyncio.run(scan_host_ports("192.0.2.1", [22], track=[22]))
  assert result.ports[0].state == PortState.ERROR and result.counts["error"] == 1
