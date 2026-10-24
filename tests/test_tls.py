 # import libraries ->
import asyncio
import ssl
from pathlib import Path

import pytest

from beacon.scanners.tls import DerError, fetch_certificate, parse_certificate


DATA = Path(__file__).parent / "data"
CERT = DATA / "tls-cert.pem"
KEY = DATA / "tls-key.pem"


def der() -> bytes:
  return ssl.PEM_cert_to_DER_cert(CERT.read_text())


 # parsing ->
def test_a_certificate_is_read_without_validating_it():
  details = parse_certificate(der())
  assert details["subject"] == "nas.lan" and details["subject_org"] == "Beacon Test"
  assert details["issuer"] == "nas.lan" and details["self_signed"] is True
  assert details["names"] == ["nas.lan", "nas.local", "192.168.1.10"]
  assert details["not_before"] < details["not_after"]
  assert len(details["sha256"]) == 64


@pytest.mark.parametrize("cut", [0, 1, 10, 200])
def test_truncated_or_garbage_certificates_are_rejected(cut):
  with pytest.raises((DerError, ValueError, IndexError)):
    parse_certificate(der()[:cut])


def test_oversized_certificates_are_rejected():
  with pytest.raises(DerError):
    parse_certificate(b"\x30" + b"\x00" * (70 * 1024))


 # network (loopback only) ->
def test_fetch_records_what_was_observed_and_never_claims_trust():
  async def scenario():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)

    async def handle(_reader, writer):
      await asyncio.sleep(0.2)
      writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    async with server:
      return await fetch_certificate("127.0.0.1", port, timeout=3)

  details = asyncio.run(scenario())
  assert details is not None and details["subject"] == "nas.lan"
  assert details["trusted"] is False and details["tls_version"].startswith("TLS")


def test_a_plain_tcp_port_yields_no_certificate():
  async def scenario():
    async def handle(_reader, writer):
      writer.write(b"SSH-2.0-test\r\n")
      await writer.drain()
      writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
      return await fetch_certificate("127.0.0.1", port, timeout=2)

  assert asyncio.run(scenario()) is None
