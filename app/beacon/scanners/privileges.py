 # import libraries ->
import importlib.util
import os
import socket
import sys
from functools import cache


 # privilege checks ->
@cache
def can_open_raw_socket() -> bool:
  """true when the process may send raw frames (root, administrator or cap_net_raw)."""
  if sys.platform == "win32":
    try:
      import ctypes

      return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
      return False
  if os.geteuid() == 0:
    return True
  try:
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
    return True
  except (PermissionError, OSError):
    return False


@cache
def scapy_available() -> bool:
  return importlib.util.find_spec("scapy") is not None


def privileged_mode_available() -> bool:
  return can_open_raw_socket() and scapy_available()
