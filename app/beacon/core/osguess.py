 # constants ->
# common initial ttl values and the families that use them; 64 also covers ios and android,
# 255 covers cisco ios, solaris and most rtos firmware
_INITIAL_TTLS: tuple[tuple[int, str], ...] = (
  (32, "windows (legacy)"),
  (64, "linux/unix/macos"),
  (128, "windows"),
  (255, "network device"),
)


 # os estimation ->
def initial_ttl(ttl: int) -> int:
  """round an observed ttl up to the most likely initial ttl it started from."""
  for value, _ in _INITIAL_TTLS:
    if ttl <= value:
      return value
  return 255


def guess_os(ttl: int | None) -> str | None:
  """a coarse os family estimate from the ttl of a reply; it is a hint, not a fingerprint."""
  if ttl is None or not 0 < ttl <= 255:
    return None
  start = initial_ttl(ttl)
  return next(label for value, label in _INITIAL_TTLS if value == start)
