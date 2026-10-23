 # import libraries ->
from beacon.core.osguess import guess_os, initial_ttl
from beacon.core.vendors import VendorDatabase


 # oui lookup ->
def test_lookup_ma_l_prefix(vendors):
  assert vendors.lookup("34:5d:9e:3f:2a:77") == "Sagemcom Broadband SAS"
  assert vendors.lookup("B0-A7-B9-DC-71-4A") == "TP-Link Systems Inc"


def test_longest_prefix_wins(vendors):
  # 00:1b:c5:00:00:0x is an ma-s (/36) block inside the ieee registration ma-l
  assert vendors.lookup("00:1b:c5:00:00:0a") == "Converging Systems Inc."
  assert vendors.lookup("00:1b:c5:99:00:0a") == "IEEE Registration Authority"
  # ma-m (/28)
  assert vendors.lookup("00:55:da:1f:ff:ff") == "KoolPOS Inc."
  assert vendors.lookup("00:55:da:20:00:00") is None


def test_unknown_invalid_and_randomized(vendors):
  assert vendors.lookup("aa:bb:cc:dd:ee:ff") is None
  assert vendors.lookup("garbage") is None
  assert vendors.lookup("36:5d:9e:3f:2a:77") is None  # locally administered


def test_counts_and_ignores_malformed_lines():
  db = VendorDatabase().load_lines(["# comment", "", "ZZ:ZZ:ZZ\tBad", "only-one-field", "00:00:0C\tCisco\tCisco Systems, Inc"])
  assert len(db) == 1
  assert db.lookup("00:00:0c:12:34:56") == "Cisco Systems, Inc"


def test_load_default_falls_back_to_empty(tmp_path, monkeypatch):
  monkeypatch.setattr("beacon.core.vendors.SYSTEM_MANUF_PATHS", ())
  assert len(VendorDatabase.load_default(tmp_path / "missing")) == 0


 # os estimate ->
def test_os_guess_from_ttl():
  assert initial_ttl(57) == 64
  assert guess_os(64) == "linux/unix/macos"
  assert guess_os(117) == "windows"
  assert guess_os(254) == "network device"
  assert guess_os(None) is None
  assert guess_os(0) is None
