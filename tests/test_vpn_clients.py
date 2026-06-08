# tests/test_vpn_clients.py — новый файл
import cascade.vpn as vpn
from cascade.config import Config, ExitServer, Client


class FakeConn:
    def __init__(self):
        self.calls = []
    def run(self, cmd, timeout=30, **kw):
        self.calls.append(cmd)
        class R: returncode = 0; stdout = "active"; stderr = ""
        return R()
    def write_file(self, local, remote):
        return True


def _cfg():
    return Config(
        exit_servers=[ExitServer(id="fin", location="Финляндия", ip="9.9.9.9",
                                 reality_private_key="P", reality_public_key="PB",
                                 reality_short_id="S")],
        clients=[Client(id="default", name="default", uuid="u-0")],
    )


def test_add_client_appends_and_returns_uuid(monkeypatch):
    monkeypatch.setattr(vpn, "save_config", lambda cfg: None)
    cfg = _cfg()
    conns = {"fin": FakeConn()}
    uid = vpn.add_vpn_client(cfg, "phone", conns)
    names = {c.name for c in cfg.clients}
    assert "phone" in names
    assert any(c.uuid == uid and c.name == "phone" for c in cfg.clients)


def test_add_duplicate_raises(monkeypatch):
    monkeypatch.setattr(vpn, "save_config", lambda cfg: None)
    cfg = _cfg()
    import pytest
    with pytest.raises(ValueError):
        vpn.add_vpn_client(cfg, "default", {"fin": FakeConn()})


def test_remove_last_client_raises(monkeypatch):
    monkeypatch.setattr(vpn, "save_config", lambda cfg: None)
    cfg = _cfg()
    import pytest
    with pytest.raises(ValueError):
        vpn.remove_vpn_client(cfg, "default", {"fin": FakeConn()})
