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


class InstallConn:
    """Conn с раздельными ответами на установку и на проверку бинаря.

    has_xray — список ответов на `command -v xray` по порядку вызовов
    (или bool, если ответ всегда один и тот же)."""
    def __init__(self, install_rc=0, install_err="", has_xray=True):
        self.install_rc, self.install_err = install_rc, install_err
        self.has_xray = has_xray if isinstance(has_xray, list) else None
        self.always = has_xray if self.has_xray is None else None
        self.calls = []

    def run(self, cmd, timeout=30, **kw):
        self.calls.append(cmd)
        class R: pass
        r = R()
        if cmd.startswith("command -v xray"):
            present = self.always if self.has_xray is None else self.has_xray.pop(0)
            r.returncode, r.stdout, r.stderr = (0 if present else 1), "", ""
        else:
            r.returncode, r.stdout, r.stderr = self.install_rc, "", self.install_err
        return r


def test_install_xray_falls_back_to_wget_when_binary_absent():
    """Упавший curl в пайпе даёт rc=0 (bash на пустом stdin). Бинаря нет →
    резервный путь: wget + install-release.sh --local (скрипт внутри жёстко на curl)."""
    conn = InstallConn(install_rc=0, install_err="curl: (60) SSL: ...",
                       has_xray=[False, True])
    vpn._install_xray(conn)
    fallback = [c for c in conn.calls if "wget" in c]
    assert fallback, "резервная установка через wget не запущена"
    assert "--local" in fallback[0]


def test_install_xray_raises_when_fallback_also_failed():
    import pytest
    conn = InstallConn(install_rc=0, install_err="curl: (60) SSL: ...",
                       has_xray=[False, False])
    with pytest.raises(RuntimeError, match="не установился"):
        vpn._install_xray(conn)


def test_install_xray_no_fallback_when_binary_present():
    """Живой выход (Xray стоит): резервный путь не трогаем, поведение как раньше."""
    conn = InstallConn(install_rc=1, install_err="network hiccup", has_xray=True)
    vpn._install_xray(conn)
    assert not any("wget" in c for c in conn.calls)


def test_install_xray_uses_pipefail():
    conn = InstallConn()
    vpn._install_xray(conn)
    assert any("pipefail" in c for c in conn.calls)
