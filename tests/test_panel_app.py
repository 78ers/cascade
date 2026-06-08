import re
from pathlib import Path

import pytest

from cascade.config import Config, Panel, save_config
from cascade.panel.auth import hash_password
from cascade.panel.app import create_app


@pytest.fixture
def app_client(tmp_path: Path):
    cfg_path = tmp_path / "config.json"
    secret_path = tmp_path / "panel_secret"
    cfg = Config(panel=Panel(enabled=True, user="boss",
                             password_hash=hash_password("pw123")))
    save_config(cfg, cfg_path)
    app = create_app(config_path=cfg_path, secret_path=secret_path)
    app.config.update(TESTING=True)
    return app.test_client()


def _login(client, user="boss", pw="pw123"):
    page = client.get("/boss")
    m = re.search(r'name="csrf" value="([^"]+)"', page.get_data(as_text=True))
    token = m.group(1) if m else ""
    return client.post("/boss", data={"user": user, "password": pw, "csrf": token})


def test_decoy_root_200_no_vpn_hint(app_client):
    r = app_client.get("/")
    assert r.status_code == 200
    body = r.get_data(as_text=True).lower()
    assert "vless" not in body and "vpn" not in body and "proxy" not in body


def test_login_get_shows_form(app_client):
    r = app_client.get("/boss")
    assert r.status_code == 200
    assert 'name="password"' in r.get_data(as_text=True)


def test_login_wrong_password(app_client):
    _login(app_client, pw="WRONG")
    d = app_client.get("/boss/")
    assert d.status_code in (301, 302)


def test_login_right_then_dashboard(app_client, monkeypatch):
    import cascade.panel.app as appmod
    monkeypatch.setattr(appmod, "check_once", lambda c: [])
    _login(app_client)
    d = app_client.get("/boss/")
    assert d.status_code == 200


def test_dashboard_requires_auth(app_client):
    r = app_client.get("/boss/")
    assert r.status_code in (301, 302)


def test_csrf_rejected(app_client):
    app_client.post("/boss", data={"user": "boss", "password": "pw123", "csrf": "bad"})
    d = app_client.get("/boss/")
    assert d.status_code in (301, 302)


def test_logout(app_client, monkeypatch):
    import cascade.panel.app as appmod
    monkeypatch.setattr(appmod, "check_once", lambda c: [])
    _login(app_client)
    app_client.get("/boss/logout")
    d = app_client.get("/boss/")
    assert d.status_code in (301, 302)


def test_dashboard_renders_counts(app_client, monkeypatch):
    import cascade.panel.app as appmod
    monkeypatch.setattr(appmod, "check_once", lambda c: [("Фин VPN", "1.1.1.1", 8444, True)])
    _login(app_client)
    r = app_client.get("/boss/")
    assert r.status_code == 200
    assert "Фин VPN" in r.get_data(as_text=True)
