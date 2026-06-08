import re
import shlex

import pytest

from cascade import sni
from cascade.config import Config, Panel, ExitServer, save_config
from cascade.panel.auth import hash_password
from cascade.panel.app import create_app


# ── чистая логика ──────────────────────────────────────────────────────────

def test_valid_domain():
    assert sni.valid_domain("www.bmw.de")
    assert sni.valid_domain("bmw.de")
    assert not sni.valid_domain("")
    assert not sni.valid_domain("no-dot")
    assert not sni.valid_domain("a b.de")
    assert not sni.valid_domain("x;reboot")
    assert not sni.valid_domain("evil.de; rm -rf /")


def test_build_check_cmd_quotes():
    cmd = sni.build_check_cmd("www.bmw.de")
    assert shlex.quote("www.bmw.de") in cmd
    assert "openssl s_client" in cmd and "curl" in cmd
    # инъекция обезврежена shlex.quote — домен в кавычках, не голой командой
    evil = sni.build_check_cmd("x;reboot")
    assert shlex.quote("x;reboot") in evil
    assert "d=x;reboot;" not in evil


def test_parse_check_ok():
    out = ("===OPENSSL===\nProtocol  : TLSv1.3\nServer Temp Key: X25519, 253 bits\n"
           "ALPN protocol: h2\n===CURL===\nHTTP=200 REDIR=")
    r = sni.parse_check(out)
    assert r["tls13"] and r["x25519"] and r["h2"]
    assert not r["redirected"]
    assert r["ok"]
    assert r["http_code"] == "200"


def test_parse_check_no_h2():
    out = "Protocol  : TLSv1.3\nServer Temp Key: X25519\n===CURL===\nHTTP=200 REDIR="
    r = sni.parse_check(out)
    assert not r["h2"]
    assert not r["ok"]


def test_parse_check_redirect():
    # кросс-доменный редирект — дисквалифицирует
    out = ("Protocol  : TLSv1.3\nX25519\nALPN protocol: h2\n"
           "===CURL===\nHTTP=301 REDIR=https://other.de/")
    r = sni.parse_check(out, "www.bmw.de")
    assert r["redirected"]
    assert r["redirect"] == "https://other.de/"
    assert not r["ok"]


def test_parse_check_same_domain_redirect():
    # path-redirect (bmw.de → bmw.de/de/) — Reality не ломает, годится
    out = ("===OPENSSL===\nProtocol  : TLSv1.3\nServer Temp Key: X25519, 253 bits\n"
           "ALPN protocol: h2\n===CURL===\nHTTP=302 REDIR=https://www.bmw.de/de/index.html")
    r = sni.parse_check(out, "www.bmw.de")
    assert not r["redirected"]
    assert r["ok"]


def test_parse_check_tls12_fail():
    out = "Protocol  : TLSv1.2\n===CURL===\nHTTP=200 REDIR="
    r = sni.parse_check(out)
    assert not r["tls13"]
    assert not r["ok"]


# ── роут панели ────────────────────────────────────────────────────────────

@pytest.fixture
def app_client(tmp_path):
    cfg = Config(
        panel=Panel(enabled=True, user="boss", password_hash=hash_password("pw")),
        exit_servers=[ExitServer(id="ger", location="GER", ip="1.2.3.4")],
    )
    p = tmp_path / "c.json"
    save_config(cfg, p)
    app = create_app(config_path=p, secret_path=tmp_path / "s")
    app.config.update(TESTING=True)
    return app.test_client()


def _login(c):
    pg = c.get("/boss")
    tok = re.search(r'name="csrf" value="([^"]+)"', pg.get_data(as_text=True)).group(1)
    c.post("/boss", data={"user": "boss", "password": "pw", "csrf": tok})


def _token(c, path="/boss/sni-check"):
    pg = c.get(path)
    return re.search(r'name="csrf" value="([^"]+)"', pg.get_data(as_text=True)).group(1)


def test_sni_page_get(app_client):
    _login(app_client)
    pg = app_client.get("/boss/sni-check")
    assert pg.status_code == 200
    assert "www.bmw.de" in pg.get_data(as_text=True)  # пресет на странице


def test_sni_check_post(monkeypatch, app_client):
    _login(app_client)
    tok = _token(app_client)

    class FakeRun:
        stdout = ("Protocol  : TLSv1.3\nServer Temp Key: X25519\nALPN protocol: h2\n"
                  "===CURL===\nHTTP=200 REDIR=")
        stderr = ""

    class FakeConn:
        def __init__(self, *a, **k):
            pass

        def run(self, cmd, timeout=25):
            return FakeRun()

    monkeypatch.setattr("cascade.panel.app.ServerConnection", FakeConn)
    pg = app_client.post("/boss/sni-check", data={"domain": "www.bmw.de", "csrf": tok})
    assert "годится" in pg.get_data(as_text=True)


def test_build_scan_cmd_quotes():
    cmd = sni.build_scan_cmd("1.2.3.4")
    assert shlex.quote("1.2.3.4") in cmd
    assert "realitls_scanner" in cmd
    assert "-addr" in cmd and "-thread" in cmd


def test_parse_scan_csv():
    csv = (
        "IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n"
        "1.2.3.4,example.com,www.example.com,Let's Encrypt,DE\n"
        "1.2.3.5,test.de,*.test.de,DigiCert,DE\n"
        "1.2.3.6,bad,  ,Some CA,DE\n"        # пустой домен — пропускаем
    )
    domains = sni.parse_scan_csv(csv)
    assert "www.example.com" in domains
    assert "test.de" in domains             # wildcard stripped
    assert len(domains) == 2                # пустой не считается


def test_parse_scan_csv_deduplication():
    csv = (
        "IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n"
        "1.2.3.4,a.com,same.com,CA,DE\n"
        "1.2.3.5,b.com,same.com,CA,DE\n"
    )
    assert sni.parse_scan_csv(csv) == ["same.com"]


def test_parse_scan_csv_new_format():
    # формат RealiTLScanner v0.2.3 (11 колонок, CERT_DOMAIN на индексе 8)
    csv = (
        "IP,ORIGIN,TLS,ALPN,CURVE,CERT_LENGTH,CERT_SIGNATURE,CERT_PUBLICKEY,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n"
        "10.20.30.7,yahoo.com,TLS 1.3,h2,X25519,3437,ECDSA,ECDH P-384,www.yahoo.com,DigiCert,DE\n"
        "10.20.30.42,github.com,TLS 1.3,h2,X25519,1280,ECDSA,ECDH P-384,github.com,Sectigo,DE\n"
        "10.20.30.99,bad,,,,,,,,\n"  # слишком короткая — пропустить
    )
    domains = sni.parse_scan_csv(csv)
    assert "www.yahoo.com" in domains
    assert "github.com" in domains
    assert len(domains) == 2


def test_parse_scan_csv_filters_bad_domains():
    # .ru, vpn-домены, vk.com — должны отфильтроваться
    csv = (
        "IP,ORIGIN,TLS,ALPN,CURVE,CERT_LENGTH,CERT_SIGNATURE,CERT_PUBLICKEY,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n"
        "1.1.1.1,x,TLS 1.3,h2,X25519,100,ECDSA,ECDSA,travel.yandex.ru,GlobalSign,DE\n"
        "1.1.1.2,x,TLS 1.3,h2,X25519,100,ECDSA,ECDSA,api.cavevpn.top,LE,DE\n"
        "1.1.1.3,x,TLS 1.3,h2,X25519,100,ECDSA,ECDSA,vk.com,GlobalSign,DE\n"
        "1.1.1.4,x,TLS 1.3,h2,X25519,100,ECDSA,ECDSA,yahoo.com,DigiCert,DE\n"
    )
    domains = sni.parse_scan_csv(csv)
    assert domains == ["yahoo.com"]  # только чистый домен прошёл


def test_sni_scan_post(monkeypatch, app_client):
    _login(app_client)
    tok = _token(app_client)

    class FakeRun:
        stdout = (
            "IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n"
            "1.2.3.4,neighbor.de,www.neighbor.de,Let's Encrypt,DE\n"
        )
        stderr = ""

    class FakeConn:
        def __init__(self, *a, **k): pass
        def run(self, cmd, timeout=90): return FakeRun()

    monkeypatch.setattr("cascade.panel.app.ServerConnection", FakeConn)
    pg = app_client.post("/boss/sni-scan", data={"csrf": tok})
    body = pg.get_data(as_text=True)
    assert pg.status_code == 200
    assert "www.neighbor.de" in body


def test_sni_check_bad_domain(app_client):
    _login(app_client)
    tok = _token(app_client)
    pg = app_client.post("/boss/sni-check", data={"domain": "x;reboot", "csrf": tok},
                         follow_redirects=True)
    # некорректный домен → не падаем, до SSH не доходим
    assert pg.status_code == 200
