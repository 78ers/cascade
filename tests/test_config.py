import json
from pathlib import Path

from cascade.config import (
    Config, ExitServer, Client, Panel, ShareToken, load_config, save_config,
    used_ports,
)


def test_used_ports_collects_all():
    cfg = Config(
        exit_servers=[
            ExitServer(id="a", relay_port=8444, vpn_port=8444),
            ExitServer(id="b", relay_port=8454, vpn_port=9000,
                       vpn_xhttp_enabled=True, vpn_xhttp_port=8455),
        ],
        mtproto_ports=[8443, 8500],
    )
    assert used_ports(cfg) == {8443, 8444, 8454, 8455, 8500, 9000}


def test_mtproto_labels_roundtrip(tmp_path):
    cfg = Config(mtproto_ports=[8443], mtproto_labels={"8443": "Вася"})
    p = tmp_path / "c.json"
    save_config(cfg, p)
    assert load_config(p).mtproto_labels == {"8443": "Вася"}


def test_panel_defaults():
    p = Panel()
    assert p.enabled is False
    assert p.user == "admin"
    assert p.password_hash == ""
    assert p.port == 8088


def test_sharetoken_defaults():
    t = ShareToken(token="abc", client_id="c1", created="2026-05-29T10:00:00+00:00")
    assert t.ttl_hours == 24


def test_config_panel_share_roundtrip(tmp_path: Path):
    cfg = Config(
        domain="tech.example.ru",
        panel=Panel(enabled=True, user="boss", password_hash="pbkdf2_sha256$1$aa$bb", port=8088),
        share_tokens=[ShareToken(token="tok1", client_id="c1",
                                 created="2026-05-29T10:00:00+00:00", ttl_hours=24)],
    )
    path = tmp_path / "config.json"
    save_config(cfg, path)
    loaded = load_config(path)
    assert loaded == cfg
    assert loaded.panel.user == "boss"
    assert loaded.share_tokens[0].token == "tok1"


def test_fingerprint_default_and_roundtrip(tmp_path: Path):
    assert Config().fingerprint == "firefox"
    cfg = Config(fingerprint="safari")
    path = tmp_path / "config.json"
    save_config(cfg, path)
    assert load_config(path).fingerprint == "safari"


def test_old_config_gets_fingerprint_default(tmp_path: Path):
    data = {"exit_servers": [], "clients": []}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert load_config(path).fingerprint == "firefox"


def test_old_config_gets_panel_defaults(tmp_path: Path):
    data = {"exit_servers": [], "clients": []}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    cfg = load_config(path)
    assert cfg.domain == ""
    assert cfg.panel == Panel()
    assert cfg.share_tokens == []


def test_sharetoken_partial_entry_no_crash(tmp_path: Path):
    # частичная запись share_tokens не должна ронять load_config (TypeError)
    data = {"exit_servers": [], "clients": [], "share_tokens": [{"token": "x"}]}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    cfg = load_config(path)
    assert cfg.share_tokens[0].token == "x"
    assert cfg.share_tokens[0].client_id == ""


def test_client_defaults():
    c = Client(id="c1", name="phone", uuid="u-123")
    assert c.enabled is True
    assert c.created == ""


def test_exit_server_new_fields():
    e = ExitServer(id="fin", location="Финляндия", ip="1.2.3.4")
    assert e.relay_port == 8444
    assert e.vpn_port == 8444
    assert e.vpn_sni == "www.google.com"
    assert e.vpn_xhttp_enabled is False
    assert e.reality_public_key == ""


def test_config_lists_default():
    cfg = Config()
    assert cfg.exit_servers == []
    assert cfg.clients == []
    assert cfg.vpn_name == "CASCADE VPN"
    assert cfg.mtproto_ports == [8443]


def test_save_load_roundtrip(tmp_path: Path):
    cfg = Config(
        exit_servers=[ExitServer(id="fin", location="Финляндия", ip="1.2.3.4",
                                 reality_public_key="PBK", reality_short_id="sid")],
        clients=[Client(id="c1", name="default", uuid="u-1", created="2026-05-29")],
        mtproto_secrets={"8443": "eeXX"},
    )
    path = tmp_path / "config.json"
    save_config(cfg, path)
    loaded = load_config(path)
    assert loaded == cfg
    assert loaded.exit_servers[0].ip == "1.2.3.4"
    assert loaded.clients[0].uuid == "u-1"


def test_load_missing_returns_none(tmp_path: Path):
    assert load_config(tmp_path / "nope.json") is None


def test_migrate_single_exit_to_multi(tmp_path: Path):
    # старый формат: один exit_server + vpn_clients dict + top-level ключи
    old = {
        "exit_server": {"name": "Финляндия", "ip": "9.9.9.9", "ssh_user": "root", "ssh_port": 22},
        "vpn_port": 8444, "vpn_sni": "www.bing.com",
        "vpn_clients": {"default": "uuid-old", "phone": "uuid-phone"},
        "vpn_private_key": "PRIV", "vpn_public_key": "PUB", "vpn_short_id": "SID",
        "vpn_xhttp_enabled": True, "vpn_xhttp_port": 8445, "vpn_xhttp_path": "abc",
        "vpn_name": "Мой VPN", "mtproto_ports": [8443],
    }
    path = tmp_path / "config.json"
    path.write_text(__import__("json").dumps(old), encoding="utf-8")
    cfg = load_config(path)
    assert len(cfg.exit_servers) == 1
    e = cfg.exit_servers[0]
    assert e.location == "Финляндия" and e.ip == "9.9.9.9"
    assert e.relay_port == 8444 and e.vpn_port == 8444
    assert e.vpn_sni == "www.bing.com"
    assert e.reality_private_key == "PRIV" and e.reality_public_key == "PUB"
    assert e.reality_short_id == "SID"
    assert e.vpn_xhttp_enabled is True and e.vpn_xhttp_path == "abc"
    names = {c.name: c.uuid for c in cfg.clients}
    assert names == {"default": "uuid-old", "phone": "uuid-phone"}
    assert all(c.enabled for c in cfg.clients)
    assert cfg.vpn_name == "Мой VPN"


def test_save_sets_600_perms(tmp_path: Path):
    cfg = Config(exit_servers=[ExitServer(id="x", ip="1.2.3.4")])
    path = tmp_path / "config.json"
    save_config(cfg, path)
    assert (path.stat().st_mode & 0o777) == 0o600


def test_primary_exit_explicit():
    from cascade.config import primary_exit
    cfg = Config(
        exit_servers=[ExitServer(id="ger"), ExitServer(id="est")],
        primary_exit_id="est",
    )
    assert primary_exit(cfg).id == "est"


def test_primary_exit_fallback_first():
    from cascade.config import primary_exit
    cfg = Config(exit_servers=[ExitServer(id="ger"), ExitServer(id="est")])
    assert primary_exit(cfg).id == "ger"


def test_primary_exit_stale_id_falls_back():
    from cascade.config import primary_exit
    cfg = Config(exit_servers=[ExitServer(id="ger")], primary_exit_id="gone")
    assert primary_exit(cfg).id == "ger"


def test_primary_exit_none_when_empty():
    from cascade.config import primary_exit
    assert primary_exit(Config()) is None


def test_primary_exit_id_roundtrip(tmp_path):
    cfg = Config(exit_servers=[ExitServer(id="est")], primary_exit_id="est")
    p = tmp_path / "c.json"
    save_config(cfg, p)
    assert load_config(p).primary_exit_id == "est"


def test_mtproto_exit_explicit():
    from cascade.config import mtproto_exit
    cfg = Config(exit_servers=[ExitServer(id="ger"), ExitServer(id="est")],
                 mtproto_exit_id="est")
    assert mtproto_exit(cfg).id == "est"


def test_mtproto_exit_fallback_first():
    from cascade.config import mtproto_exit
    cfg = Config(exit_servers=[ExitServer(id="ger"), ExitServer(id="est")])
    assert mtproto_exit(cfg).id == "ger"


def test_mtproto_exit_none_when_empty():
    from cascade.config import mtproto_exit
    assert mtproto_exit(Config()) is None


def test_mtproto_exit_id_roundtrip(tmp_path):
    cfg = Config(exit_servers=[ExitServer(id="est")], mtproto_exit_id="est")
    p = tmp_path / "c.json"
    save_config(cfg, p)
    assert load_config(p).mtproto_exit_id == "est"


def test_mtproto_port_exit_recorded():
    from cascade.config import mtproto_port_exit
    cfg = Config(exit_servers=[ExitServer(id="ger"), ExitServer(id="est")],
                 mtproto_port_exits={"8500": "est"})
    assert mtproto_port_exit(cfg, 8500).id == "est"


def test_mtproto_port_exit_legacy_fallback_first():
    # незамапленный (старый) порт → exit_servers[0], даже если mtproto_exit_id сменён
    from cascade.config import mtproto_port_exit
    cfg = Config(exit_servers=[ExitServer(id="ger"), ExitServer(id="est")],
                 mtproto_exit_id="est")
    assert mtproto_port_exit(cfg, 8443).id == "ger"


def test_mtproto_port_exit_stale_id_fallback():
    from cascade.config import mtproto_port_exit
    cfg = Config(exit_servers=[ExitServer(id="ger")],
                 mtproto_port_exits={"8500": "gone"})
    assert mtproto_port_exit(cfg, 8500).id == "ger"


def test_mtproto_port_exits_roundtrip(tmp_path):
    cfg = Config(exit_servers=[ExitServer(id="est")], mtproto_port_exits={"8500": "est"})
    p = tmp_path / "c.json"
    save_config(cfg, p)
    assert load_config(p).mtproto_port_exits == {"8500": "est"}
