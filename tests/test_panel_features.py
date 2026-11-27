import re

import pytest

from cascade.config import Config, Panel, ExitServer, Client, load_config, save_config
from cascade.panel.auth import hash_password
from cascade.panel.app import create_app


@pytest.fixture
def client_cfg(tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg = Config(
        panel=Panel(enabled=True, user="boss", password_hash=hash_password("pw")),
        exit_servers=[ExitServer(id="fin", location="Фин", ip="9.9.9.9",
                                 reality_public_key="PB", reality_short_id="S")],
        clients=[Client(id="c1", name="phone", uuid="u-1")],
    )
    save_config(cfg, cfg_path)
    app = create_app(config_path=cfg_path, secret_path=tmp_path / "sec")
    app.config.update(TESTING=True)
    return app.test_client(), cfg_path


def _login(c):
    page = c.get("/boss")
    m = re.search(r'name="csrf" value="([^"]+)"', page.get_data(as_text=True))
    return c.post("/boss", data={"user": "boss", "password": "pw", "csrf": m.group(1)})


def _token(c, path="/boss/clients"):
    page = c.get(path)
    return re.search(r'name="csrf" value="([^"]+)"', page.get_data(as_text=True)).group(1)


def test_diag_cmd_builds():
    import cascade.panel.app as appmod
    ex = ExitServer(id="e", location="GER", ip="1.2.3.4", vpn_port=8444)
    assert appmod._diag_cmd("ss", ex) == ["ss", "-tin", "dst 1.2.3.4"]
    assert appmod._diag_cmd("ping", ex)[:3] == ["ping", "-c", "20"]
    assert appmod._diag_cmd("ping", ex)[-1] == "1.2.3.4"
    mtr = appmod._diag_cmd("mtr", ex)
    assert "--tcp" in mtr and "8444" in mtr and mtr[-1] == "1.2.3.4"
    assert "speed_download" in appmod._diag_cmd("exit_speed", ex)
    speed = appmod._diag_cmd("speed", ex)
    assert "iperf3" in speed and " -R " in speed and "1.2.3.4" in speed
    assert appmod._diag_cmd("nope", ex) is None


def test_diag_test_ss_runs(client_cfg, monkeypatch):
    import types
    import cascade.panel.app as appmod
    c, _ = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    monkeypatch.setattr(appmod.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(stdout="cwnd:10 retrans:0", stderr="", returncode=0))
    _login(c)
    r = c.post("/boss/diag/test/ss", data={"csrf": _token(c)})
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "TCP-сессии" in body and "9.9.9.9" in body and "cwnd:10 retrans:0" in body


def test_diag_test_unknown_redirects(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    c, _ = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    _login(c)
    r = c.post("/boss/diag/test/bogus", data={"csrf": _token(c)})
    assert r.status_code in (301, 302)


def test_diag_test_requires_auth(client_cfg):
    c, _ = client_cfg
    assert c.post("/boss/diag/test/ss").status_code in (301, 302)


def test_fmt_msk_converts_utc_to_moscow():
    from cascade.panel.app import fmt_msk
    assert fmt_msk("2026-11-27T11:59:38.390853+00:00") == "27.11.2026 14:59"
    assert fmt_msk("2026-12-31T22:30:00+00:00") == "01.01.2027 01:30"   # переход через полночь и год
    assert fmt_msk("2026-11-27T11:59:38") == "27.11.2026 14:59"          # без часового пояса — считаем UTC
    assert fmt_msk("") == "—"
    assert fmt_msk("мусор") == "мусор"


def test_hwid_page_shows_time_in_moscow(client_cfg):
    c, cfg_path = client_cfg
    cfg = load_config(cfg_path)
    cfg.clients[0].hwid_list = [{"hwid": "abcdef0123456789zz", "first_seen": "2026-11-27T08:31:00+00:00",
                                 "last_seen": "2026-11-27T11:59:38+00:00", "user_agent": "iPhone 13 Pro iOS 4.12.0"}]
    save_config(cfg, cfg_path)
    _login(c)
    body = c.get("/boss/hwid").get_data(as_text=True)
    assert "27.11.2026 14:59" in body     # последнее обновление, часы и минуты по Москве
    assert "27.11.2026 11:31" in body     # первое появление
    assert "(МСК)" in body


def test_sub_records_profile_hash_and_hwid_page_marks_status(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    c, cfg_path = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    cfg = load_config(cfg_path)
    cfg.clients[0].sub_token = "tok1"
    save_config(cfg, cfg_path)
    # устройство запрашивает подписку: сервер записывает отметку выданного профиля
    r = c.get("/sub/tok1", headers={"X-Hwid": "dev-new", "X-Device-Model": "iPhone"})
    assert r.status_code == 200
    saved = load_config(cfg_path).clients[0].hwid_list[0]
    assert saved["profile_hash"] == appmod.profile_hash(r.get_data(as_text=True)) and saved["profile_exit"] == "fin"
    # второе устройство скачало «старый» профиль
    cfg = load_config(cfg_path)
    cfg.clients[0].hwid_list.append({"hwid": "dev-old-0123456789", "first_seen": "2026-11-27T08:00:00+00:00",
                                     "last_seen": "2026-11-27T09:00:00+00:00", "user_agent": "iPhone X",
                                     "profile_hash": "0badc0ffee00", "profile_exit": "fin"})
    save_config(cfg, cfg_path)
    _login(c)
    body = c.get("/boss/hwid").get_data(as_text=True)
    assert "✅ актуальный" in body and "не скачал новый" in body and "1 из 2 актуальны" in body
    # после смены SNI у выхода «новое» устройство перестаёт быть актуальным до следующего скачивания
    cfg = load_config(cfg_path)
    cfg.exit_servers[0].vpn_sni = "ya.ru"
    save_config(cfg, cfg_path)
    body = c.get("/boss/hwid").get_data(as_text=True)
    assert "✅ актуальный" not in body and "0 из 2 актуальны" in body


def test_fragment_button_toggles_flag_and_changes_subscription_profile(client_cfg, monkeypatch):
    import json as _j
    import cascade.panel.app as appmod
    c, cfg_path = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    cfg = load_config(cfg_path)
    cfg.clients[0].sub_token = "tok1"
    save_config(cfg, cfg_path)
    assert load_config(cfg_path).fragment_enabled is False
    before = c.get("/sub/tok1", headers={"X-Hwid": "dev-a"}).get_data(as_text=True)
    assert "finalmask" not in before
    _login(c)
    page = c.get("/boss/settings").get_data(as_text=True)
    assert "Включить защиту для всех клиентов" in page and "Сейчас: <b>выключена</b>" in page
    c.post("/boss/settings/fragment", data={"csrf": _token(c, "/boss/settings"), "enabled": "1"})
    assert load_config(cfg_path).fragment_enabled is True
    after = c.get("/sub/tok1", headers={"X-Hwid": "dev-a"}).get_data(as_text=True)
    stream = _j.loads(after)["outbounds"][0]["streamSettings"]
    assert stream["finalmask"]["tcp"][0]["settings"]["packets"] == "tlshello"
    assert appmod.profile_hash(after) != appmod.profile_hash(before)
    page = c.get("/boss/settings").get_data(as_text=True)
    assert "Выключить защиту" in page and "Сейчас: <b>включена</b>" in page
    c.post("/boss/settings/fragment", data={"csrf": _token(c, "/boss/settings"), "enabled": "0"})
    assert load_config(cfg_path).fragment_enabled is False
    assert c.get("/sub/tok1", headers={"X-Hwid": "dev-a"}).get_data(as_text=True) == before


def test_fragment_button_adds_fragment_param_to_links_and_qr(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    c, cfg_path = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    seen = []
    monkeypatch.setattr(appmod, "_qr_svg", lambda data: seen.append(data) or "<svg/>")
    cfg = load_config(cfg_path)
    cfg.domain = "t.example.ru"
    cfg.clients[0].sub_token = "tok1"
    save_config(cfg, cfg_path)
    _login(c)
    c.get("/boss/clients")
    assert seen and not any("fragment=" in x for x in seen)
    c.post("/boss/settings/fragment", data={"csrf": _token(c, "/boss/settings"), "enabled": "1"})
    seen.clear()
    body = c.get("/boss/clients").get_data(as_text=True)
    vless = [x for x in seen if x.startswith("vless://")]
    assert vless and all("&fragment=1-4,1-3,tlshello,60-80#" in x.split("\n")[0] for x in vless)
    assert any(x.startswith("vless://") and "\nhttps://t.example.ru/sub/tok1" in x for x in seen)
    assert "fragment=1-4,1-3,tlshello,60-80" in body


def test_fragment_button_rejects_missing_csrf_and_anonymous(client_cfg):
    c, cfg_path = client_cfg
    assert c.post("/boss/settings/fragment", data={"enabled": "1"}).status_code in (301, 302)
    assert load_config(cfg_path).fragment_enabled is False
    _login(c)
    c.post("/boss/settings/fragment", data={"csrf": "wrong", "enabled": "1"})
    assert load_config(cfg_path).fragment_enabled is False


def test_clients_requires_auth(client_cfg):
    c, _ = client_cfg
    assert c.get("/boss/clients").status_code in (301, 302)


def test_clients_lists_after_login(client_cfg):
    c, _ = client_cfg
    _login(c)
    r = c.get("/boss/clients")
    assert r.status_code == 200
    assert "phone" in r.get_data(as_text=True)


def test_share_creates_token_and_link(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    r = c.post("/boss/clients/c1/share", data={"csrf": _token(c)})
    assert r.status_code == 200
    assert "/c/" in r.get_data(as_text=True)
    assert len(load_config(cfg_path).share_tokens) == 1


def test_share_page_valid(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    monkeypatch.setattr(appmod, "_qr_svg", lambda d: "")
    c, cfg_path = client_cfg
    cfg = load_config(cfg_path)
    from cascade.panel.share import add_share
    st = add_share(cfg, "c1")
    save_config(cfg, cfg_path)
    r = c.get(f"/c/{st.token}")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Настройки для подключения" in body
    assert "vless://" in body


def test_share_page_invalid_token_no_leak(client_cfg):
    c, _ = client_cfg
    r = c.get("/c/nope")
    assert r.status_code == 200
    assert "vless" not in r.get_data(as_text=True).lower()


def test_clients_add_without_csrf_noop(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    c.post("/boss/clients/add", data={"name": "hacker"})  # без csrf
    assert "hacker" not in {cl.name for cl in load_config(cfg_path).clients}


def test_share_page_empty_relay_ip_no_broken_links(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "")
    c, cfg_path = client_cfg
    cfg = load_config(cfg_path)
    from cascade.panel.share import add_share
    st = add_share(cfg, "c1")
    save_config(cfg, cfg_path)
    r = c.get(f"/c/{st.token}")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "vless://" not in body
    assert "недоступен" in body


def test_exits_lists(client_cfg):
    c, _ = client_cfg
    _login(c)
    r = c.get("/boss/exits")
    assert r.status_code == 200 and "Фин" in r.get_data(as_text=True)


def test_settings_get(client_cfg):
    c, _ = client_cfg
    _login(c)
    assert c.get("/boss/settings").status_code == 200


def test_settings_post_domain(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    tok = _token(c, "/boss/settings")
    c.post("/boss/settings", data={"csrf": tok, "domain": "t.example.ru",
                                   "telegram_bot_token": "", "telegram_chat_id": ""})
    assert load_config(cfg_path).domain == "t.example.ru"


def test_settings_post_fingerprint(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    tok = _token(c, "/boss/settings")
    c.post("/boss/settings", data={"csrf": tok, "domain": "", "fingerprint": "firefox",
                                   "telegram_bot_token": "", "telegram_chat_id": ""})
    assert load_config(cfg_path).fingerprint == "firefox"


def test_settings_post_fingerprint_rejects_unknown(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    tok = _token(c, "/boss/settings")
    c.post("/boss/settings", data={"csrf": tok, "domain": "", "fingerprint": "netscape",
                                   "telegram_bot_token": "", "telegram_chat_id": ""})
    assert load_config(cfg_path).fingerprint == "firefox"


def test_exits_check_ensures_host_key(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    import cascade.ssh as sshmod
    calls = []
    monkeypatch.setattr(appmod, "_ensure_host_key", lambda ip, port: calls.append((ip, port)))
    monkeypatch.setattr(appmod.ServerConnection, "check_ssh", lambda self: None)
    monkeypatch.setattr(sshmod, "tcp_connect", lambda *a, **k: True)
    c, _ = client_cfg
    _login(c)
    tok = _token(c, "/boss/exits")
    r = c.post("/boss/exits/fin/check", data={"csrf": tok}, follow_redirects=True)
    assert r.status_code == 200
    assert calls == [("9.9.9.9", 22)]   # host-key обеспечивается до check_ssh
    assert "✓" in r.get_data(as_text=True)


def test_client_profile_json_download(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    c, _ = client_cfg
    _login(c)
    r = c.get("/boss/clients/c1/profile.json")
    assert r.status_code == 200
    assert r.content_type == "application/json"
    import json
    data = json.loads(r.get_data())
    assert "outbounds" in data


def test_client_profile_json_unknown_id(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    c, _ = client_cfg
    _login(c)
    r = c.get("/boss/clients/nope/profile.json")
    assert r.status_code == 404


def test_mtproto_page_requires_auth(client_cfg):
    c, _ = client_cfg
    assert c.get("/boss/mtproto").status_code in (301, 302)


def test_mtproto_page_redirects_to_clients(client_cfg):
    # MTProto слит в страницу «Клиенты» — GET редиректит
    c, _ = client_cfg
    _login(c)
    r = c.get("/boss/mtproto")
    assert r.status_code in (301, 302)


def test_mtproto_add_requires_auth(client_cfg):
    c, _ = client_cfg
    assert c.post("/boss/mtproto/add", data={}).status_code in (301, 302)


def test_mtproto_add_rejects_used_port(client_cfg):
    # порт 8444 занят выходом fin (relay/vpn) → в конфиг не попадает, SSH не дёргается
    c, cfg_path = client_cfg
    _login(c)
    tok = _token(c)
    c.post("/boss/mtproto/add",
           data={"csrf": tok, "port": "8444", "label": "x", "domain": "google.com"})
    assert 8444 not in load_config(cfg_path).mtproto_ports


def test_clients_toggle_without_csrf_noop(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    c.post("/boss/clients/c1/toggle", data={})  # без csrf
    assert load_config(cfg_path).clients[0].enabled is True


def test_clients_rename_without_csrf_noop(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    c.post("/boss/clients/c1/rename", data={"name": "hacked"})  # без csrf
    assert load_config(cfg_path).clients[0].name == "phone"


def test_exits_ip_rejects_bad_ip(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    tok = _token(c, "/boss/exits")
    c.post("/boss/exits/fin/ip", data={"csrf": tok, "ip": "not-an-ip"})
    assert load_config(cfg_path).exit_servers[0].ip == "9.9.9.9"


def test_share_tokens_page(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    cfg = load_config(cfg_path)
    from cascade.panel.share import add_share
    add_share(cfg, "c1")
    save_config(cfg, cfg_path)
    r = c.get("/boss/share")
    assert r.status_code == 200


def test_share_revoke(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    cfg = load_config(cfg_path)
    from cascade.panel.share import add_share
    st = add_share(cfg, "c1")
    save_config(cfg, cfg_path)
    tok = _token(c, "/boss/share")
    r = c.post(f"/boss/share/{st.token}/revoke", data={"csrf": tok})
    assert r.status_code in (200, 301, 302)
    assert len(load_config(cfg_path).share_tokens) == 0


def test_settings_post_interval(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    tok = _token(c, "/boss/settings")
    c.post("/boss/settings", data={
        "csrf": tok, "domain": "", "telegram_bot_token": "", "telegram_chat_id": "",
        "monitor_interval_min": "10", "auto_restart": "on",
    })
    cfg = load_config(cfg_path)
    assert cfg.monitor_interval_min == 10
    assert cfg.auto_restart is True


def test_sub_page_invalid_token_decoy(client_cfg):
    c, _ = client_cfg
    r = c.get("/sub/nope")
    assert r.status_code == 200
    body = r.get_data(as_text=True).lower()
    assert "vless" not in body and "vpn" not in body


def test_sub_page_valid_returns_json(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    c, cfg_path = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    cfg = load_config(cfg_path)
    cfg.clients[0].sub_token = "test-sub-tok"
    save_config(cfg, cfg_path)
    r = c.get("/sub/test-sub-tok")
    assert r.status_code == 200
    assert r.content_type.startswith("application/json")
    import json
    data = json.loads(r.get_data())
    assert "outbounds" in data  # полный xray-конфиг с routing
    assert r.headers.get("profile-title") == "phone"


def test_sub_token_generate(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    tok = _token(c)
    r = c.post("/boss/clients/c1/sub-token", data={"csrf": tok})
    assert r.status_code in (200, 301, 302)
    cfg = load_config(cfg_path)
    cl = next(cl for cl in cfg.clients if cl.id == "c1")
    assert cl.sub_token  # токен сгенерирован и сохранён


def test_sub_token_requires_auth(client_cfg):
    c, _ = client_cfg
    r = c.post("/boss/clients/c1/sub-token", data={"csrf": "x"})
    assert r.status_code in (301, 302)


def test_sub_serves_primary_exit_and_1h(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    from cascade.config import ExitServer
    c, cfg_path = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    cfg = load_config(cfg_path)
    cfg.exit_servers.append(ExitServer(id="est", location="EST", ip="7.7.7.7",
                                       reality_public_key="PBE", reality_short_id="SE",
                                       relay_port=8454, vpn_port=8454))
    cfg.primary_exit_id = "est"
    cfg.clients[0].sub_token = "tok-pri"
    save_config(cfg, cfg_path)
    r = c.get("/sub/tok-pri")
    assert r.status_code == 200
    assert r.headers.get("profile-update-interval") == "1"
    import json
    data = json.loads(r.get_data())
    vnext = data["outbounds"][0]["settings"]["vnext"][0]
    assert vnext["port"] == 8454


def test_profile_download_uses_primary(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    from cascade.config import ExitServer
    c, cfg_path = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    cfg = load_config(cfg_path)
    cfg.exit_servers.append(ExitServer(id="est", location="EST", ip="7.7.7.7",
                                       reality_public_key="PBE", reality_short_id="SE",
                                       relay_port=8454, vpn_port=8454))
    cfg.primary_exit_id = "est"
    save_config(cfg, cfg_path)
    _login(c)
    r = c.get("/boss/clients/c1/profile.json")
    assert r.status_code == 200
    assert "EST" in r.headers.get("Content-Disposition", "")


def test_exits_set_primary(client_cfg):
    from cascade.config import ExitServer
    c, cfg_path = client_cfg
    cfg = load_config(cfg_path)
    cfg.exit_servers.append(ExitServer(id="est", location="EST", ip="7.7.7.7"))
    save_config(cfg, cfg_path)
    _login(c)
    tok = _token(c, "/boss/exits")
    r = c.post("/boss/exits/est/primary", data={"csrf": tok})
    assert r.status_code in (200, 301, 302)
    assert load_config(cfg_path).primary_exit_id == "est"


def test_exits_set_primary_unknown(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    tok = _token(c, "/boss/exits")
    c.post("/boss/exits/nope/primary", data={"csrf": tok})
    assert load_config(cfg_path).primary_exit_id == ""


def test_mtproto_add_uses_selected_exit(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    from cascade.config import ExitServer
    import cascade.mtproto as mtmod
    c, cfg_path = client_cfg
    cfg = load_config(cfg_path)
    cfg.exit_servers.append(ExitServer(id="est", location="EST", ip="7.7.7.7"))
    save_config(cfg, cfg_path)
    captured = {}
    monkeypatch.setattr(appmod.relay, "port_listening", lambda p: False)
    monkeypatch.setattr(appmod.relay, "apply_rule",
                        lambda rule: captured.setdefault("dnat_ip", rule.target_ip))
    monkeypatch.setattr(mtmod, "exit_port_listening", lambda conn, p: False)
    monkeypatch.setattr(mtmod, "deploy_mtproto", lambda conn, p, domain: "ee-secret")
    _login(c)
    tok = _token(c, "/boss/clients")
    c.post("/boss/mtproto/add", data={"csrf": tok, "port": "8500",
                                      "domain": "google.com", "label": "x", "exit_id": "est"})
    saved = load_config(cfg_path)
    assert saved.mtproto_exit_id == "est"
    assert 8500 in saved.mtproto_ports
    assert captured["dnat_ip"] == "7.7.7.7"


def test_sni_scan_uses_selected_exit(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    from cascade.config import ExitServer
    c, cfg_path = client_cfg
    cfg = load_config(cfg_path)
    cfg.exit_servers.append(ExitServer(id="est", location="EST", ip="7.7.7.7"))
    save_config(cfg, cfg_path)
    seen = {}
    class FakeConn:
        def __init__(self, ip, *a, **k): seen["ip"] = ip
        def run(self, cmd, timeout=90):
            return type("R", (), {"stdout": "", "stderr": ""})()
    monkeypatch.setattr(appmod, "ServerConnection", FakeConn)
    _login(c)
    tok = _token(c, "/boss/sni-check")
    c.post("/boss/sni-scan", data={"csrf": tok, "eid": "est"})
    assert seen["ip"] == "7.7.7.7"


def test_diag_test_filters_exit(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    from cascade.config import ExitServer
    c, cfg_path = client_cfg
    cfg = load_config(cfg_path)
    cfg.exit_servers.append(ExitServer(id="est", location="EST", ip="7.7.7.7"))
    save_config(cfg, cfg_path)
    monkeypatch.setattr(appmod.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": "ok", "stderr": ""})())
    _login(c)
    tok = _token(c, "/boss/diag")
    r = c.post("/boss/diag/test/ss", data={"csrf": tok, "eid": "est"})
    body = r.get_data(as_text=True)
    assert "7.7.7.7" in body and "9.9.9.9" not in body


def test_mtproto_rotate_targets_ports_own_exit(client_cfg, monkeypatch):
    # порт развёрнут на первом выходе (fin); mtproto_exit_id переключён на est →
    # rotate должен бить в fin (выход порта), не в est
    import cascade.panel.app as appmod
    import cascade.mtproto as mtmod
    from cascade.config import ExitServer
    c, cfg_path = client_cfg
    cfg = load_config(cfg_path)
    cfg.exit_servers.append(ExitServer(id="est", location="EST", ip="7.7.7.7"))
    cfg.mtproto_ports = [8443]
    cfg.mtproto_secrets = {"8443": "ee-old"}
    cfg.mtproto_port_exits = {"8443": "fin"}
    cfg.mtproto_exit_id = "est"
    save_config(cfg, cfg_path)
    seen = {}
    class FakeConn:
        def __init__(self, ip, *a, **k): seen["ip"] = ip
        def run(self, *a, **k): return type("R", (), {"stdout": "", "stderr": ""})()
    monkeypatch.setattr(appmod, "ServerConnection", FakeConn)
    monkeypatch.setattr(mtmod, "gen_secret", lambda d: "ee-new")
    monkeypatch.setattr(mtmod, "deploy_mtproto", lambda *a, **k: "ee-new")
    monkeypatch.setattr(mtmod, "domain_from_secret", lambda s: "google.com")
    _login(c)
    tok = _token(c, "/boss/clients")
    c.post("/boss/mtproto/8443/rotate", data={"csrf": tok})
    assert seen["ip"] == "9.9.9.9"  # fin (выход порта), не est(7.7.7.7)


def test_client_profiles_include_json_per_exit(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    from cascade.config import ExitServer
    c, cfg_path = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    monkeypatch.setattr(appmod, "_qr_svg", lambda d: "")
    cfg = load_config(cfg_path)
    cfg.exit_servers.append(ExitServer(id="est", location="EST", ip="7.7.7.7",
                                       reality_public_key="PBE", reality_short_id="SE",
                                       relay_port=8454, vpn_port=8454))
    save_config(cfg, cfg_path)
    c2 = load_config(cfg_path)
    profs = appmod._client_profiles(c2, c2.clients[0], "5.5.5.5")
    assert len(profs) == 4
    import json as _j
    for p in profs:
        assert "outbounds" in _j.loads(p["json"])


def test_profile_download_exit_param(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    from cascade.config import ExitServer
    c, cfg_path = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    cfg = load_config(cfg_path)
    cfg.exit_servers.append(ExitServer(id="est", location="EST", ip="7.7.7.7",
                                       reality_public_key="PBE", reality_short_id="SE",
                                       relay_port=8454, vpn_port=8454))
    save_config(cfg, cfg_path)
    _login(c)
    r = c.get("/boss/clients/c1/profile.json?exit=est")
    assert r.status_code == 200
    assert "EST" in r.headers.get("Content-Disposition", "")


def test_sub_exit_param_overrides_primary(client_cfg, monkeypatch):
    import cascade.panel.app as appmod
    from cascade.config import ExitServer
    c, cfg_path = client_cfg
    monkeypatch.setattr(appmod, "_relay_ip", lambda: "5.5.5.5")
    cfg = load_config(cfg_path)
    cfg.exit_servers.append(ExitServer(id="est", location="EST", ip="7.7.7.7",
                                       reality_public_key="PBE", reality_short_id="SE",
                                       relay_port=8454, vpn_port=8454))
    cfg.primary_exit_id = "fin"
    cfg.clients[0].sub_token = "tok-x"
    save_config(cfg, cfg_path)
    import json as _j
    r0 = c.get("/sub/tok-x")
    assert _j.loads(r0.get_data())["outbounds"][0]["settings"]["vnext"][0]["port"] == 8444
    r1 = c.get("/sub/tok-x?exit=est")
    assert _j.loads(r1.get_data())["outbounds"][0]["settings"]["vnext"][0]["port"] == 8454


def test_hwid_page_loads(client_cfg):
    c, _ = client_cfg
    _login(c)
    resp = c.get("/boss/hwid")
    assert resp.status_code == 200
    assert "Устройства" in resp.get_data(as_text=True)


def test_hwid_page_shows_clients(client_cfg):
    c, cfg_path = client_cfg
    _login(c)
    from cascade.config import record_hwid
    cfg = load_config(cfg_path)
    record_hwid(cfg.clients[0], "abc123", "Happ iOS")
    save_config(cfg, cfg_path)
    resp = c.get("/boss/hwid")
    text = resp.get_data(as_text=True)
    assert "phone" in text
    assert "abc123" in text
