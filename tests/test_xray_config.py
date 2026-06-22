import json

from cascade.xray_config import (
    build_client_xray_config, build_xray_config, gen_short_id, parse_x25519,
    vless_reality_url, vless_xhttp_url,
)


def test_gen_short_id_is_hex_even():
    sid = gen_short_id()
    assert len(sid) == 16
    int(sid, 16)  # не бросит, если hex


def test_parse_x25519_classic():
    out = "Private key: AAA_priv\nPublic key: BBB_pub\n"
    priv, pub = parse_x25519(out)
    assert priv == "AAA_priv"
    assert pub == "BBB_pub"


def test_parse_x25519_new_format():
    out = "PrivateKey: XPRIV\nPassword: XPUB\n"
    priv, pub = parse_x25519(out)
    assert priv == "XPRIV"
    assert pub == "XPUB"


def test_build_config_reality_only():
    cfg = build_xray_config(
        clients={"default": "U", "alice": "U2"},
        private_key="PK", short_id="SID", sni="www.google.com",
        vpn_port=8444,
    )
    data = json.loads(cfg)
    inbounds = data["inbounds"]
    assert len(inbounds) == 1
    ib = inbounds[0]
    assert ib["port"] == 8444
    assert ib["protocol"] == "vless"
    rs = ib["streamSettings"]["realitySettings"]
    assert rs["serverNames"] == ["www.google.com"]
    assert rs["privateKey"] == "PK"
    assert rs["shortIds"] == ["SID"]
    clients = ib["settings"]["clients"]
    assert len(clients) == 2
    assert all(c["flow"] == "xtls-rprx-vision" for c in clients)
    ids = {c["id"] for c in clients}
    assert ids == {"U", "U2"}
    emails = {c["email"] for c in clients}
    assert emails == {"default", "alice"}


def test_build_config_with_xhttp():
    cfg = build_xray_config(
        clients={"default": "U"},
        private_key="PK", short_id="SID", sni="www.google.com",
        vpn_port=8444, xhttp_port=8445, xhttp_path="abc123",
    )
    data = json.loads(cfg)
    nets = {ib["streamSettings"]["network"] for ib in data["inbounds"]}
    assert nets == {"tcp", "xhttp"}
    # XHTTP inbound: flow обязан быть пустым
    xhttp_ib = [ib for ib in data["inbounds"] if ib["streamSettings"]["network"] == "xhttp"][0]
    assert xhttp_ib["settings"]["clients"][0]["flow"] == ""


def test_build_config_sni_legacy():
    # legacy SNI добавляются в serverNames — клиенты на старом SNI не теряют связь
    cfg = build_xray_config(
        clients={"default": "U"}, private_key="PK", short_id="SID",
        sni="yahoo.com", vpn_port=8444,
        sni_legacy=["www.google.com", "www.siemens.com"],
    )
    rs = json.loads(cfg)["inbounds"][0]["streamSettings"]["realitySettings"]
    assert rs["serverNames"] == ["yahoo.com", "www.google.com", "www.siemens.com"]


def test_build_config_sni_legacy_no_duplicates():
    # legacy не должен дублировать текущий SNI
    cfg = build_xray_config(
        clients={"default": "U"}, private_key="PK", short_id="SID",
        sni="yahoo.com", vpn_port=8444, sni_legacy=["yahoo.com"],
    )
    rs = json.loads(cfg)["inbounds"][0]["streamSettings"]["realitySettings"]
    assert rs["serverNames"] == ["yahoo.com"]


def test_build_config_freedom_ipv4():
    # выход обязан ходить наружу только по IPv4 (иначе флаки v6 → фризы)
    cfg = build_xray_config(clients={"default": "U"}, private_key="PK",
                            short_id="SID", sni="s", vpn_port=8444)
    out = json.loads(cfg)["outbounds"][0]
    assert out["protocol"] == "freedom"
    assert out["settings"]["domainStrategy"] == "UseIPv4"


def test_build_config_logs_disabled():
    cfg = build_xray_config(clients={"default": "U"}, private_key="PK",
                            short_id="SID", sni="s", vpn_port=8444)
    data = json.loads(cfg)
    assert data["log"]["access"] == "none"
    assert data["log"]["error"] == "none"


def test_vless_reality_url():
    url = vless_reality_url(
        uuid="U", host="1.2.3.4", port=8444, sni="www.google.com",
        public_key="PBK", short_id="SID", name="phone",
    )
    assert url.startswith("vless://U@1.2.3.4:8444?")
    assert "security=reality" in url
    assert "flow=xtls-rprx-vision" in url
    assert "sni=www.google.com" in url
    assert "pbk=PBK" in url
    assert "sid=SID" in url
    assert "type=tcp" in url
    assert url.endswith("#phone")


def test_build_client_config_split_routing():
    cfg = build_client_xray_config(
        uuid="U", public_key="PBK", short_id="SID", host="1.2.3.4",
        sni="www.google.com", vpn_port=8444,
    )
    data = json.loads(cfg)
    # три outbound: proxy/direct/block
    tags = {o["tag"] for o in data["outbounds"]}
    assert tags == {"proxy", "direct", "block"}
    proxy = [o for o in data["outbounds"] if o["tag"] == "proxy"][0]
    vnext = proxy["settings"]["vnext"][0]
    assert vnext["address"] == "1.2.3.4"  # host = IP моста (РФ)
    assert vnext["port"] == 8444
    assert vnext["users"][0]["flow"] == "xtls-rprx-vision"
    rs = proxy["streamSettings"]["realitySettings"]
    assert rs["publicKey"] == "PBK"
    assert rs["serverName"] == "www.google.com"
    rules = data["routing"]["rules"]
    direct_dom_rules = [r for r in rules if r["outboundTag"] == "direct" and "domain" in r]
    all_direct_domains = [d for r in direct_dom_rules for d in r["domain"]]
    assert "geosite:category-ru" in all_direct_domains
    assert "domain:qq.com" in all_direct_domains  # WeChat → direct списком корневых доменов
    assert "geosite:cn" not in all_direct_domains  # китайская geo-база НЕ грузится (лимит памяти iOS 50МБ)
    assert "geosite:telegram" not in all_direct_domains  # Telegram → каскад через catch-all, не direct
    direct_ip = [r for r in rules if r["outboundTag"] == "direct" and "ip" in r][0]
    assert "geoip:ru" in direct_ip["ip"]
    assert "geoip:private" in direct_ip["ip"]
    assert "119.29.29.29" in direct_ip["ip"]  # китайский DNS-резолвер WeChat ходит direct, не каскадом
    assert "geoip:cn" not in direct_ip["ip"]  # geoip:cn убран — превышал лимит памяти туннеля iOS
    # последнее правило — всё прочее в каскад
    assert rules[-1]["outboundTag"] == "proxy"


def test_build_client_config_dns_split():
    cfg = build_client_xray_config(
        uuid="U", public_key="P", short_id="S", host="h", sni="s", vpn_port=8444,
    )
    data = json.loads(cfg)
    servers = data["dns"]["servers"]
    # РФ-домены резолвятся через РФ-DNS
    ru = [s for s in servers
          if isinstance(s, dict) and "geosite:category-ru" in s.get("domains", [])]
    assert ru and ru[0]["address"] == "77.88.8.8"
    assert "geoip:ru" in ru[0]["expectIPs"]
    # WeChat-домены — китайский DNS (DNSPod) без expectIPs (Xray кэширует IP для UDP-звонков)
    wc = [s for s in servers
          if isinstance(s, dict) and "domain:qq.com" in s.get("domains", [])]
    assert wc and wc[0]["address"] == "119.29.29.29"
    assert "expectIPs" not in wc[0]
    # прочее — через DoH (строка-URL)
    assert any(isinstance(s, str) and s.startswith("https://") for s in servers)


def test_build_client_config_inbounds_local():
    cfg = build_client_xray_config(
        uuid="U", public_key="P", short_id="S", host="h", sni="s", vpn_port=8444,
    )
    data = json.loads(cfg)
    protos = {ib["protocol"] for ib in data["inbounds"]}
    assert protos == {"socks", "http"}
    for ib in data["inbounds"]:
        assert ib["listen"] == "127.0.0.1"


def test_vless_xhttp_url():
    url = vless_xhttp_url(
        uuid="U", host="cdn.example.ru", port=443, sni="cdn.example.ru",
        xhttp_path="p1", name="pc",
    )
    assert url.startswith("vless://U@cdn.example.ru:443?")
    assert "type=xhttp" in url
    assert "security=tls" in url
    assert "path=%2Fp1" in url


# Task 6: Profile helpers for cascade/direct
from cascade.config import ExitServer, Client
from cascade.xray_config import client_profile_json, client_profile_url


def _exit():
    return ExitServer(id="fin", location="Финляндия", ip="9.9.9.9",
                      relay_port=8444, vpn_port=8444, vpn_sni="www.google.com",
                      reality_public_key="PBK", reality_short_id="SID")


def test_profile_cascade_uses_relay_ip_and_relay_port():
    data = json.loads(client_profile_json("u-1", _exit(), relay_ip="5.5.5.5", direct=False))
    vnext = [o for o in data["outbounds"] if o["tag"] == "proxy"][0]["settings"]["vnext"][0]
    assert vnext["address"] == "5.5.5.5"   # мост РФ
    assert vnext["port"] == 8444           # relay_port


def test_profile_direct_uses_exit_ip_and_vpn_port():
    data = json.loads(client_profile_json("u-1", _exit(), relay_ip="5.5.5.5", direct=True))
    vnext = [o for o in data["outbounds"] if o["tag"] == "proxy"][0]["settings"]["vnext"][0]
    assert vnext["address"] == "9.9.9.9"   # сам выход
    assert vnext["port"] == 8444           # vpn_port


def test_profile_url_cascade_vs_direct():
    e = _exit()
    cascade = client_profile_url("u-1", e, relay_ip="5.5.5.5", name="phone", direct=False)
    direct = client_profile_url("u-1", e, relay_ip="5.5.5.5", name="phone", direct=True)
    assert "@5.5.5.5:8444" in cascade
    assert "@9.9.9.9:8444" in direct
    assert "pbk=PBK" in cascade and "sid=SID" in cascade


def test_profile_json_fingerprint_threads():
    data = json.loads(client_profile_json("u-1", _exit(), relay_ip="5.5.5.5",
                                          fingerprint="firefox"))
    proxy = [o for o in data["outbounds"] if o["tag"] == "proxy"][0]
    assert proxy["streamSettings"]["realitySettings"]["fingerprint"] == "firefox"


def test_profile_url_fingerprint_threads():
    url = client_profile_url("u-1", _exit(), relay_ip="5.5.5.5", name="phone",
                             fingerprint="firefox")
    assert "fp=firefox" in url


def test_profile_default_fingerprint_firefox():
    data = json.loads(client_profile_json("u-1", _exit(), relay_ip="5.5.5.5"))
    proxy = [o for o in data["outbounds"] if o["tag"] == "proxy"][0]
    assert proxy["streamSettings"]["realitySettings"]["fingerprint"] == "firefox"


from cascade.xray_config import (
    vless_xhttp_reality_url, client_xhttp_profile_json, client_xhttp_profile_url,
)


def _exit_xhttp():
    return ExitServer(id="ger", location="GER", ip="9.9.9.9",
                      relay_port=8444, vpn_port=8444, vpn_sni="www.bmw.de",
                      vpn_xhttp_enabled=True, vpn_xhttp_port=8445, vpn_xhttp_path="p1path",
                      reality_public_key="PBK", reality_short_id="SID")


def test_client_config_default_unchanged_is_tcp_vision():
    # БЕЗ xhttp_path профиль остаётся ровно прежним (tcp+vision) — текущие клиенты не страдают
    data = json.loads(build_client_xray_config(
        uuid="U", public_key="P", short_id="S", host="h", sni="s", vpn_port=8444,
    ))
    proxy = [o for o in data["outbounds"] if o["tag"] == "proxy"][0]
    assert proxy["streamSettings"]["network"] == "tcp"
    assert proxy["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert "xhttpSettings" not in proxy["streamSettings"]


def test_client_config_xhttp_switches_transport():
    data = json.loads(build_client_xray_config(
        uuid="U", public_key="P", short_id="S", host="h", sni="s", vpn_port=8445,
        xhttp_path="p1path",
    ))
    proxy = [o for o in data["outbounds"] if o["tag"] == "proxy"][0]
    ss = proxy["streamSettings"]
    assert ss["network"] == "xhttp"
    assert ss["security"] == "reality"               # не tls — наш inbound на Reality
    assert ss["xhttpSettings"]["path"] == "/p1path"
    # vision-flow ломает XHTTP → flow обязан быть пустым
    assert proxy["settings"]["vnext"][0]["users"][0]["flow"] == ""
    # сплит-routing сохранён (РФ/WeChat → direct)
    rules = data["routing"]["rules"]
    all_direct = [d for r in rules if r["outboundTag"] == "direct" and "domain" in r for d in r["domain"]]
    assert "geosite:category-ru" in all_direct


def test_vless_xhttp_reality_url_has_pbk_sid():
    url = vless_xhttp_reality_url(
        uuid="U", host="5.5.5.5", port=8445, sni="www.bmw.de",
        public_key="PBK", short_id="SID", xhttp_path="p1", name="pc",
    )
    assert url.startswith("vless://U@5.5.5.5:8445?")
    assert "type=xhttp" in url
    assert "security=reality" in url     # Reality, не tls
    assert "pbk=PBK" in url and "sid=SID" in url
    assert "path=%2Fp1" in url


def test_client_xhttp_profile_uses_bridge_and_xhttp_port():
    # cascade через мост: host=relay_ip, port=vpn_xhttp_port, path из выхода
    e = _exit_xhttp()
    data = json.loads(client_xhttp_profile_json("u-1", e, relay_ip="5.5.5.5"))
    vnext = [o for o in data["outbounds"] if o["tag"] == "proxy"][0]["settings"]["vnext"][0]
    assert vnext["address"] == "5.5.5.5"   # мост РФ
    assert vnext["port"] == 8445           # vpn_xhttp_port
    url = client_xhttp_profile_url("u-1", e, relay_ip="5.5.5.5", name="phone")
    assert "@5.5.5.5:8445" in url and "path=%2Fp1path" in url


def test_server_config_no_sniffing():
    # Выход — «тупая труба», sniffing только жрёт CPU. Не должен быть в inbound.
    data = json.loads(build_xray_config(
        clients={"u": "uid"}, private_key="PK", short_id="SID",
        sni="yahoo.com", vpn_port=8444,
    ))
    for ib in data["inbounds"]:
        assert not ib.get("sniffing", {}).get("enabled", False), \
            "sniffing должен быть выключен на серверном inbound"


def test_server_config_has_freedom_ipv4():
    # UseIPv4 обязателен — без него happy-eyeballs предпочитает IPv6 → нестабильный транзит
    data = json.loads(build_xray_config(
        clients={"u": "uid"}, private_key="PK", short_id="SID",
        sni="yahoo.com", vpn_port=8444,
    ))
    freedom = next(o for o in data["outbounds"] if o["protocol"] == "freedom")
    assert freedom["settings"]["domainStrategy"] == "UseIPv4"
