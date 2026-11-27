"""Чистая генерация Xray config.json (Reality/XHTTP), ключей и VLESS-ссылок.

Референс структур: meridian-main/src/meridian/provision/xray.py и protocols.py.
Отличие: emit raw config.json для systemd-xray, без 3x-ui API.
"""
from __future__ import annotations

import json
import secrets
import uuid as _uuid

DEFAULT_FINGERPRINT = "firefox"   # chrome-отпечаток режет РФ-DPI; firefox проходит
# Поддерживаемые Xray uTLS-отпечатки (маскировка TLS ClientHello)
FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "android",
                "edge", "360", "qq", "random", "randomized"]

# Дробление первого пакета TLS (ClientHello) на ≈70 кусков по 1–4 байта: имя SNI не лежит
# в одном пакете, оператор, режущий по имени, его не видит. Формат ядра Xray (finalmask);
# maxSplit здесь не равен числу кусков (у ссылки Happ fragment=… он равен), значения подобраны замером.
FRAGMENT_SETTINGS = {"packets": "tlshello", "length": "1-4", "delay": "1-2", "maxSplit": "250-300"}
# То же дробление для ссылки vless:// (параметр fragment приложения Happ: длина, интервал, пакеты, число кусков).
FRAGMENT_LINK = "1-4,1-3,tlshello,60-80"

# WeChat → direct: из РФ напрямую быстрее, чем крюком через Европу.
# Список корневых доменов вместо geosite:cn/geoip:cn — китайская geo-база огромна
# и превышает лимит памяти туннеля на iOS (Network Extension ~50 МБ). Один
# domain:qq.com накрывает всю qq.com-семью (weixin/wx/tc/video/v/wxs/dldir1...);
# медиа-CDN WeChat живут на отдельных корнях (qpic.cn/qlogo.cn/myqcloud.com/
# wechatos.net/smtcdns) — их domain:qq.com НЕ покрывает, перечислены явно.
# Правило по домену срабатывает, только если домен виден: из sniffing (TLS SNI, HTTP Host)
# или из самого запроса. Обратного сопоставления IP → домен по кэшу DNS в Xray нет:
# соединения WeChat по голому IP (звонки по UDP, собственный протокол) этим правилам
# не подходят и уходят в каскад.
# geosite:tencent (backstop-категория) УБРАН 2026-06-26 — самый тяжёлый по RAM при
# росте встроенных geo-баз Happ; явный список ниже сверен с эталоном blackmatrix7
# WeChat.yaml (+ Grok/Gemini) и покрывает экосистему. Новый Tencent-домен — дописать сюда.
WECHAT_DOMAINS = [
    "domain:qq.com",           # вся qq.com-семья: чат, voip-сигналинг, Channels-видео
                               # (tc/video/v.qq.com), статьи (mp.weixin), загрузки (dldir1)
    "domain:qpic.cn",          # картинки: Moments (mmsns), статьи (mmbiz), стикеры
    "domain:qlogo.cn",         # аватары (wx.qlogo.cn)
    "domain:myqcloud.com",     # Tencent Cloud CDN, медиа мини-программ
    "domain:gtimg.com",        # Tencent статика-CDN (фото/видео/файлы)
    "domain:gtimg.cn",
    "domain:url.cn",           # короткие ссылки
    "domain:weixin.com",
    "domain:wechat.com",       # международный WeChat
    "domain:wechatpay.com",    # WeChat Pay
    "domain:tenpay.com",       # платежи Tenpay
    "domain:servicewechat.com",  # мини-программы
    "domain:wechatos.net",     # зарубежный asset-CDN WeChat (CNAME картинок/стикеров)
    "domain:smtcdns.com",      # Tencent Smart CDN (динамический CNAME-таргет медиа)
    "domain:smtcdns.net",
    # дополнено 2026-06-26 (сверка blackmatrix7 WeChat.yaml + Grok + Gemini):
    "domain:weixinbridge.com",   # открытие внешних ссылок/webview/deep-link внутри WeChat
    "domain:weixinsxy.com",      # служебные эндпоинты / раздача ресурсов
    "domain:wechatlegal.net",    # auth-политики / compliance / логин-handshake
    "domain:iot-tencent.com",    # WeChat IoT / устройства
    "domain:wechatpay.cn",       # домашние CDN-зеркала WeChat Pay
    "domain:tencentmap.com",     # карты / локация в мини-программах
    "full:apd-pcdnwxlogin.teg.tencent-cloud.net",  # P-CDN логина (точечно, не весь tencent-cloud.net)
    "full:slife.xy-asia.com",    # сервис WeChat (точечно)
]


# Режим dns_from_json (клиент с отметкой Client.dns_from_json): подписка шлёт Happ
# dns-from-json-enable, Happ ставит DNS туннеля = адрес первой записи dns.servers (DoU).
# Запросы приложений на этот адрес перехватываются в DNS-модуль Xray (outbound dns),
# и наш раздельный DNS работает для приложений. Перехват не сработал — запросы уходят
# на 8.8.8.8 через туннель, как без режима.
TUNNEL_DNS_IP = "8.8.8.8"
# Подсеть China Telecom (Шанхай) для доменов WeChat: Tencent отдаёт по ней узлы в сетях
# China Telecom, а для РФ/EE/США — в своём зарубежном облаке (AS132203, AS139341).
WECHAT_DNS_CLIENT_IP = "101.80.0.1"
# Домены WeChat из v2fly/domain-list-community (data/tencent), которых нет в WECHAT_DOMAINS.
WECHAT_DOMAINS_EXTRA = [
    "domain:wxlivecdn.com",      # трансляции
    "domain:wxgateway.com",
    "domain:wxcloudrun.com",
    "domain:mmbizurl.cn",        # короткие ссылки
    "domain:wxaurl.cn",
    "domain:wxmpurl.cn",
    "domain:tenpayglobal.com",   # WeChat Pay
]


def gen_uuid() -> str:
    return str(_uuid.uuid4())


def gen_short_id() -> str:
    return secrets.token_hex(8)  # 16 hex символов


def parse_x25519(output: str) -> "tuple[str, str]":
    """Вытащить (private, public) из вывода `xray x25519`.

    Поддерживает classic (Private key:/Public key:) и новый (PrivateKey:/Password:).
    """
    priv = pub = ""
    for line in output.splitlines():
        low = line.lower()
        if "private" in low:
            priv = line.split(":", 1)[1].strip()
        elif "public" in low or "password" in low:
            pub = line.split(":", 1)[1].strip()
    if not priv or not pub:
        raise ValueError(f"Не удалось распарсить xray x25519: {output!r}")
    return priv, pub


def _reality_inbound(clients: dict, private_key, short_id, sni, port, fingerprint, network, xhttp_path="",
                     sni_legacy: list | None = None):
    """clients = {"имя": "uuid", ...}"""
    if network == "tcp":
        flow = "xtls-rprx-vision"
    else:  # xhttp — vision-flow ломает XHTTP, flow обязан быть пустым
        flow = ""
    stream = {
        "network": network,
        "security": "reality",
        "realitySettings": {
            "show": False,
            "dest": f"{sni}:443",
            "xver": 0,
            "serverNames": [sni] + [s for s in (sni_legacy or []) if s and s != sni],
            "privateKey": private_key,
            "shortIds": [short_id],
        },
    }
    if network == "tcp":
        stream["tcpSettings"] = {"header": {"type": "none"}}
    else:
        stream["xhttpSettings"] = {"mode": "auto", "path": f"/{xhttp_path}"}
    return {
        "listen": "0.0.0.0",
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": uid, "flow": flow, "email": name}
                        for name, uid in clients.items()],
            "decryption": "none",
        },
        "streamSettings": stream,
    }


def build_xray_config(
    clients: dict, private_key: str, short_id: str, sni: str, vpn_port: int,
    fingerprint: str = DEFAULT_FINGERPRINT,
    xhttp_port: int = 0, xhttp_path: str = "",
    sni_legacy: list | None = None,
) -> str:
    """Собрать полный Xray config.json. clients = {"имя": "uuid"}.
    XHTTP-inbound добавляется если xhttp_port>0.
    sni_legacy — старые SNI, принимаются параллельно пока клиенты обновляют подписки."""
    inbounds = [
        _reality_inbound(clients, private_key, short_id, sni, vpn_port, fingerprint, "tcp",
                         sni_legacy=sni_legacy),
    ]
    if xhttp_port and xhttp_path:
        inbounds.append(
            _reality_inbound(clients, private_key, short_id, sni, xhttp_port,
                             fingerprint, "xhttp", xhttp_path, sni_legacy=sni_legacy)
        )
    config = {
        "log": {"access": "none", "error": "none", "loglevel": "warning"},
        "inbounds": inbounds,
        # UseIPv4: исходящий резолв только по A-записям. Без него Go-дефолт
        # happy-eyeballs предпочитает IPv6 → флаки v6-транзит хостера даёт фризы.
        "outbounds": [{
            "protocol": "freedom", "tag": "direct",
            "settings": {"domainStrategy": "UseIPv4"},
        }],
    }
    return json.dumps(config, indent=2)


def build_client_xray_config(
    uuid: str, public_key: str, short_id: str, host: str, sni: str,
    vpn_port: int, fingerprint: str = DEFAULT_FINGERPRINT,
    socks_port: int = 10808, http_port: int = 10809,
    xhttp_path: str = "",
    dns_from_json: bool = False,
    fragment: bool = False,
) -> str:
    """Клиентский config.json со сплит-routing: РФ → direct, прочее → каскад.

    host = IP моста (РФ), точка входа каскада — НЕ сервер выхода.
    geoip/geosite встроены в клиент, скачивать не нужно.
    Совместим с Happ, OneXray, v2rayNG, Nekoray, NekoBox (все на Xray-core).
    xhttp_path задан → транспорт XHTTP+Reality (vision-flow ломает XHTTP → flow=""),
    иначе raw TCP+Reality+vision (дефолт).
    """
    # vision-flow совместим только с raw TCP; XHTTP требует пустой flow
    realitySettings = {
        "serverName": sni,
        "fingerprint": fingerprint,
        "publicKey": public_key,
        "shortId": short_id,
        "spiderX": "",
    }
    if xhttp_path:
        flow = ""
        stream = {"network": "xhttp", "security": "reality",
                  "realitySettings": realitySettings,
                  "xhttpSettings": {"mode": "auto", "path": f"/{xhttp_path}"}}
    else:
        flow = "xtls-rprx-vision"
        stream = {"network": "tcp", "security": "reality",
                  "realitySettings": realitySettings}
    if fragment:
        stream["finalmask"] = {"tcp": [{"type": "fragment", "settings": dict(FRAGMENT_SETTINGS)}]}
    proxy_out = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": vpn_port,
                "users": [{"id": uuid, "encryption": "none", "flow": flow}],
            }]
        },
        "streamSettings": stream,
    }
    config = {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                # РФ-домены резолвим через РФ-DNS (Яндекс): правильные РФ IP, запрос внутри страны
                {"address": "77.88.8.8", "domains": ["geosite:category-ru"],
                 "expectIPs": ["geoip:ru"]},
                # РФ-TLD резолвим РФ-DNS (без expectIPs: .ru на иностранном CDN тоже резолвится)
                {"address": "77.88.8.8", "domains": ["domain:ru", "domain:su", "domain:xn--p1ai"]},
                # WeChat/Tencent — китайский DNS (DNSPod = собственный резолвер Tencent), запрос
                # DIRECT из РФ (IP резолверов в direct ip-правиле ниже). Действует только на
                # собственные запросы Xray. Адреса, к которым подключается само приложение, даёт
                # DNS туннеля, который Happ задаёт у себя («Tunnel DNS», в JSON провайдера не
                # попадает), — эта секция на них не влияет.
                # DoH по IP, не обычный UDP: открытый UDP-DNS к зарубежным резолверам ТСПУ
                # может перехватить и подменить ответ, шифрованный — только заблокировать.
                {"address": "https://1.12.12.12/dns-query", "domains": WECHAT_DOMAINS},  # DNSPod DoH (Tencent-own)
                {"address": "https://223.5.5.5/dns-query", "domains": WECHAT_DOMAINS},   # AliDNS DoH (запасной)
                # прочее — Google DoH через туннель: провайдер не видит, какие сайты резолвим.
                # Адрес IP, а не домен: домен пришлось бы резолвить системным DNS провайдера
                # (bootstrap), а его ТСПУ подменяет — тогда DoH не поднимется вовсе.
                "https://8.8.8.8/dns-query",
                # Резерв на случай мёртвого каскада: DoH идёт внутрь туннеля, и пока он не
                # ответит, не резолвятся и РФ-сайты вне доменных правил (РФ-сервисы на .com).
                # Xray опрашивает безфильтровые серверы по порядку → сюда попадёт только
                # после провала DoH. Яндекс в geoip:ru → запрос уходит direct, мимо моста.
                "77.88.8.8",
            ],
            "queryStrategy": "UseIPv4",
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": http_port,
                "protocol": "http",
            },
        ],
        "outbounds": [
            proxy_out,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                # РФ-домены и РФ-IP + локалка идут напрямую (с реального IP устройства).
                # 1.12.12.12, 119.29.29.29 (DNSPod) и 223.5.5.5 (AliDNS) — китайские DNS-резолверы WeChat:
                # их запросы тоже direct из РФ, иначе уйдут в каскад → европейский edge.
                {"type": "field", "outboundTag": "direct", "domain": ["geosite:category-ru"]},
                # весь .ru/.su/.рф → direct: ловит РФ-сайты, что урезанный geosite.dat в Happ пропускает
                # (напр. госсайты/банки на корневом сертификате Минцифры — иначе утекают в каскад)
                {"type": "field", "outboundTag": "direct",
                 "domain": ["domain:ru", "domain:su", "domain:xn--p1ai"]},
                {"type": "field", "outboundTag": "direct",
                 "ip": ["geoip:ru", "geoip:private", "1.12.12.12", "119.29.29.29", "223.5.5.5", host]},
                # WeChat → direct узким списком доменов. НЕ geosite:cn/geoip:cn —
                # китайская geo-база превышает лимит памяти туннеля iOS (50 МБ).
                {"type": "field", "outboundTag": "direct", "domain": WECHAT_DOMAINS},
                # всё остальное (вкл. Telegram — домены и IP не-РФ) — в каскад через мост.
                # Telegram идёт по Reality (firefox-fp, DPI-устойчив), MTProto-прокси не нужен.
                {"type": "field", "outboundTag": "proxy", "port": "0-65535"},
            ],
        },
    }
    if dns_from_json:
        servers = config["dns"]["servers"]
        # расширенный список WeChat — во всех местах, где стоит WECHAT_DOMAINS
        wc_domains = WECHAT_DOMAINS + WECHAT_DOMAINS_EXTRA
        for item in servers + config["routing"]["rules"]:
            for key in ("domains", "domain"):
                if isinstance(item, dict) and item.get(key) is WECHAT_DOMAINS:
                    item[key] = wc_domains
        # первая запись — адрес DNS туннеля для Happ; Xray её не опрашивает (фиктивный домен)
        servers.insert(0, {"address": TUNNEL_DNS_IP, "domains": ["full:happ-tunnel-dns.invalid"]})
        # WeChat — глазами China Telecom, раньше китайских резолверов; DoH 8.8.8.8 через туннель
        wc = next(i for i, s in enumerate(servers)
                  if isinstance(s, dict) and s.get("domains") is wc_domains)
        servers.insert(wc, {"address": "https://8.8.8.8/dns-query", "domains": wc_domains,
                            "clientIP": WECHAT_DNS_CLIENT_IP})
        config["outbounds"].append({"tag": "dns-out", "protocol": "dns"})
        # запросы приложений к DNS туннеля → DNS-модуль Xray (свои запросы Xray сюда не попадают:
        # Яндекс — другой адрес, DoH — TCP 443)
        config["routing"]["rules"].insert(0, {"type": "field", "network": "udp", "port": "53",
                                              "ip": [TUNNEL_DNS_IP], "outboundTag": "dns-out"})
    return json.dumps(config, indent=2)


def vless_reality_url(uuid, host, port, sni, public_key, short_id, name,
                      fingerprint=DEFAULT_FINGERPRINT, fragment=False):
    frag = f"&fragment={FRAGMENT_LINK}" if fragment else ""
    return (
        f"vless://{uuid}@{host}:{port}"
        f"?encryption=none&flow=xtls-rprx-vision"
        f"&security=reality&sni={sni}&fp={fingerprint}"
        f"&pbk={public_key}&sid={short_id}"
        f"&type=tcp&headerType=none"
        f"{frag}"
        f"#{name}"
    )


def vless_xhttp_url(uuid, host, port, sni, xhttp_path, name,
                    fingerprint=DEFAULT_FINGERPRINT):
    return (
        f"vless://{uuid}@{host}:{port}"
        f"?encryption=none&security=tls&sni={sni}&fp={fingerprint}"
        f"&type=xhttp&path=%2F{xhttp_path}"
        f"#{name}"
    )


def client_profile_json(uuid: str, exit_server, relay_ip: str,
                        direct: bool = False, remarks: str = "",
                        fingerprint: str = DEFAULT_FINGERPRINT,
                        dns_from_json: bool = False,
                        fragment: bool = False) -> str:
    """Полный клиентский config.json под один выход.
    direct=False → через мост РФ (host=relay_ip, port=relay_port).
    direct=True  → напрямую к выходу (host=exit.ip, port=exit.vpn_port)."""
    host = exit_server.ip if direct else relay_ip
    port = exit_server.vpn_port if direct else exit_server.relay_port
    cfg = json.loads(build_client_xray_config(
        uuid=uuid, public_key=exit_server.reality_public_key,
        short_id=exit_server.reality_short_id, host=host,
        sni=exit_server.vpn_sni, vpn_port=port, fingerprint=fingerprint,
        dns_from_json=dns_from_json, fragment=fragment,
    ))
    if remarks:
        cfg = {"remarks": remarks, **cfg}
    return json.dumps(cfg, indent=2, ensure_ascii=False)


def client_profile_url(uuid: str, exit_server, relay_ip: str, name: str,
                       direct: bool = False,
                       fingerprint: str = DEFAULT_FINGERPRINT,
                       fragment: bool = False) -> str:
    """VLESS-ссылка под один выход (cascade или direct)."""
    host = exit_server.ip if direct else relay_ip
    port = exit_server.vpn_port if direct else exit_server.relay_port
    suffix = " direct" if direct else ""
    return vless_reality_url(
        uuid=uuid, host=host, port=port, sni=exit_server.vpn_sni,
        public_key=exit_server.reality_public_key,
        short_id=exit_server.reality_short_id,
        name=f"{name} [{exit_server.location}]{suffix}",
        fingerprint=fingerprint, fragment=fragment,
    )


# ---------------------------------------------------------------------------
# XHTTP+Reality — клиентский профиль (PoC, транспорт вместо raw TCP).
# Серверный inbound и DNAT моста уже есть (build_xray_config + wizard/menu/panel).
# Реально через мост: host=relay_ip, port=exit.vpn_xhttp_port (мост слушает его и
# DNAT'ит на выход:vpn_xhttp_port). vless_xhttp_url (security=tls) — отдельный
# режим, для нашего Reality-inbound нужен этот, с pbk/sid.
# ---------------------------------------------------------------------------

def vless_xhttp_reality_url(uuid, host, port, sni, public_key, short_id, xhttp_path,
                            name, fingerprint=DEFAULT_FINGERPRINT):
    """VLESS-ссылка XHTTP поверх Reality (flow пустой — vision ломает XHTTP)."""
    return (
        f"vless://{uuid}@{host}:{port}"
        f"?encryption=none&security=reality&sni={sni}&fp={fingerprint}"
        f"&pbk={public_key}&sid={short_id}"
        f"&type=xhttp&path=%2F{xhttp_path}&mode=auto"
        f"#{name}"
    )


def client_xhttp_profile_json(uuid: str, exit_server, relay_ip: str,
                              remarks: str = "",
                              fingerprint: str = DEFAULT_FINGERPRINT) -> str:
    """Клиентский config.json XHTTP+Reality через мост (тот же сплит-routing)."""
    cfg = json.loads(build_client_xray_config(
        uuid=uuid, public_key=exit_server.reality_public_key,
        short_id=exit_server.reality_short_id, host=relay_ip,
        sni=exit_server.vpn_sni, vpn_port=exit_server.vpn_xhttp_port,
        fingerprint=fingerprint, xhttp_path=exit_server.vpn_xhttp_path,
    ))
    if remarks:
        cfg = {"remarks": remarks, **cfg}
    return json.dumps(cfg, indent=2, ensure_ascii=False)


def client_xhttp_profile_url(uuid: str, exit_server, relay_ip: str, name: str,
                             fingerprint: str = DEFAULT_FINGERPRINT) -> str:
    """VLESS-XHTTP-ссылка через мост под один выход."""
    return vless_xhttp_reality_url(
        uuid=uuid, host=relay_ip, port=exit_server.vpn_xhttp_port,
        sni=exit_server.vpn_sni, public_key=exit_server.reality_public_key,
        short_id=exit_server.reality_short_id, xhttp_path=exit_server.vpn_xhttp_path,
        name=f"{name} [{exit_server.location}] xhttp", fingerprint=fingerprint,
    )
