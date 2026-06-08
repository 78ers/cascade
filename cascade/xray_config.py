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
) -> str:
    """Клиентский config.json со сплит-routing: РФ → direct, прочее → каскад.

    host = IP моста (РФ), точка входа каскада — НЕ сервер выхода.
    geoip/geosite встроены в клиент, скачивать не нужно.
    Совместим с Happ, OneXray, v2rayNG, Nekoray, NekoBox (все на Xray-core).
    """
    proxy_out = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": vpn_port,
                "users": [{"id": uuid, "encryption": "none", "flow": "xtls-rprx-vision"}],
            }]
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": sni,
                "fingerprint": fingerprint,
                "publicKey": public_key,
                "shortId": short_id,
                "spiderX": "",
            },
        },
    }
    config = {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                # РФ-домены резолвим через РФ-DNS (Яндекс): правильные РФ IP, запрос внутри страны
                {"address": "77.88.8.8", "domains": ["geosite:category-ru"],
                 "expectIPs": ["geoip:ru"]},
                # прочее — Google DoH через туннель: провайдер не видит, какие сайты резолвим
                "https://dns.google/dns-query",
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
                # РФ-домены и РФ-IP + локалка идут напрямую (с реального IP устройства)
                {"type": "field", "outboundTag": "direct", "domain": ["geosite:category-ru"]},
                {"type": "field", "outboundTag": "direct", "ip": ["geoip:ru", "geoip:private", host]},
                # всё остальное (вкл. Telegram — домены и IP не-РФ) — в каскад через мост.
                # Telegram идёт по Reality (firefox-fp, DPI-устойчив), MTProto-прокси не нужен.
                {"type": "field", "outboundTag": "proxy", "port": "0-65535"},
            ],
        },
    }
    return json.dumps(config, indent=2)


def vless_reality_url(uuid, host, port, sni, public_key, short_id, name,
                      fingerprint=DEFAULT_FINGERPRINT):
    return (
        f"vless://{uuid}@{host}:{port}"
        f"?encryption=none&flow=xtls-rprx-vision"
        f"&security=reality&sni={sni}&fp={fingerprint}"
        f"&pbk={public_key}&sid={short_id}"
        f"&type=tcp&headerType=none"
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
                        fingerprint: str = DEFAULT_FINGERPRINT) -> str:
    """Полный клиентский config.json под один выход.
    direct=False → через мост РФ (host=relay_ip, port=relay_port).
    direct=True  → напрямую к выходу (host=exit.ip, port=exit.vpn_port)."""
    host = exit_server.ip if direct else relay_ip
    port = exit_server.vpn_port if direct else exit_server.relay_port
    cfg = json.loads(build_client_xray_config(
        uuid=uuid, public_key=exit_server.reality_public_key,
        short_id=exit_server.reality_short_id, host=host,
        sni=exit_server.vpn_sni, vpn_port=port, fingerprint=fingerprint,
    ))
    if remarks:
        cfg = {"remarks": remarks, **cfg}
    return json.dumps(cfg, indent=2, ensure_ascii=False)


def client_profile_url(uuid: str, exit_server, relay_ip: str, name: str,
                       direct: bool = False,
                       fingerprint: str = DEFAULT_FINGERPRINT) -> str:
    """VLESS-ссылка под один выход (cascade или direct)."""
    host = exit_server.ip if direct else relay_ip
    port = exit_server.vpn_port if direct else exit_server.relay_port
    suffix = " direct" if direct else ""
    return vless_reality_url(
        uuid=uuid, host=host, port=port, sni=exit_server.vpn_sni,
        public_key=exit_server.reality_public_key,
        short_id=exit_server.reality_short_id,
        name=f"{name} [{exit_server.location}]{suffix}",
        fingerprint=fingerprint,
    )
