"""Генерация Caddyfile, nginx stream-конфига, systemd-юнита панели + локальный apply."""
from __future__ import annotations

import subprocess
from pathlib import Path

CADDYFILE_PATH = "/etc/caddy/Caddyfile"
PANEL_CADDY_PATH = "/etc/caddy/conf.d/cascade-panel.caddy"
CADDY_IMPORT_LINE = "import /etc/caddy/conf.d/*.caddy"
PANEL_UNIT_PATH = "/etc/systemd/system/cascade-panel.service"

NGINX_CONF_PATH = "/etc/nginx/nginx.conf"  # полностью управляется CASCADE


def caddyfile(domain: str, port: int, caddy_bind_port: int = 443) -> str:
    """Авто-TLS по домену + reverse-proxy на локальную панель.

    caddy_bind_port=443  → стандартный биндинг "domain {" (Caddy сам занимает :443).
    caddy_bind_port=8443 → биндинг "domain:8443 {" (nginx stream в front на :443).
    При caddy_bind_port != 443 добавляется явный http→https редирект на port 443.
    """
    _scanners = (
        "sqlmap|nikto|masscan|zgrab|nuclei|nessus|openvas|acunetix|"
        "burpsuite|dirbuster|gobuster|wfuzz|ffuf|nmap|ZmEu|"
        "python-requests|python-urllib|Go-http-client|"
        "Googlebot|bingbot|YandexBot|Baiduspider|DotBot|SemrushBot|"
        "AhrefsBot|MJ12bot|DataForSeoBot|PetalBot|Bytespider|"
        "zgrab|masscan|scanner|crawler|spider"
    )
    host = f"{domain}:{caddy_bind_port}" if caddy_bind_port != 443 else domain
    https_block = (
        f"{host} {{\n"
        f"    encode gzip\n"
        f"    @blocked header_regexp User-Agent \"(?i)({_scanners})\"\n"
        f"    respond @blocked 404\n"
        f"    header {{\n"
        f"        Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
        f"        X-Frame-Options \"DENY\"\n"
        f"        X-Content-Type-Options \"nosniff\"\n"
        f"        Referrer-Policy \"no-referrer\"\n"
        f"        Content-Security-Policy \"default-src 'self'; style-src 'self' 'unsafe-inline'\"\n"
        f"        X-Robots-Tag \"noindex, nofollow, noarchive, nosnippet\"\n"
        f"        -Server\n"
        f"    }}\n"
        f"    reverse_proxy 127.0.0.1:{port}\n"
        f"}}\n"
    )
    if caddy_bind_port == 443:
        return https_block
    # При nginx в front: HTTP→HTTPS редирект на стандартный :443 (nginx → Caddy:8443)
    http_redirect = (
        f"http://{domain} {{\n"
        f"    redir https://{domain}{{uri}} permanent\n"
        f"}}\n"
    )
    return https_block + "\n" + http_redirect


def nginx_stream_conf(
    panel_domain: str,
    caddy_port: int = 8443,
    telemt_port: int = 8448,
    telemt_host: str = "127.0.0.1",
) -> str:
    """Минимальный nginx.conf для L4 SNI-роутинга без http-блока.

    SNI = panel_domain → Caddy на :caddy_port.
    SNI = всё остальное (маска TELEMT) → telemt_host:telemt_port.
    telemt_host="127.0.0.1" — TELEMT локально; IP выхода — TELEMT на GER (TCP relay).
    """
    return (
        "# Управляется CASCADE — не редактировать вручную\n"
        "load_module modules/ngx_stream_module.so;\n\n"
        "user www-data;\n"
        "worker_processes auto;\n"
        "pid /run/nginx.pid;\n\n"
        "events {\n"
        "    worker_connections 1024;\n"
        "}\n\n"
        "stream {\n"
        # limit_conn: не более 20 одновременных TCP-соединений с одного IP (защита от сканеров/флуда)
        "    limit_conn_zone $binary_remote_addr zone=cascade_addr:10m;\n\n"
        "    map $ssl_preread_server_name $cascade_backend {\n"
        f"        {panel_domain}  127.0.0.1:{caddy_port};\n"
        f"        default         {telemt_host}:{telemt_port};\n"
        "    }\n\n"
        "    server {\n"
        "        listen 443;\n"
        "        proxy_pass $cascade_backend;\n"
        "        ssl_preread on;\n"
        "        limit_conn cascade_addr 20;\n"
        "        proxy_connect_timeout 10s;\n"
        "    }\n"
        "}\n"
    )


def panel_unit(cascade_bin: str) -> str:
    return (
        "[Unit]\nDescription=CASCADE web panel\nAfter=network-online.target\n\n"
        "[Service]\n"
        f"ExecStart={cascade_bin} --panel\n"
        "Restart=on-failure\nRestartSec=5\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def apply_nginx_stream(
    panel_domain: str,
    caddy_port: int = 8443,
    telemt_port: int = 8448,
    telemt_host: str = "127.0.0.1",
) -> None:
    """Установить nginx (если нет), записать stream-конфиг, запустить.

    Записывает полный /etc/nginx/nginx.conf без http-блока — CASCADE владеет nginx на мосту.
    telemt_host: куда форвардить MTProto-трафик (127.0.0.1 = локально, IP выхода = GER).
    """
    r = subprocess.run(["which", "nginx"], capture_output=True)
    if r.returncode != 0:
        subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends", "nginx", "libnginx-mod-stream"],
            check=True,
        )
    else:
        # модуль stream может отсутствовать даже если nginx установлен
        subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends", "libnginx-mod-stream"],
            check=False,
        )

    Path(NGINX_CONF_PATH).write_text(
        nginx_stream_conf(panel_domain, caddy_port, telemt_port, telemt_host), encoding="utf-8"
    )

    test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test.returncode != 0:
        raise RuntimeError(f"nginx -t не прошёл:\n{test.stderr}")

    # порт 443 уже открыт (был у Caddy); добавляем если вдруг нет
    r443 = subprocess.run(
        ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
        capture_output=True,
    )
    if r443.returncode != 0:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
            check=False,
        )

    subprocess.run(["systemctl", "enable", "--now", "nginx"], check=False)
    subprocess.run(["systemctl", "reload-or-restart", "nginx"], check=False)


def apply_panel(
    domain: str,
    port: int,
    cascade_bin: str = "/usr/local/bin/cascade",
    use_nginx_stream: bool = False,
) -> None:
    """Записать конфиг панели + systemd-юнит, поднять сервисы. Локально на РФ-мосту (root).

    НЕ затирает существующий /etc/caddy/Caddyfile: панель пишется в
    conf.d/cascade-panel.caddy, в корневой Caddyfile добавляется import (идемпотентно).

    use_nginx_stream=True: Caddy переходит на :8443, nginx stream занимает :443 для SNI-роутинга.
    """
    caddy_bind_port = 8443 if use_nginx_stream else 443
    panel_caddy = Path(PANEL_CADDY_PATH)
    panel_caddy.parent.mkdir(parents=True, exist_ok=True)
    panel_caddy.write_text(caddyfile(domain, port, caddy_bind_port=caddy_bind_port), encoding="utf-8")
    # подключить conf.d в корневой Caddyfile, не трогая чужие сайты
    main = Path(CADDYFILE_PATH)
    main.parent.mkdir(parents=True, exist_ok=True)
    existing = main.read_text(encoding="utf-8") if main.is_file() else ""
    if CADDY_IMPORT_LINE not in existing:
        new = (existing.rstrip("\n") + "\n" + CADDY_IMPORT_LINE + "\n").lstrip("\n")
        main.write_text(new, encoding="utf-8")
    Path(PANEL_UNIT_PATH).write_text(panel_unit(cascade_bin), encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", "--now", "cascade-panel"], check=False)
    # Caddy перезапускается первым: освобождает :443 если переходит на :8443
    subprocess.run(["systemctl", "reload-or-restart", "caddy"], check=False)
    if use_nginx_stream:
        apply_nginx_stream(domain, caddy_port=caddy_bind_port)
    for port in ("443", "80"):
        r = subprocess.run(
            ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"],
            capture_output=True,
        )
        if r.returncode != 0:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"],
                check=False,
            )
    subprocess.run(["netfilter-persistent", "save"], check=False)
