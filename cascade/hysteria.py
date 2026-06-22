"""Hysteria2 — PoC-протокол для каскада (UDP/QUIC + Brutal congestion).

Назначение: проверить на запасном выходе (GER), проходит ли UDP/QUIC сквозь ТСПУ
до РФ-моста, и бьёт ли Brutal по TCP-in-TCP на аплоуде. Клиент — Happ (умеет hy2://).

Схема (как у VLESS): телефон → мост:PORT (UDP) → DNAT → выход:PORT (Hysteria2) → интернет.
Маскировка пакета — Salamander-обфускация: на проводе это «случайный UDP» к РФ-IP,
без видимого QUIC/TLS-хендшейка (потому TLS = self-signed, клиент с insecure=1).

Pure-часть (yaml/ссылка) — юнит-тестируется. SSH-часть — проверка на живом сервере.
"""
from __future__ import annotations

import re
import secrets
import shlex


HYST_CFG_DIR = "/etc/cascade-hysteria"
HYST_CFG_PATH = f"{HYST_CFG_DIR}/config.yaml"
HYST_BINARY = "/usr/local/bin/hysteria"
HYST_UNIT_NAME = "cascade-hysteria"
HYST_UNIT_PATH = f"/etc/systemd/system/{HYST_UNIT_NAME}.service"


def gen_password() -> str:
    """Случайный пароль (auth или obfs)."""
    return secrets.token_urlsafe(16)


def hysteria_server_yaml(port: int, auth_pw: str, obfs_pw: str,
                         mask_domain: str) -> str:
    """Конфиг Hysteria2-сервера (YAML). Self-signed TLS + Salamander-обфускация."""
    return (
        f"listen: :{port}\n"
        f"tls:\n"
        f"  cert: {HYST_CFG_DIR}/cert.pem\n"
        f"  key: {HYST_CFG_DIR}/key.pem\n"
        f"auth:\n"
        f"  type: password\n"
        f"  password: {auth_pw}\n"
        f"obfs:\n"
        f"  type: salamander\n"
        f"  salamander:\n"
        f"    password: {obfs_pw}\n"
        f"masquerade:\n"
        f"  type: proxy\n"
        f"  proxy:\n"
        f"    url: https://{mask_domain}/\n"
        f"    rewriteHost: true\n"
    )


def hy2_url(host: str, port: int, auth_pw: str, obfs_pw: str,
            mask_domain: str, name: str) -> str:
    """Ссылка hysteria2:// для импорта в Happ.
    host = IP моста (РФ), port = UDP-порт моста (DNAT на выход).
    insecure=1 — TLS self-signed (под Salamander сертификат всё равно не виден ТСПУ)."""
    from urllib.parse import quote
    auth = quote(auth_pw, safe="")
    obfs = quote(obfs_pw, safe="")
    return (
        f"hysteria2://{auth}@{host}:{port}/"
        f"?obfs=salamander&obfs-password={obfs}"
        f"&sni={mask_domain}&insecure=1"
        f"#{name}"
    )


def valid_hy2_password(pw: str) -> bool:
    """Пароль без пробелов/управляющих символов (защита от инъекций в yaml/ссылку)."""
    return bool(pw) and bool(re.fullmatch(r"[A-Za-z0-9_\-]+", pw))


# ---------------------------------------------------------------------------
# Deploy-часть (SSH на сервер выхода) — не юнит-тестируется
# Зеркало mtproto.deploy_mtproto: install → write config → systemd → is-active
# ---------------------------------------------------------------------------

def _write_cmd(remote_path: str, content: str) -> str:
    """Команда записи файла через heredoc (для bash -c по SSH)."""
    return f"cat > {shlex.quote(remote_path)} <<'CASCADE_EOF'\n{content}CASCADE_EOF"


def _unit() -> str:
    return (
        "[Unit]\nDescription=CASCADE Hysteria2 (PoC)\nAfter=network-online.target\n\n"
        "[Service]\n"
        f"ExecStart={HYST_BINARY} server -c {HYST_CFG_PATH}\n"
        "Restart=always\nRestartSec=3\nLimitNOFILE=65536\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def deploy_hysteria_remote(conn, port: int, mask_domain: str,
                           auth_pw: str = "", obfs_pw: str = "") -> tuple[str, str]:
    """Поднять Hysteria2 на сервере выхода по SSH. Вернуть (auth_pw, obfs_pw).

    Пустые пароли — сгенерим. Бинарь ставим официальным инсталлером get.hy2.sh
    (надёжнее прямой ссылки на релиз: у apernet/hysteria тег со слэшем app/vX)."""
    from cascade.console import info, ok

    if not auth_pw:
        auth_pw = gen_password()
    if not obfs_pw:
        obfs_pw = gen_password()
    if not (valid_hy2_password(auth_pw) and valid_hy2_password(obfs_pw)):
        raise ValueError("пароль Hysteria2 должен быть [A-Za-z0-9_-]+")

    info(f"Деплой Hysteria2 на порт {port} (маска {mask_domain})...")
    conn.run(f"mkdir -p {shlex.quote(HYST_CFG_DIR)}", timeout=10)

    # 1) бинарь
    r = conn.run("bash -c 'curl -fsSL https://get.hy2.sh/ | bash'", timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"Установка hysteria не удалась:\n{r.stderr or r.stdout}")
    conn.run(f"test -x {HYST_BINARY} || install -m755 "
             f"$(command -v hysteria) {HYST_BINARY} || true", timeout=15)

    # 2) self-signed сертификат (под Salamander ТСПУ его не видит)
    cert_cmd = (
        f"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 "
        f"-days 3650 -nodes -keyout {HYST_CFG_DIR}/key.pem -out {HYST_CFG_DIR}/cert.pem "
        f"-subj {shlex.quote('/CN=' + mask_domain)}"
    )
    r = conn.run(f"bash -c {shlex.quote(cert_cmd)}", timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"Генерация сертификата не удалась:\n{r.stderr or r.stdout}")

    # 3) конфиг + юнит
    yaml = hysteria_server_yaml(port, auth_pw, obfs_pw, mask_domain)
    r = conn.run(f"bash -c {shlex.quote(_write_cmd(HYST_CFG_PATH, yaml))}", timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"Не удалось записать конфиг Hysteria2: {r.stderr or r.stdout}")
    conn.run(f"chmod 600 {shlex.quote(HYST_CFG_PATH)}", timeout=10)
    conn.run(f"bash -c {shlex.quote(_write_cmd(HYST_UNIT_PATH, _unit()))}", timeout=15)

    # 4) firewall (UDP!) + запуск
    conn.run(f"ufw allow {port}/udp || true", timeout=15)
    r = conn.run(
        f"systemctl daemon-reload && systemctl enable --now {HYST_UNIT_NAME} "
        f"&& systemctl restart {HYST_UNIT_NAME}",
        timeout=30,
    )
    if r.returncode != 0:
        raise RuntimeError(f"Запуск Hysteria2 не удался: {r.stderr or r.stdout}")

    active = conn.run(f"systemctl is-active {HYST_UNIT_NAME}", timeout=10)
    if active.stdout.strip() != "active":
        logs = conn.run(f"journalctl -u {HYST_UNIT_NAME} -n 20 --no-pager", timeout=10).stdout
        raise RuntimeError(
            f"Hysteria2 не активен (статус: {active.stdout.strip()}).\nЛоги:\n{logs}"
        )
    ok(f"Hysteria2 на порту {port} (UDP) запущен")
    return auth_pw, obfs_pw


def restart_hysteria_remote(conn) -> bool:
    r = conn.run(f"systemctl restart {HYST_UNIT_NAME}", timeout=30)
    return r.returncode == 0


def remove_hysteria_remote(conn) -> bool:
    """Остановить Hysteria2 на выходе, удалить юнит и конфиг."""
    conn.run(f"systemctl disable --now {HYST_UNIT_NAME}", timeout=30)
    r = conn.run(
        f"rm -f {shlex.quote(HYST_UNIT_PATH)} {shlex.quote(HYST_CFG_PATH)} "
        f"{HYST_CFG_DIR}/cert.pem {HYST_CFG_DIR}/key.pem && systemctl daemon-reload",
        timeout=15,
    )
    return r.returncode == 0
