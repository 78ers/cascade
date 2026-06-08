"""MTProto — секреты, ссылки, SSH-деплой mtg на выход и локальный деплой TELEMT на мост.

Pure-часть (секреты/ссылки) — логика из mtproto/install.sh.
SSH-часть (deploy_mtproto) — ставит mtg на сервер выхода.
Local-часть (deploy_telemt_local) — ставит TELEMT на мост (subprocess, без SSH).
"""
from __future__ import annotations

import re
import secrets
import shlex
import subprocess
from pathlib import Path


def gen_secret(domain: str) -> str:
    """ee + 16 random байт (hex) + hex(домен)."""
    rand = secrets.token_hex(16)
    dom_hex = domain.encode("utf-8").hex()
    return f"ee{rand}{dom_hex}"


def domain_from_secret(secret: str) -> str:
    """Домен из Fake-TLS секрета (байты после ee + 32 hex)."""
    dom_hex = secret[34:]
    return bytes.fromhex(dom_hex).decode("utf-8", errors="replace")


def valid_secret(secret: str) -> bool:
    if not re.fullmatch(r"ee[0-9a-f]{34,}", secret):
        return False
    return len(secret) % 2 == 0


def tg_link(host: str, port: int, secret: str) -> str:
    return f"tg://proxy?server={host}&port={port}&secret={secret}"


# ---------------------------------------------------------------------------
# Deploy-часть (SSH) — не юнит-тестируется, проверка на живом сервере
# ---------------------------------------------------------------------------

MTG_INSTALL_DIR = "/etc/cascade-mtg"


def deploy_mtproto(conn, port: int, domain: str = "google.com", secret: str = "") -> str:
    """Поднять mtg на сервере выхода (systemd). Вернуть секрет.

    Если secret пуст — генерим под domain. Иначе импортируем готовый.
    """
    from cascade.console import info, ok

    if not secret:
        secret = gen_secret(domain)
    info(f"Деплой MTProto на порт {port} (домен {domain_from_secret(secret)})...")
    conn.run(f"mkdir -p {shlex.quote(MTG_INSTALL_DIR)}", timeout=10)

    install_script = (
        "set -e; cd /tmp; "
        "ARCH=$(uname -m); case $ARCH in x86_64) A=amd64;; aarch64) A=arm64;; esac; "
        "TAG=$(curl -fsSL https://api.github.com/repos/9seconds/mtg/releases/latest "
        "| grep -oP '\"tag_name\": \"\\K[^\"]+'); "
        "[ -n \"$TAG\" ] || { echo 'не удалось узнать версию mtg (GitHub API)'; exit 1; }; "
        "curl -fsSL \"https://github.com/9seconds/mtg/releases/download/${TAG}/"
        "mtg-${TAG#v}-linux-${A}.tar.gz\" -o mtg.tgz; "
        "tar xzf mtg.tgz; "
        "find . -name mtg -type f -executable -exec install -m755 {} /usr/local/bin/mtg \\;"
    )
    r = conn.run(f"bash -c {shlex.quote(install_script)}", timeout=120)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "(нет вывода)").strip()
        raise RuntimeError(f"Установка mtg не удалась (код {r.returncode}):\n{detail}")

    unit = (
        "[Unit]\nDescription=mtg MTProto proxy\nAfter=network-online.target\n\n"
        "[Service]\n"
        f"ExecStart=/usr/local/bin/mtg simple-run -n 1.1.1.1 0.0.0.0:{port} {secret}\n"
        "Restart=on-failure\nRestartSec=5\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    remote_unit = f"/etc/systemd/system/cascade-mtg@{port}.service"
    write_unit = f"cat > {shlex.quote(remote_unit)} <<'CASCADE_EOF'\n{unit}CASCADE_EOF"
    conn.run(f"bash -c {shlex.quote(write_unit)}", timeout=15)
    conn.run(f"ufw allow {port}/tcp || true", timeout=15)
    r = conn.run(f"systemctl daemon-reload && systemctl enable --now cascade-mtg@{port}", timeout=30)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "(нет вывода)").strip()
        raise RuntimeError(f"Запуск mtg на порту {port} не удался (код {r.returncode}):\n{detail}")
    active = conn.run(f"systemctl is-active cascade-mtg@{port}", timeout=10)
    if active.stdout.strip() != "active":
        logs = conn.run(f"journalctl -u cascade-mtg@{port} -n 20 --no-pager", timeout=10).stdout
        raise RuntimeError(
            f"mtg на порту {port} не активен (статус: {active.stdout.strip()}).\n"
            f"Логи:\n{logs}"
        )
    ok(f"MTProto на порту {port} запущен")
    return secret


def restart_mtproto(conn, port: int) -> bool:
    r = conn.run(f"systemctl restart cascade-mtg@{port}", timeout=30)
    return r.returncode == 0


def remove_mtproto(conn, port: int) -> bool:
    """Остановить и удалить mtg-инстанс порта (systemd-юнит)."""
    conn.run(f"systemctl disable --now cascade-mtg@{port}", timeout=30)
    r = conn.run(
        f"rm -f /etc/systemd/system/cascade-mtg@{port}.service && systemctl daemon-reload",
        timeout=15,
    )
    return r.returncode == 0


def exit_port_listening(conn, port: int) -> bool:
    """Слушает ли кто-то :port на выходе (для проверки коллизий перед деплоем mtg)."""
    r = conn.run(f"ss -Hltn 'sport = :{port}'", timeout=10)
    return bool(r.stdout.strip())


# ---------------------------------------------------------------------------
# TELEMT — локальный деплой на мост (subprocess, без SSH)
# Формат секрета совместим с mtg: ee + 32hex + hex(домен)
# ---------------------------------------------------------------------------

TELEMT_BINARY = "/usr/local/bin/telemt"
TELEMT_CFG_PATH = "/etc/cascade/telemt.toml"
TELEMT_CFG_DIR = "/etc/cascade/telemt"
TELEMT_UNIT_PATH = "/etc/systemd/system/cascade-telemt.service"
TELEMT_UNIT_NAME = "cascade-telemt"
TELEMT_INTERNAL_PORT = 8448  # nginx :443 → TELEMT :8448 (TLS passthrough)


def _sanitize_toml_key(label: str) -> str:
    """Нормализовать метку для bare TOML key: только [a-zA-Z0-9_-]."""
    key = re.sub(r"[^a-zA-Z0-9_-]", "_", label) or "user"
    return key[:32]


def _telemt_user_secret(ee_secret: str) -> str:
    """32 hex-символа из ee-секрета (случайная часть) для TELEMT access.users."""
    return ee_secret[2:34]


def _telemt_toml(mask_domain: str, users: dict) -> str:
    """Конфиг TELEMT в формате TOML.
    users = {label: ee_secret} — label станет ключом в [access.users].
    """
    user_lines = "\n".join(
        f'{_sanitize_toml_key(label)} = "{_telemt_user_secret(sec)}"'
        for label, sec in users.items()
    )
    return (
        f"[general]\nlog_level = \"normal\"\n\n"
        f"[general.modes]\nclassic = false\nsecure = false\ntls = true\n\n"
        f"[server]\nport = {TELEMT_INTERNAL_PORT}\n\n"
        f"[[server.listeners]]\nip = \"0.0.0.0\"\n\n"
        f"[censorship]\n"
        f"tls_domain = \"{mask_domain}\"\n"
        f"mask = true\n"
        f"tls_emulation = true\n"
        f"tls_front_dir = \"{TELEMT_CFG_DIR}/tlsfront\"\n\n"
        f"[access.users]\n{user_lines}\n"
    )


def _telemt_unit() -> str:
    """Systemd unit для cascade-telemt."""
    return (
        "[Unit]\nDescription=CASCADE TELEMT MTProxy\nAfter=network-online.target\n\n"
        "[Service]\n"
        f"ExecStart={TELEMT_BINARY} {TELEMT_CFG_PATH}\n"
        "Restart=always\nRestartSec=3\nLimitNOFILE=65536\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def _install_telemt_local() -> None:
    """Скачать telemt/telemt latest release → /usr/local/bin/telemt."""
    install_script = (
        "set -e; cd /tmp; "
        "ARCH=$(uname -m); "
        "LIBC=$(ldd --version 2>&1 | grep -iq musl && echo musl || echo gnu); "
        'URL="https://github.com/telemt/telemt/releases/latest/download/'
        'telemt-${ARCH}-linux-${LIBC}.tar.gz"; '
        "curl -fsSL \"$URL\" | tar xzf -; "
        "install -m755 telemt /usr/local/bin/telemt"
    )
    r = subprocess.run(
        ["bash", "-c", install_script],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        raise RuntimeError(f"Установка telemt не удалась:\n{r.stderr or r.stdout}")


def deploy_telemt_local(mask_domain: str, users: dict) -> None:
    """Поднять/перезапустить TELEMT на мосту. users = {label: ee_secret}."""
    from cascade.console import info, ok

    if not users:
        raise ValueError("users не может быть пустым")
    info(f"Деплой TELEMT на мосту (порт {TELEMT_INTERNAL_PORT}, маска {mask_domain})...")

    _install_telemt_local()

    Path(TELEMT_CFG_DIR).mkdir(parents=True, exist_ok=True)
    (Path(TELEMT_CFG_DIR) / "tlsfront").mkdir(exist_ok=True)

    cfg = Path(TELEMT_CFG_PATH)
    cfg.write_text(_telemt_toml(mask_domain, users), encoding="utf-8")
    cfg.chmod(0o600)

    Path(TELEMT_UNIT_PATH).write_text(_telemt_unit(), encoding="utf-8")

    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", TELEMT_UNIT_NAME], check=False)
    subprocess.run(["systemctl", "restart", TELEMT_UNIT_NAME], check=False)

    active = subprocess.run(
        ["systemctl", "is-active", TELEMT_UNIT_NAME],
        capture_output=True, text=True,
    ).stdout.strip()
    if active != "active":
        logs = subprocess.run(
            ["journalctl", "-u", TELEMT_UNIT_NAME, "-n", "20", "--no-pager"],
            capture_output=True, text=True,
        ).stdout
        raise RuntimeError(
            f"cascade-telemt не активен (статус: {active}).\nЛоги:\n{logs}"
        )
    ok(f"TELEMT на мосту запущен на :{TELEMT_INTERNAL_PORT}")


def restart_telemt_local() -> bool:
    r = subprocess.run(["systemctl", "restart", TELEMT_UNIT_NAME], capture_output=True)
    return r.returncode == 0


def remove_telemt_local() -> bool:
    """Остановить cascade-telemt, удалить юнит и TOML."""
    subprocess.run(["systemctl", "disable", "--now", TELEMT_UNIT_NAME], check=False)
    success = True
    for path in (TELEMT_UNIT_PATH, TELEMT_CFG_PATH):
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            success = False
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    return success


# ---------------------------------------------------------------------------
# TELEMT — SSH-деплой на сервер выхода (GER)
# Зеркало local-функций, но работает через conn.run() по SSH
# ---------------------------------------------------------------------------

def _telemt_write_cmd(remote_path: str, content: str) -> str:
    """Команда записи файла через heredoc (для bash -c по SSH)."""
    return f"cat > {shlex.quote(remote_path)} <<'CASCADE_EOF'\n{content}CASCADE_EOF"


def deploy_telemt_remote(conn, mask_domain: str, users: dict) -> None:
    """Поднять/перезапустить TELEMT на сервере выхода по SSH. users = {label: ee_secret}."""
    from cascade.console import info, ok as ok_msg

    if not users:
        raise ValueError("users не может быть пустым")
    info(f"Деплой TELEMT на выходе (порт {TELEMT_INTERNAL_PORT}, маска {mask_domain})...")

    install_script = (
        "set -e; cd /tmp; "
        "ARCH=$(uname -m); "
        "LIBC=$(ldd --version 2>&1 | grep -iq musl && echo musl || echo gnu); "
        'URL="https://github.com/telemt/telemt/releases/latest/download/'
        'telemt-${ARCH}-linux-${LIBC}.tar.gz"; '
        "curl -fsSL \"$URL\" | tar xzf -; "
        "install -m755 telemt /usr/local/bin/telemt"
    )
    r = conn.run(f"bash -c {shlex.quote(install_script)}", timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"Установка telemt не удалась:\n{r.stderr or r.stdout}")

    conn.run(f"mkdir -p {shlex.quote(TELEMT_CFG_DIR)}/tlsfront", timeout=10)

    toml_cmd = _telemt_write_cmd(TELEMT_CFG_PATH, _telemt_toml(mask_domain, users))
    r = conn.run(f"bash -c {shlex.quote(toml_cmd)}", timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"Не удалось записать TELEMT-конфиг: {r.stderr or r.stdout}")
    conn.run(f"chmod 600 {shlex.quote(TELEMT_CFG_PATH)}", timeout=10)

    unit_cmd = _telemt_write_cmd(TELEMT_UNIT_PATH, _telemt_unit())
    conn.run(f"bash -c {shlex.quote(unit_cmd)}", timeout=15)

    conn.run("ufw allow 8448/tcp || true", timeout=15)
    r = conn.run(
        f"systemctl daemon-reload && systemctl enable --now {TELEMT_UNIT_NAME} && systemctl restart {TELEMT_UNIT_NAME}",
        timeout=30,
    )
    if r.returncode != 0:
        raise RuntimeError(f"Не удалось запустить cascade-telemt: {r.stderr or r.stdout}")

    active = conn.run(f"systemctl is-active {TELEMT_UNIT_NAME}", timeout=10)
    if active.stdout.strip() != "active":
        logs = conn.run(f"journalctl -u {TELEMT_UNIT_NAME} -n 20 --no-pager", timeout=10).stdout
        raise RuntimeError(
            f"cascade-telemt не активен (статус: {active.stdout.strip()}).\nЛоги:\n{logs}"
        )
    ok_msg(f"TELEMT на выходе запущен на :{TELEMT_INTERNAL_PORT}")


def restart_telemt_remote(conn) -> bool:
    r = conn.run(f"systemctl restart {TELEMT_UNIT_NAME}", timeout=30)
    return r.returncode == 0


def remove_telemt_remote(conn) -> bool:
    """Остановить cascade-telemt на сервере выхода, удалить юнит и TOML."""
    conn.run(f"systemctl disable --now {TELEMT_UNIT_NAME}", timeout=30)
    r = conn.run(
        f"rm -f {shlex.quote(TELEMT_UNIT_PATH)} {shlex.quote(TELEMT_CFG_PATH)} && systemctl daemon-reload",
        timeout=15,
    )
    return r.returncode == 0
