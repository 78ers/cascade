"""Первичная установка CASCADE: настройка обоих серверов одной командой."""
from __future__ import annotations

import subprocess
import traceback
from pathlib import Path

import questionary

from cascade import mtproto, relay, vpn
from cascade.config import Config, ExitServer, save_config
from cascade.console import err, info, ok, qr, questionary_style, warn
from cascade.ssh import ServerConnection, SSHError


def _ensure_ssh_key() -> "Path | None":
    """Вернуть путь к pub-ключу, сгенерировать ed25519 если ключей нет."""
    ssh_dir = Path.home() / ".ssh"
    for name in ("id_ed25519", "id_rsa", "id_ecdsa"):
        p = ssh_dir / f"{name}.pub"
        if p.exists():
            return p
    key = ssh_dir / "id_ed25519"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    r = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", ""],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        ok("Сгенерирован новый SSH-ключ")
        return Path(str(key) + ".pub")
    warn("Не удалось сгенерировать SSH-ключ")
    return None


def _fix_ssh_auth(ip: str, user: str, port: int, st) -> bool:
    """Показать pub-ключ и запустить ssh-copy-id интерактивно. Вернуть True при успехе."""
    pub = _ensure_ssh_key()
    if not pub:
        return False
    info("Публичный ключ этого сервера:")
    print(pub.read_text().strip())
    print()
    if not questionary.confirm(
        f"Скопировать ключ на {ip} через ssh-copy-id? (потребуется пароль от {ip})",
        default=True, style=st,
    ).ask():
        info(f"Добавь вручную на {ip}: echo '<ключ выше>' >> ~/.ssh/authorized_keys")
        return False
    port_args = ["-p", str(port)] if port != 22 else []
    r = subprocess.run(["ssh-copy-id", "-i", str(pub), *port_args, f"{user}@{ip}"])
    return r.returncode == 0


def _get_local_ip() -> str:
    r = subprocess.run(["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
                       capture_output=True, text=True)
    ip = r.stdout.strip()
    if not ip:
        warn("Не удалось определить публичный IP этого сервера. Укажи вручную.")
        return ""
    return ip


def run_wizard(existing: "Config | None" = None) -> "Config | None":
    st = questionary_style()
    info("Первичная установка CASCADE VPN")
    location = questionary.text("Имя/локация сервера выхода:", default="Финляндия", style=st).ask()
    ip = questionary.text("IP сервера выхода:", style=st).ask()
    if not ip:
        return existing
    user = questionary.text("SSH-пользователь:", default="root", style=st).ask()
    ssh_port_s = questionary.text("SSH-порт:", default="22", style=st).ask()
    vpn_name = questionary.text("Название подключения в клиенте:", default="CASCADE VPN", style=st).ask()
    sni = questionary.text("SNI-маскировка:", default="www.google.com", style=st).ask()
    vpn_port_s = questionary.text("Порт VLESS+Reality:", default="8444", style=st).ask()
    mtproto_port_s = questionary.text("Порт MTProto:", default="8443", style=st).ask()
    domain = questionary.text("Домен для XHTTP+CDN (Enter — пропустить):", default="", style=st).ask()

    from cascade.config import Client
    from cascade.xray_config import gen_uuid
    import datetime
    vpn_port = int(vpn_port_s) if vpn_port_s and vpn_port_s.isdigit() else 8444
    mtproto_port = int(mtproto_port_s) if mtproto_port_s and mtproto_port_s.isdigit() else 8443
    ex = ExitServer(
        id="default", location=location, ip=ip, ssh_user=user,
        ssh_port=int(ssh_port_s) if ssh_port_s.isdigit() else 22,
        relay_port=vpn_port, vpn_port=vpn_port, vpn_sni=sni,
        vpn_xhttp_enabled=bool(domain), vpn_xhttp_port=8445,
    )
    first_client = Client(id="default", name="default", uuid=gen_uuid(),
                          created=datetime.date.today().isoformat())
    cfg = Config(exit_servers=[ex], clients=[first_client],
                 vpn_name=vpn_name or "CASCADE VPN",
                 mtproto_ports=[mtproto_port],
                 primary_exit_id=ex.id)
    # домен XHTTP хранить на выходе нечем отдельно — vpn_domain убран; XHTTP path сгенерится в deploy

    try:
        conn = ServerConnection(ip, user, port=ex.ssh_port)
        info(f"Проверка SSH-соединения с {ip}...")
        try:
            conn.check_ssh()
        except SSHError as e:
            if getattr(e, "hint_type", "") == "auth":
                if _fix_ssh_auth(ip, user, ex.ssh_port, st):
                    conn.check_ssh()  # повтор после копирования ключа
                else:
                    raise
            else:
                raise
        vpn.deploy_vpn(conn, ex, cfg.clients)
        secret = mtproto.deploy_mtproto(conn, cfg.mtproto_ports[0], domain="google.com")
        cfg.mtproto_secrets = {str(cfg.mtproto_ports[0]): secret}
        info("Настройка relay (iptables) на этом сервере...")
        relay.apply_rule(relay.RelayRule("tcp", ex.relay_port, ip, ex.vpn_port))
        if ex.vpn_xhttp_enabled:
            relay.apply_rule(relay.RelayRule("tcp", ex.vpn_xhttp_port, ip, ex.vpn_xhttp_port))
        for p in cfg.mtproto_ports:
            relay.apply_rule(relay.RelayRule("tcp", p, ip, p))
        if questionary.confirm("Настроить Telegram-уведомления?", default=False, style=st).ask():
            cfg.telegram_bot_token = questionary.text("Bot token:", style=st).ask() or ""
            cfg.telegram_chat_id = questionary.text("Chat ID:", style=st).ask() or ""
        save_config(cfg)
        ok("Установка завершена")
        relay_ip = _get_local_ip() or (questionary.text("IP этого (РФ) сервера:", style=st).ask() or "?")
        vpn.print_vpn_links(cfg, relay_ip)
        link = mtproto.tg_link(relay_ip, cfg.mtproto_ports[0], secret)
        print(link); qr(link)
    except SSHError as e:
        err(f"Ошибка SSH: {e}")
        if e.hint: err(f"Подсказка: {e.hint}")
        _print_report_hint(); input("Enter..."); return existing
    except RuntimeError as e:
        err(str(e)); _print_report_hint(); input("Enter..."); return existing
    except Exception:
        err("Неожиданная ошибка при установке:"); traceback.print_exc()
        _print_report_hint(); input("Enter..."); return existing
    input("Enter...")
    return cfg


def _print_report_hint() -> None:
    err("──────────────────────────────────────────")
    err("Скопируй сообщение выше и пришли для диагностики.")
    err("──────────────────────────────────────────")
