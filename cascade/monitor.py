"""Мониторинг сервера выхода + Telegram-уведомления + авто-рестарт."""
from __future__ import annotations

import requests

from cascade.config import Config, mtproto_port_exit
from cascade.ssh import ServerConnection, tcp_connect


def decide_targets(cfg: Config) -> "list[tuple[str, str, int]]":
    """[(label, ip, port)] — порт Xray (vpn_port) каждого выхода + mtproto на ЕГО выходе.
    Проверяем сам выход напрямую (ip выхода:vpn_port), не мост."""
    targets = []
    for ex in cfg.exit_servers:
        targets.append((f"{ex.location} VPN", ex.ip, ex.vpn_port))
        if ex.vpn_xhttp_enabled:
            targets.append((f"{ex.location} XHTTP", ex.ip, ex.vpn_xhttp_port))
    for p in cfg.mtproto_ports:
        pex = mtproto_port_exit(cfg, p)   # выход конкретного порта (не всегда [0])
        if pex:
            targets.append(("MTProto", pex.ip, p))
    return targets


def format_alert(results: "list[tuple[str, str, int, bool]]") -> str:
    lines = ["⚠️ CASCADE: проблема на выходах", ""]
    for label, ip, port, up in results:
        mark = "✅" if up else "❌"
        lines.append(f"{mark} {label} {ip}:{port}")
    return "\n".join(lines)


def send_telegram(token: str, chat_id: str, text: str) -> bool:
    if not token or not chat_id:
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text}, timeout=10,
        )
        return r.ok
    except requests.RequestException:
        return False


def check_once(cfg: Config) -> "list[tuple[str, str, int, bool]]":
    return [(label, ip, port, tcp_connect(ip, port))
            for label, ip, port in decide_targets(cfg)]


def run_check(cfg: Config) -> None:
    results = check_once(cfg)
    down = [r for r in results if not r[3]]
    if not down:
        return
    send_telegram(cfg.telegram_bot_token, cfg.telegram_chat_id, format_alert(results))
    if not cfg.auto_restart:
        return
    from cascade.vpn import restart_vpn
    from cascade.mtproto import restart_mtproto
    # рестартим только выходы с упавшими целями, чтобы не дёргать здоровые
    down_ips = {ip for _, ip, _, up in results if not up}
    for ex in cfg.exit_servers:
        if ex.ip in down_ips:
            conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
            restart_vpn(conn)
    mtproto_down = any(label == "MTProto" and not up for label, _, _, up in results)
    if mtproto_down and cfg.exit_servers:
        # рестартим каждый порт на ЕГО выходе (не всегда [0])
        for p in cfg.mtproto_ports:
            pex = mtproto_port_exit(cfg, p)
            if not pex:
                continue
            mtconn = ServerConnection(pex.ip, pex.ssh_user, port=pex.ssh_port)
            restart_mtproto(mtconn, p)
    results2 = check_once(cfg)
    if any(not r[3] for r in results2):
        send_telegram(cfg.telegram_bot_token, cfg.telegram_chat_id,
                      "❌ Авто-рестарт не помог. Нужно вмешательство.")
    else:
        send_telegram(cfg.telegram_bot_token, cfg.telegram_chat_id,
                      "✅ Авто-рестарт восстановил сервисы.")
