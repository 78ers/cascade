"""Деплой и управление Xray (VLESS+Reality/XHTTP) на сервере выхода по SSH."""
from __future__ import annotations

import datetime
import shlex
import tempfile
from pathlib import Path

from cascade.config import Config, Client, save_config
from cascade.console import info, ok, warn, qr
from cascade.ssh import ServerConnection
from cascade.xray_config import (
    build_xray_config, gen_short_id, gen_uuid, parse_x25519,
    client_profile_url,
)

XRAY_INSTALL = "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
REMOTE_CONFIG = "/usr/local/etc/xray/config.json"


def _run_checked(conn: ServerConnection, cmd: str, desc: str, timeout: int = 30) -> str:
    """Выполнить команду по SSH, поднять RuntimeError с stderr при провале."""
    info(desc)
    r = conn.run(cmd, timeout=timeout)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "(нет вывода)").strip()
        raise RuntimeError(f"{desc} — ошибка (код {r.returncode}):\n{detail}")
    return r.stdout


def _install_xray(conn: ServerConnection) -> None:
    info("Установка Xray на сервере выхода (~2 мин)...")
    r = conn.run(f"bash -c {shlex.quote(f'curl -fsSL {XRAY_INSTALL} | bash')}", timeout=180)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "(нет вывода)").strip()
        raise RuntimeError(f"Установка Xray не удалась (код {r.returncode}):\n{detail}")
    # убрать User=nobody — systemd считает его небезопасным и спамит в логах
    conn.run(
        "sed -i '/^User=nobody/d' /etc/systemd/system/xray.service"
        " && systemctl daemon-reload",
        timeout=15,
    )


def _tune_exit(conn: ServerConnection) -> None:
    """Сетевой тюнинг выхода по SSH: BBR+fq+mtu_probing+буферы (idempotent).
    Модуль tcp_bbr грузим до применения sysctl. Стабильность дальнего канала."""
    script = (
        "modprobe tcp_bbr; echo tcp_bbr > /etc/modules-load.d/cascade-bbr.conf; "
        "cat > /etc/sysctl.d/99-cascade-net.conf <<'EOF'\n"
        "net.core.default_qdisc=fq\n"
        "net.ipv4.tcp_congestion_control=bbr\n"
        "net.ipv4.tcp_mtu_probing=1\n"
        "net.core.rmem_max=16777216\n"
        "net.core.wmem_max=16777216\n"
        "net.ipv4.tcp_rmem=4096 87380 16777216\n"
        "net.ipv4.tcp_wmem=4096 65536 16777216\n"
        "EOF\n"
        "sysctl --system"
    )
    info("Сетевой тюнинг выхода (BBR/fq/буферы)")
    conn.run(f"bash -c {shlex.quote(script)}", timeout=30)


def _gen_keys(conn: ServerConnection) -> "tuple[str, str]":
    out = _run_checked(conn, "xray x25519", "Генерация Reality-ключей")
    return parse_x25519(out)


def _rebuild_xray(conn: ServerConnection, exit_server, clients: list) -> None:
    """Пересобрать config.json выхода из включённых клиентов + рестарт Xray.
    clients — list[Client]; в inbound идут только enabled."""
    enabled = {c.name: c.uuid for c in clients if c.enabled}
    config_json = build_xray_config(
        clients=enabled,
        private_key=exit_server.reality_private_key,
        short_id=exit_server.reality_short_id,
        sni=exit_server.vpn_sni,
        vpn_port=exit_server.vpn_port,
        xhttp_port=exit_server.vpn_xhttp_port if exit_server.vpn_xhttp_enabled else 0,
        xhttp_path=exit_server.vpn_xhttp_path,
        sni_legacy=exit_server.vpn_sni_legacy or [],
    )
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(config_json)
        local_tmp = Path(f.name)
    info(f"Заливка config.json на выход «{exit_server.location}»...")
    conn.run(f"mkdir -p {shlex.quote(str(Path(REMOTE_CONFIG).parent))}", timeout=10)
    if not conn.write_file(local_tmp, REMOTE_CONFIG):
        local_tmp.unlink(missing_ok=True)
        raise RuntimeError(f"Не удалось записать config.json на выход «{exit_server.location}».")
    local_tmp.unlink(missing_ok=True)
    _run_checked(conn, "systemctl restart xray", "Перезапуск Xray", timeout=30)


def deploy_vpn(conn: ServerConnection, exit_server, clients: list) -> None:
    """Полный деплой Xray на ОДИН выход. Генерит reality-ключи в exit_server.
    Заливает текущих clients (enabled)."""
    _install_xray(conn)
    _tune_exit(conn)
    # Ключи генерим только если их ещё нет. При смене IP (ключи заданы) — сохраняем,
    # иначе сломались бы все cascade-ссылки клиентов (host=мост неизменен, меняется лишь DNAT).
    if not exit_server.reality_private_key:
        private_key, public_key = _gen_keys(conn)
        exit_server.reality_private_key = private_key
        exit_server.reality_public_key = public_key
        exit_server.reality_short_id = gen_short_id()
    if exit_server.vpn_xhttp_enabled and not exit_server.vpn_xhttp_path:
        exit_server.vpn_xhttp_path = gen_short_id()

    info(f"Открытие порта {exit_server.vpn_port}...")
    conn.run(f"ufw allow {exit_server.vpn_port}/tcp || true", timeout=15)
    if exit_server.vpn_xhttp_enabled:
        conn.run(f"ufw allow {exit_server.vpn_xhttp_port}/tcp || true", timeout=15)
    _run_checked(conn, "systemctl enable xray", "Включение Xray в автозапуск")
    _rebuild_xray(conn, exit_server, clients)

    r = conn.run("systemctl is-active xray", timeout=10)
    if r.stdout.strip() != "active":
        logs = conn.run("journalctl -u xray -n 20 --no-pager", timeout=10).stdout
        raise RuntimeError(
            f"Xray на «{exit_server.location}» не активен (статус: {r.stdout.strip()}).\n"
            f"Логи:\n{logs}\nПришли это сообщение для диагностики."
        )
    ok(f"Xray развёрнут на «{exit_server.location}»")


def _find_client(cfg, name):
    return next((c for c in cfg.clients if c.name == name), None)


def add_vpn_client(cfg: Config, name: str, conns: dict) -> str:
    """Добавить клиента ВО ВСЕ выходы. conns = {exit.id: ServerConnection}.
    Возвращает uuid. Синхронизирует каждый выход (rebuild)."""
    if _find_client(cfg, name):
        raise ValueError(f"Клиент '{name}' уже существует")
    uid = gen_uuid()
    cfg.clients.append(Client(id=name, name=name, uuid=uid, enabled=True,
                              created=datetime.date.today().isoformat()))
    for ex in cfg.exit_servers:
        conn = conns[ex.id]
        _rebuild_xray(conn, ex, cfg.clients)
    save_config(cfg)
    ok(f"Клиент '{name}' добавлен на {len(cfg.exit_servers)} выход(а/ов)")
    return uid


def remove_vpn_client(cfg: Config, name: str, conns: dict) -> None:
    """Удалить клиента из ВСЕХ выходов. Минимум один клиент должен остаться."""
    c = _find_client(cfg, name)
    if not c:
        raise ValueError(f"Клиент '{name}' не найден")
    if len(cfg.clients) <= 1:
        raise ValueError("Нельзя удалить последнего клиента")
    cfg.clients.remove(c)
    for ex in cfg.exit_servers:
        _rebuild_xray(conns[ex.id], ex, cfg.clients)
    save_config(cfg)
    ok(f"Клиент '{name}' удалён")


def set_client_enabled(cfg: Config, name: str, enabled: bool, conns: dict) -> None:
    """Включить/выключить клиента. Выключенный выпадает из inbound (rebuild всех выходов)."""
    c = _find_client(cfg, name)
    if not c:
        raise ValueError(f"Клиент '{name}' не найден")
    if not enabled and sum(1 for cl in cfg.clients if cl.enabled) <= 1:
        raise ValueError("Нельзя выключить последнего активного клиента")
    c.enabled = enabled
    for ex in cfg.exit_servers:
        _rebuild_xray(conns[ex.id], ex, cfg.clients)
    save_config(cfg)
    ok(f"Клиент '{name}' {'включён' if enabled else 'выключен'}")


def rename_client(cfg: Config, old_name: str, new_name: str, conns: dict) -> None:
    """Переименовать клиента. Имя = email в Xray → нужен rebuild для синка.
    id/uuid/share-токены не меняются (id остаётся стабильным ключом)."""
    new_name = new_name.strip()
    if not new_name:
        raise ValueError("Имя не может быть пустым")
    c = _find_client(cfg, old_name)
    if not c:
        raise ValueError(f"Клиент '{old_name}' не найден")
    if new_name != old_name and _find_client(cfg, new_name):
        raise ValueError(f"Клиент '{new_name}' уже существует")
    c.name = new_name
    for ex in cfg.exit_servers:
        _rebuild_xray(conns[ex.id], ex, cfg.clients)
    save_config(cfg)
    ok(f"Клиент переименован: '{old_name}' → '{new_name}'")


def change_sni(conn: ServerConnection, exit_server, cfg: Config, new_sni: str) -> None:
    """Сменить SNI на одном выходе. Старый SNI уходит в legacy — Xray принимает оба
    пока клиенты обновят подписки. Очистить legacy → sni_legacy_clear()."""
    from datetime import date
    old_sni = exit_server.vpn_sni
    if old_sni and old_sni != new_sni and old_sni not in exit_server.vpn_sni_legacy:
        exit_server.vpn_sni_legacy.append(old_sni)
    exit_server.vpn_sni = new_sni
    exit_server.vpn_sni_changed_at = date.today().isoformat()
    _rebuild_xray(conn, exit_server, cfg.clients)
    save_config(cfg)
    ok(f"SNI на «{exit_server.location}» обновлён: {new_sni}")


def sni_legacy_clear(conn: ServerConnection, exit_server, cfg: Config) -> None:
    """Убрать все legacy SNI — вызывать когда все клиенты обновили подписки."""
    exit_server.vpn_sni_legacy = []
    _rebuild_xray(conn, exit_server, cfg.clients)
    save_config(cfg)
    ok(f"Legacy SNI очищены на «{exit_server.location}»")


def print_vpn_links(cfg: Config, relay_ip: str) -> None:
    """Ссылки + QR: каждый клиент × каждый выход (cascade)."""
    for c in cfg.clients:
        if not c.enabled:
            continue
        for ex in cfg.exit_servers:
            url = client_profile_url(c.uuid, ex, relay_ip, c.name, direct=False,
                                     fingerprint=cfg.fingerprint)
            print(f"\n{c.name} → {ex.location}:")
            print(url)
            qr(url)


def client_vless_url(cfg: Config, name: str, exit_id: str, relay_ip: str,
                     direct: bool = False) -> str:
    """VLESS-ссылка одного клиента на один выход."""
    c = _find_client(cfg, name)
    ex = next((e for e in cfg.exit_servers if e.id == exit_id), None)
    if not c or not ex:
        return ""
    return client_profile_url(c.uuid, ex, relay_ip, c.name, direct=direct,
                              fingerprint=cfg.fingerprint)


def restart_vpn(conn: ServerConnection) -> bool:
    r = conn.run("systemctl restart xray", timeout=30)
    return r.returncode == 0
