"""Главное меню CASCADE VPN (questionary, лайм-тема)."""
from __future__ import annotations

import os
import subprocess

import questionary
from questionary import Choice

import traceback

from cascade.config import Config, load_config, save_config
from cascade.console import LIME, NC, err, info, ok, qr, questionary_style, warn
from cascade.ssh import ServerConnection, SSHError, tcp_connect


def _handle_error(e: Exception) -> None:
    """Показать ошибку + подсказку отправить диагностику."""
    if isinstance(e, SSHError):
        err(f"Ошибка SSH: {e}")
        if e.hint:
            err(f"Подсказка: {e.hint}")
    elif isinstance(e, RuntimeError):
        err(str(e))
    else:
        err("Неожиданная ошибка:")
        traceback.print_exc()
    err("──────────────────────────────────────────")
    err("Скопируй сообщение выше и пришли для диагностики.")
    err("──────────────────────────────────────────")


def _header(cfg: "Config | None") -> None:
    status = "не настроен"
    if cfg and cfg.exit_servers:
        from cascade.ssh import tcp_connect
        ups = sum(1 for ex in cfg.exit_servers if tcp_connect(ex.ip, ex.vpn_port))
        status = f"{len(cfg.exit_servers)} выход(а/ов), активны {ups}"
    print(LIME)
    print("╔══════════════════════════════════════╗")
    print("║          🌐 CASCADE VPN              ║")
    print(f"║  {status:<35}║")
    print("╚══════════════════════════════════════╝")
    print(NC)


def main_menu() -> None:
    st = questionary_style()
    while True:
        cfg = load_config()
        _header(cfg)
        choice = questionary.select(
            "",
            choices=[
                Choice("🔧 Установка и настройка",       value="1", shortcut_key="1"),
                Choice("🛡️  Управление VPN (VLESS+Reality)", value="2", shortcut_key="2"),
                Choice("✈️  Управление MTProto",          value="3", shortcut_key="3"),
                Choice("📊 Статус и диагностика",         value="4", shortcut_key="4"),
                Choice("⚙️  Настройки",                   value="5", shortcut_key="5"),
                Choice("🌐 Веб-панель",                   value="6", shortcut_key="6"),
                Choice("🚪 Выход",                        value="7", shortcut_key="7"),
            ],
            style=st, qmark="", use_shortcuts=True,
        ).ask()
        if choice is None or choice.startswith("7"):
            return
        n = choice[0]
        if n == "1":
            from cascade.wizard import run_wizard
            run_wizard(cfg)
        elif n == "2":
            vpn_menu(cfg)
        elif n == "3":
            mtproto_menu(cfg)
        elif n == "4":
            status_screen(cfg)
        elif n == "5":
            settings_menu(cfg)
        elif n == "6":
            panel_menu(cfg)


def _require_cfg(cfg: "Config | None") -> "Config | None":
    if not cfg or not cfg.exit_servers:
        warn("Сначала выполните установку (пункт 1)")
        input("Enter...")
        return None
    return cfg


def _relay_ip(st) -> str:
    """IP РФ-моста (точка входа каскада). При сбое автоопределения — спросить."""
    from cascade.wizard import _get_local_ip
    ip = _get_local_ip()
    if not ip:
        ip = questionary.text("IP этого (РФ) сервера:", style=st).ask() or ""
    return ip


def _conns(cfg):
    return {ex.id: ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
            for ex in cfg.exit_servers}


def vpn_menu(cfg: "Config | None") -> None:
    st = questionary_style()
    cfg = _require_cfg(cfg)
    if not cfg:
        return
    from cascade import vpn
    while True:
        choice = questionary.select(
            "🛡️  VPN (VLESS+Reality):",
            choices=[
                Choice("Показать клиентов + ссылки",   value="1", shortcut_key="1"),
                Choice("Добавить клиента",              value="2", shortcut_key="2"),
                Choice("Удалить клиента",               value="3", shortcut_key="3"),
                Choice("Включить / выключить клиента",  value="4", shortcut_key="4"),
                Choice("Переименовать клиента",         value="5", shortcut_key="5"),
                Choice("URL подписки клиента",          value="6", shortcut_key="6"),
                Choice("Профиль для устройства (JSON)", value="7", shortcut_key="7"),
                Choice("🌍 Выходы (серверы)",           value="8", shortcut_key="8"),
                Choice("Проверить SNI-домен",           value="9", shortcut_key="9"),
                Choice("← Назад",                      value="0", shortcut_key="0"),
            ],
            style=st, use_shortcuts=True,
        ).ask()
        if not choice or choice.startswith("0"):
            return
        n = choice[0]
        if n == "1":
            vpn.print_vpn_links(cfg, _relay_ip(st))
            input("Enter...")
        elif n == "2":
            name = questionary.text("Имя клиента:", style=st).ask()
            if not name:
                continue
            try:
                vpn.add_vpn_client(cfg, name, _conns(cfg))
                ex0 = cfg.exit_servers[0]
                print(vpn.client_vless_url(cfg, name, ex0.id, _relay_ip(st)))
            except ValueError as e:
                warn(str(e))
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif n == "3":
            if len(cfg.clients) <= 1:
                warn("Нельзя удалить последнего клиента"); input("Enter..."); continue
            names = [c.name for c in cfg.clients]
            pick = questionary.select("Удалить клиента:", choices=names + ["0. Отмена"],
                                      style=st).ask()
            if not pick or pick.startswith("0"):
                continue
            try:
                vpn.remove_vpn_client(cfg, pick, _conns(cfg))
            except ValueError as e:
                warn(str(e))
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif n == "4":
            names = [f"{'✅' if c.enabled else '⏸'} {c.name}" for c in cfg.clients]
            pick = questionary.select("Клиент:", choices=names + ["0. Отмена"], style=st).ask()
            if not pick or pick.startswith("0"):
                continue
            cname = pick.split(" ", 1)[1]
            client = next(c for c in cfg.clients if c.name == cname)
            enable = not client.enabled
            try:
                vpn.set_client_enabled(cfg, cname, enable, _conns(cfg))
                ok(f"{'Включён' if enable else 'Выключен'}: {cname}")
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif n == "5":
            names = [c.name for c in cfg.clients]
            old = questionary.select("Переименовать:", choices=names + ["0. Отмена"], style=st).ask()
            if not old or old.startswith("0"):
                continue
            new = questionary.text("Новое имя:", style=st).ask()
            if not new:
                continue
            try:
                vpn.rename_client(cfg, old, new, _conns(cfg))
                ok(f"Переименован: {old} → {new}")
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif n == "6":
            names = [c.name for c in cfg.clients]
            pick = questionary.select("Клиент:", choices=names + ["0. Отмена"], style=st).ask()
            if not pick or pick.startswith("0"):
                continue
            client = next(c for c in cfg.clients if c.name == pick)
            if client.sub_token and cfg.domain:
                url = f"https://{cfg.domain}/sub/{client.sub_token}"
                print(f"\n  {url}")
                qr(url)
            elif client.sub_token:
                print(f"\n  /sub/{client.sub_token}  (домен панели не задан)")
            else:
                warn("Подписка не создана — зайди в панель → Клиенты → Sub")
            input("Enter...")
        elif n == "7":
            _profile_screen(cfg, st)
        elif n == "8":
            exits_menu(cfg, st)
        elif n == "9":
            _sni_check_screen(cfg, st)


def _profile_screen(cfg, st) -> None:
    from cascade.config import SERVER_CREDS_DIR
    from cascade.xray_config import client_profile_json
    relay_ip = _relay_ip(st)
    if not relay_ip:
        warn("Без IP РФ-сервера профиль будет нерабочим — отменено")
        input("Enter..."); return
    cname = questionary.select("Клиент:", choices=[c.name for c in cfg.clients], style=st).ask()
    if not cname:
        return
    exloc = questionary.select("Выход:",
                               choices=[f"{e.id}: {e.location}" for e in cfg.exit_servers],
                               style=st).ask()
    if not exloc:
        return
    exit_id = exloc.split(":", 1)[0]
    ex = next(e for e in cfg.exit_servers if e.id == exit_id)
    direct = questionary.confirm("Direct (минуя мост, admin)?", default=False, style=st).ask()
    client = next(c for c in cfg.clients if c.name == cname)
    suffix = " direct" if direct else ""
    remarks = f"{ex.location}-{cname}{suffix}"
    conf_json = client_profile_json(client.uuid, ex, relay_ip, direct=direct,
                                    remarks=remarks, fingerprint=cfg.fingerprint)
    out_path = SERVER_CREDS_DIR / f"client-{cname}-{exit_id}{'-direct' if direct else ''}.json"
    out_path.write_text(conf_json, encoding="utf-8")
    os.chmod(out_path, 0o600)
    print(conf_json)
    ok(f"Сохранено: {out_path}")
    info("Импортируй как custom config в Happ/OneXray/v2rayNG/Nekoray")
    input("Enter...")


def _sni_check_screen(cfg, st) -> None:
    from cascade import sni as sni_mod
    domain = questionary.text("Домен для проверки (напр. yahoo.com):", style=st).ask()
    if not domain or not sni_mod.valid_domain(domain):
        warn("Некорректный домен"); input("Enter..."); return
    ex = cfg.exit_servers[0]
    if len(cfg.exit_servers) > 1:
        pick = questionary.select("Выход:", choices=[f"{e.id}: {e.location}" for e in cfg.exit_servers],
                                  style=st).ask()
        if pick:
            ex = next(e for e in cfg.exit_servers if e.id == pick.split(":")[0])
    info(f"Проверка {domain} с выхода {ex.location} (~10 сек)...")
    try:
        conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
        r = conn.run(sni_mod.build_check_cmd(domain), timeout=25)
        res = sni_mod.parse_check(r.stdout or "", domain)
        print(f"\n  TLS1.3: {'✅' if res['tls13'] else '❌'}  "
              f"X25519: {'✅' if res['x25519'] else '❌'}  "
              f"h2: {'✅' if res['h2'] else '❌'}  "
              f"HTTP: {res['http_code']}  "
              f"Редирект: {res['redirect'] or 'нет'}")
        if res["ok"]:
            ok(f"{domain} — годится как SNI для Reality")
        else:
            warn(f"{domain} — НЕ годится")
    except Exception as e:
        _handle_error(e)
    input("Enter...")


def exits_menu(cfg, st) -> None:
    from cascade import vpn, relay
    from cascade.config import ExitServer, save_config
    while True:
        lines = [f"{e.id}: {e.location} ({e.ip}) SNI:{e.vpn_sni} relay:{e.relay_port}" for e in cfg.exit_servers]
        info("Выходы:\n  " + "\n  ".join(lines))
        choice = questionary.select(
            "🌍 Выходы:",
            choices=[
                Choice("Добавить выход",      value="1", shortcut_key="1"),
                Choice("Удалить выход",       value="2", shortcut_key="2"),
                Choice("Сменить SNI",         value="3", shortcut_key="3"),
                Choice("Перезапустить Xray",  value="4", shortcut_key="4"),
                Choice("Проверить SSH+TCP",   value="5", shortcut_key="5"),
                Choice("Сделать основным (подписка)", value="6", shortcut_key="6"),
                Choice("← Назад",             value="0", shortcut_key="0"),
            ],
            style=st, use_shortcuts=True,
        ).ask()
        if not choice or choice.startswith("0"):
            return
        if choice.startswith("1"):
            eid = questionary.text("ID выхода (лат., напр. ger):", style=st).ask()
            if not eid or any(e.id == eid for e in cfg.exit_servers):
                warn("Пустой или занятый ID"); input("Enter..."); continue
            loc = questionary.text("Локация:", default=eid, style=st).ask()
            ip = questionary.text("IP выхода:", style=st).ask()
            if not ip:
                continue
            user = questionary.text("SSH-пользователь:", default="root", style=st).ask()
            # relay_port = max существующий + 10, чтобы не пересекаться на мосту
            relay_port = max((e.relay_port for e in cfg.exit_servers), default=8434) + 10
            sni = questionary.text("SNI:", default="www.google.com", style=st).ask()
            ex = ExitServer(id=eid, location=loc, ip=ip, ssh_user=user,
                            relay_port=relay_port, vpn_port=relay_port, vpn_sni=sni)
            try:
                from cascade.ssh import SSHError
                from cascade.wizard import _fix_ssh_auth
                conn = ServerConnection(ip, user, port=ex.ssh_port)
                try:
                    conn.check_ssh()
                except SSHError as e:
                    if getattr(e, "hint_type", "") == "auth":
                        if _fix_ssh_auth(ip, user, ex.ssh_port, st):
                            conn.check_ssh()
                        else:
                            raise
                    else:
                        raise
                vpn.deploy_vpn(conn, ex, cfg.clients)   # зальёт всех текущих клиентов
                relay.apply_rule(relay.RelayRule("tcp", ex.relay_port, ip, ex.vpn_port))
                cfg.exit_servers.append(ex)
                save_config(cfg)
                ok(f"Выход «{loc}» добавлен (relay-порт {relay_port})")
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif choice.startswith("2"):
            if len(cfg.exit_servers) <= 1:
                warn("Нельзя удалить последний выход"); input("Enter..."); continue
            pick = questionary.select("Удалить выход:",
                                      choices=[e.id for e in cfg.exit_servers] + ["0. Отмена"],
                                      style=st).ask()
            if not pick or pick.startswith("0"):
                continue
            ex = next(e for e in cfg.exit_servers if e.id == pick)
            relay.remove_rule(relay.RelayRule("tcp", ex.relay_port, ex.ip, ex.vpn_port), quiet=True)
            cfg.exit_servers.remove(ex)
            save_config(cfg)
            ok(f"Выход «{ex.location}» удалён (Xray на нём не трогаем)")
            input("Enter...")
        elif choice.startswith("3"):
            exits = cfg.exit_servers
            ex = exits[0] if len(exits) == 1 else next(
                (e for e in exits if e.id == questionary.select(
                    "Выход:", choices=[f"{e.id}: {e.location}" for e in exits], style=st).ask().split(":")[0]), exits[0])
            new_sni = questionary.text("Новый SNI:", default=ex.vpn_sni, style=st).ask()
            if not new_sni or new_sni == ex.vpn_sni:
                continue
            try:
                conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
                vpn.change_sni(conn, ex, cfg, new_sni)
                ok(f"SNI → {new_sni}. Legacy {ex.vpn_sni_legacy} активен 48ч.")
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif choice.startswith("4"):
            exits = cfg.exit_servers
            pick = questionary.select("Выход:", choices=[f"{e.id}: {e.location}" for e in exits],
                                      style=st).ask() if len(exits) > 1 else f"{exits[0].id}: {exits[0].location}"
            if not pick:
                continue
            ex = next(e for e in exits if e.id == pick.split(":")[0])
            try:
                conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
                vpn.restart_vpn(conn)
                ok(f"Xray на «{ex.location}» перезапущен")
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif choice.startswith("5"):
            exits = cfg.exit_servers
            pick = questionary.select("Выход:", choices=[f"{e.id}: {e.location}" for e in exits],
                                      style=st).ask() if len(exits) > 1 else f"{exits[0].id}: {exits[0].location}"
            if not pick:
                continue
            ex = next(e for e in exits if e.id == pick.split(":")[0])
            try:
                conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
                ssh_ok = conn.check_ssh()
                tcp_ok = tcp_connect(ex.ip, ex.vpn_port)
                print(f"\n  SSH: {'✅' if ssh_ok else '❌'}  TCP {ex.vpn_port}: {'✅' if tcp_ok else '❌'}")
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif choice.startswith("6"):
            from cascade.config import primary_exit, save_config
            cur = primary_exit(cfg)
            pick = questionary.select(
                "Основной выход (его отдаёт подписка):",
                choices=[f"{e.id}: {e.location}" + (" ★" if cur and e.id == cur.id else "")
                         for e in cfg.exit_servers] + ["0. Отмена"],
                style=st).ask()
            if not pick or pick.startswith("0"):
                continue
            eid = pick.split(":", 1)[0]
            cfg.primary_exit_id = eid
            save_config(cfg)
            ex = next(e for e in cfg.exit_servers if e.id == eid)
            ok(f"Основной выход: {ex.location}. Клиенты подтянут за ≤3ч.")
            input("Enter...")


def mtproto_menu(cfg: "Config | None") -> None:
    st = questionary_style()
    cfg = _require_cfg(cfg)
    if not cfg:
        return
    from cascade import mtproto
    from cascade.config import mtproto_exit, mtproto_port_exit
    while True:
        ports_info = ", ".join(str(p) for p in cfg.mtproto_ports) or "нет"
        info(f"MTProto порты: {ports_info}")
        choice = questionary.select(
            "✈️  MTProto:",
            choices=[
                Choice("Показать ссылки + QR",  value="1", shortcut_key="1"),
                Choice("Добавить порт",          value="2", shortcut_key="2"),
                Choice("Сменить секрет порта",   value="3", shortcut_key="3"),
                Choice("Удалить порт",           value="4", shortcut_key="4"),
                Choice("Перезапустить все",      value="5", shortcut_key="5"),
                Choice("🌍 Выход для MTProto",   value="6", shortcut_key="6"),
                Choice("← Назад",               value="0", shortcut_key="0"),
            ],
            style=st, use_shortcuts=True,
        ).ask()
        if not choice or choice.startswith("0"):
            return
        if choice.startswith("6"):
            from cascade.config import save_config
            cur = mtproto_exit(cfg)
            pick = questionary.select(
                "Выход для MTProto (mtg):",
                choices=[f"{e.id}: {e.location}" + (" ★" if cur and e.id == cur.id else "")
                         for e in cfg.exit_servers] + ["0. Отмена"],
                style=st).ask()
            if not pick or pick.startswith("0"):
                continue
            cfg.mtproto_exit_id = pick.split(":", 1)[0]
            save_config(cfg)
            ok(f"Выход MTProto: {pick}. Новые порты развернутся там.")
            input("Enter...")
            continue
        first = mtproto_exit(cfg)
        if choice.startswith("1"):
            ip = _relay_ip(st)
            if not cfg.mtproto_ports:
                warn("Нет MTProto-портов"); input("Enter..."); continue
            for port_s, secret in cfg.mtproto_secrets.items():
                label = cfg.mtproto_labels.get(port_s, "")
                link = mtproto.tg_link(ip, int(port_s), secret)
                print(f"\n  {'[' + label + '] ' if label else ''}Порт {port_s}:")
                print(f"  {link}")
                qr(link)
            input("Enter...")
        elif choice.startswith("2"):
            v = questionary.text("Порт:", style=st).ask()
            if not v or not v.isdigit():
                continue
            port = int(v)
            if port in cfg.mtproto_ports:
                warn(f"Порт {port} уже используется"); input("Enter..."); continue
            domain = questionary.text("Fake-TLS домен:", default="yahoo.com", style=st).ask() or "yahoo.com"
            label = questionary.text("Метка (имя юзера, необязательно):", style=st).ask() or ""
            try:
                conn = ServerConnection(first.ip, first.ssh_user, port=first.ssh_port)
                secret = mtproto.deploy_mtproto(conn, port, domain)
                cfg.mtproto_ports.append(port)
                cfg.mtproto_secrets[str(port)] = secret
                cfg.mtproto_port_exits[str(port)] = first.id
                if label:
                    cfg.mtproto_labels[str(port)] = label
                save_config(cfg)
                ip = _relay_ip(st)
                link = mtproto.tg_link(ip, port, secret)
                print(f"\n  {link}")
                qr(link)
                ok(f"MTProto порт {port} добавлен")
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif choice.startswith("3"):
            if not cfg.mtproto_ports:
                warn("Нет MTProto-портов"); input("Enter..."); continue
            pick = questionary.select("Порт:", choices=[str(p) for p in cfg.mtproto_ports] + ["0. Отмена"],
                                      style=st).ask()
            if not pick or pick.startswith("0"):
                continue
            port = int(pick)
            domain = cfg.mtproto_labels.get(str(port), "yahoo.com")
            try:
                pex = mtproto_port_exit(cfg, port)
                conn = ServerConnection(pex.ip, pex.ssh_user, port=pex.ssh_port)
                new_secret = mtproto.gen_secret(domain)
                mtproto.deploy_mtproto(conn, port, domain, new_secret)
                cfg.mtproto_secrets[str(port)] = new_secret
                save_config(cfg)
                ip = _relay_ip(st)
                link = mtproto.tg_link(ip, port, new_secret)
                print(f"\n  {link}")
                qr(link)
                ok(f"Секрет порта {port} обновлён")
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif choice.startswith("4"):
            if not cfg.mtproto_ports:
                warn("Нет MTProto-портов"); input("Enter..."); continue
            pick = questionary.select("Удалить порт:", choices=[str(p) for p in cfg.mtproto_ports] + ["0. Отмена"],
                                      style=st).ask()
            if not pick or pick.startswith("0"):
                continue
            port = int(pick)
            try:
                pex = mtproto_port_exit(cfg, port)
                conn = ServerConnection(pex.ip, pex.ssh_user, port=pex.ssh_port)
                mtproto.remove_mtproto(conn, port)
                cfg.mtproto_ports = [p for p in cfg.mtproto_ports if p != port]
                cfg.mtproto_secrets.pop(str(port), None)
                cfg.mtproto_labels.pop(str(port), None)
                cfg.mtproto_port_exits.pop(str(port), None)
                save_config(cfg)
                ok(f"MTProto порт {port} удалён")
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif choice.startswith("5"):
            try:
                for p in cfg.mtproto_ports:
                    pex = mtproto_port_exit(cfg, p)
                    conn = ServerConnection(pex.ip, pex.ssh_user, port=pex.ssh_port)
                    mtproto.restart_mtproto(conn, p)
                ok("Все MTProto-порты перезапущены")
            except Exception as e:
                _handle_error(e)
            input("Enter...")


def status_screen(cfg: "Config | None") -> None:
    cfg = _require_cfg(cfg)
    if not cfg:
        return
    from cascade import relay
    from cascade.monitor import check_once
    for label, ip, port, up in check_once(cfg):
        mark = "✅" if up else "❌"
        print(f"  {mark} {label} {ip}:{port}")
    print("\nRelay-правила (РФ-сервер):")
    print(relay.list_dnat() or "  (нет)")
    input("\nEnter...")


def settings_menu(cfg: "Config | None") -> None:
    st = questionary_style()
    cfg = _require_cfg(cfg)
    if not cfg:
        return
    while True:
        choice = questionary.select(
            "⚙️  Настройки:",
            choices=[
                Choice("🔔 Telegram-уведомления",  value="1", shortcut_key="1"),
                Choice("⏱️  Интервал мониторинга", value="2", shortcut_key="2"),
                Choice("🔄 Авто-рестарт сервисов", value="3", shortcut_key="3"),
                Choice("🔑 SSH-доступы",           value="4", shortcut_key="4"),
                Choice("🌐 Домен панели",           value="5", shortcut_key="5"),
                Choice("🔒 Пароль панели",          value="6", shortcut_key="6"),
                Choice("🎭 Фингерпринт (TLS-маскировка)", value="9", shortcut_key="9"),
                Choice("🔁 Перезагрузить серверы",  value="7", shortcut_key="7"),
                Choice("🗑️  Удалить всё",           value="8", shortcut_key="8"),
                Choice("← Назад",                  value="0", shortcut_key="0"),
            ],
            style=st, use_shortcuts=True,
        ).ask()
        if not choice or choice.startswith("0"):
            return
        n = choice[0]
        if n == "1":
            cfg.telegram_bot_token = questionary.text(
                "Bot token:", default=cfg.telegram_bot_token, style=st).ask() or ""
            cfg.telegram_chat_id = questionary.text(
                "Chat ID:", default=cfg.telegram_chat_id, style=st).ask() or ""
            save_config(cfg)
            ok("Сохранено")
        elif n == "2":
            v = questionary.text("Интервал (мин):",
                                 default=str(cfg.monitor_interval_min), style=st).ask()
            if v and v.isdigit():
                cfg.monitor_interval_min = int(v)
                save_config(cfg)
                _install_cron(cfg)
                ok("Сохранено")
        elif n == "3":
            cfg.auto_restart = questionary.confirm(
                "Авто-рестарт?", default=cfg.auto_restart, style=st).ask()
            save_config(cfg)
            ok("Сохранено")
        elif n == "4":
            first = cfg.exit_servers[0]
            first.ssh_user = questionary.text(
                "SSH-пользователь (выход 1):", default=first.ssh_user, style=st).ask()
            v = questionary.text("SSH-порт:", default=str(first.ssh_port), style=st).ask()
            if v and v.isdigit():
                first.ssh_port = int(v)
            save_config(cfg)
            ok("Сохранено")
        elif n == "5":
            cfg.domain = questionary.text(
                "Техдомен панели (напр. tech.example.ru):",
                default=cfg.domain, style=st).ask() or ""
            save_config(cfg)
            if cfg.panel.enabled and cfg.domain:
                from cascade.panel import deploy
                try:
                    deploy.apply_panel(cfg.domain, cfg.panel.port)
                    ok("Сохранено, Caddy перенастроен на новый домен")
                except Exception as e:
                    _handle_error(e)
            else:
                ok("Сохранено")
        elif n == "6":
            from cascade.panel.auth import hash_password
            pw = questionary.password("Новый пароль панели:", style=st).ask()
            if pw:
                user = questionary.text("Логин панели:",
                                        default=cfg.panel.user or "admin", style=st).ask()
                cfg.panel.user = user or "admin"
                cfg.panel.password_hash = hash_password(pw)
                cfg.panel.enabled = True
                save_config(cfg)
                ok(f"Пароль панели задан (логин {cfg.panel.user})")
        elif n == "9":
            from cascade.xray_config import FINGERPRINTS
            fp = questionary.select(
                "TLS-фингерпринт клиента (firefox помогает при блокировках chrome):",
                choices=FINGERPRINTS,
                default=cfg.fingerprint if cfg.fingerprint in FINGERPRINTS else "firefox",
                style=st,
            ).ask()
            if fp:
                cfg.fingerprint = fp
                save_config(cfg)
                ok(f"Фингерпринт: {fp}. Клиентам перевыдать профиль (JSON/ссылку).")
        elif n == "7":
            _reboot_menu(cfg)
        elif n == "8":
            _uninstall(cfg)
            return


def panel_menu(cfg: "Config | None") -> None:
    st = questionary_style()
    if cfg is None:
        from cascade.config import Config as _Config
        cfg = _Config()
    from cascade.panel.auth import hash_password
    from cascade.panel import deploy

    # первичная настройка если панель ещё не сконфигурирована
    if not cfg.domain or not cfg.panel.password_hash:
        cfg.domain = questionary.text("Техдомен панели:", default=cfg.domain or "", style=st).ask() or ""
        if not cfg.domain:
            warn("Без домена панель не поднять"); input("Enter..."); return
        pw = questionary.password("Пароль панели:", style=st).ask()
        if not pw:
            return
        cfg.panel.user = questionary.text("Логин:", default=cfg.panel.user or "admin", style=st).ask() or "admin"
        cfg.panel.password_hash = hash_password(pw)
        save_config(cfg)
        try:
            deploy.apply_panel(cfg.domain, cfg.panel.port)
            cfg.panel.enabled = True
            save_config(cfg)
            ok(f"Панель поднята: https://{cfg.domain}/boss  (логин {cfg.panel.user})")
        except Exception as e:
            _handle_error(e)
        input("Enter...")
        return

    # панель уже настроена — меню управления
    while True:
        status = "включена" if cfg.panel.enabled else "выключена"
        choice = questionary.select(
            f"🌐 Веб-панель ({status}):",
            choices=[
                Choice(f"Открыть  https://{cfg.domain}/boss", value="1", shortcut_key="1"),
                Choice("Изменить домен",                       value="2", shortcut_key="2"),
                Choice("Изменить пароль / логин",             value="3", shortcut_key="3"),
                Choice("Перезапустить",                        value="4", shortcut_key="4"),
                Choice("Выключить" if cfg.panel.enabled else "Включить", value="5", shortcut_key="5"),
                Choice("← Назад",                             value="0", shortcut_key="0"),
            ],
            style=st, use_shortcuts=True,
        ).ask()
        if not choice or choice == "0":
            return
        if choice == "1":
            ok(f"https://{cfg.domain}/boss  (логин {cfg.panel.user})")
            input("Enter...")
        elif choice == "2":
            new_domain = questionary.text("Новый домен:", default=cfg.domain, style=st).ask() or ""
            if new_domain and new_domain != cfg.domain:
                cfg.domain = new_domain
                save_config(cfg)
                if cfg.panel.enabled:
                    try:
                        deploy.apply_panel(cfg.domain, cfg.panel.port)
                        ok(f"Домен изменён: https://{cfg.domain}/boss")
                    except Exception as e:
                        _handle_error(e)
                else:
                    ok("Домен сохранён (панель выключена, применится при включении)")
            input("Enter...")
        elif choice == "3":
            pw = questionary.password("Новый пароль:", style=st).ask()
            if pw:
                cfg.panel.user = questionary.text(
                    "Логин:", default=cfg.panel.user or "admin", style=st).ask() or "admin"
                cfg.panel.password_hash = hash_password(pw)
                save_config(cfg)
                ok(f"Пароль обновлён (логин {cfg.panel.user})")
            input("Enter...")
        elif choice == "4":
            try:
                subprocess.run(["systemctl", "restart", "cascade-panel"], check=False)
                ok("Перезапущено")
            except Exception as e:
                _handle_error(e)
            input("Enter...")
        elif choice == "5":
            if cfg.panel.enabled:
                subprocess.run(["systemctl", "stop", "cascade-panel"], check=False)
                cfg.panel.enabled = False
                save_config(cfg)
                ok("Панель остановлена")
            else:
                try:
                    deploy.apply_panel(cfg.domain, cfg.panel.port)
                    cfg.panel.enabled = True
                    save_config(cfg)
                    ok(f"Панель запущена: https://{cfg.domain}/boss")
                except Exception as e:
                    _handle_error(e)
            input("Enter...")


def _install_cron(cfg: Config) -> None:
    line = f"*/{cfg.monitor_interval_min} * * * * cascade --monitor"
    subprocess.run(
        ["bash", "-c",
         f"(crontab -l 2>/dev/null | grep -v 'cascade --monitor'; echo '{line}') | crontab -"],
        check=False,
    )


def _reboot_menu(cfg: Config) -> None:
    st = questionary_style()
    choice = questionary.select(
        "Что перезапустить?",
        choices=[
            Choice("Только сервисы (Xray+mtg) на всех выходах", value="1", shortcut_key="1"),
            Choice("Reboot ВСЕХ серверов выхода",                value="2", shortcut_key="2"),
            Choice("Отмена",                                     value="0", shortcut_key="0"),
        ],
        style=st, use_shortcuts=True,
    ).ask()
    if not choice or choice.startswith("0"):
        return
    from cascade import mtproto, vpn
    if choice.startswith("2") and questionary.text(
            "Reboot ВСЕХ серверов выхода — введите YES:", style=st).ask() != "YES":
        return
    for ex in cfg.exit_servers:
        conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
        if choice.startswith("1"):
            vpn.restart_vpn(conn)
            if ex is cfg.exit_servers[0]:
                for p in cfg.mtproto_ports:
                    mtproto.restart_mtproto(conn, p)
        elif choice.startswith("2"):
            conn.run("reboot", timeout=10)
    ok("Готово")
    input("Enter...")


def _uninstall(cfg: Config) -> None:
    st = questionary_style()
    if questionary.text("Введите YES для удаления ВСЕГО:", style=st).ask() != "YES":
        return
    from cascade import relay
    for ex in cfg.exit_servers:
        conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
        conn.run("systemctl disable --now xray; rm -f /usr/local/etc/xray/config.json", timeout=30)
        if ex is cfg.exit_servers[0]:
            for p in cfg.mtproto_ports:
                conn.run(f"systemctl disable --now cascade-mtg@{p}", timeout=20)
        relay.remove_rule(relay.RelayRule("tcp", ex.relay_port, ex.ip, ex.vpn_port), quiet=True)
        if ex.vpn_xhttp_enabled:
            relay.remove_rule(
                relay.RelayRule("tcp", ex.vpn_xhttp_port, ex.ip, ex.vpn_xhttp_port), quiet=True)
    if cfg.exit_servers:
        first_ip = cfg.exit_servers[0].ip
        for p in cfg.mtproto_ports:
            relay.remove_rule(relay.RelayRule("tcp", p, first_ip, p), quiet=True)
    from cascade.config import CONFIG_PATH
    CONFIG_PATH.unlink(missing_ok=True)
    ok("Удалено")
    input("Enter...")
