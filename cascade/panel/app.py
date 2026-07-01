"""Flask-панель CASCADE. Фабрика create_app + роуты ядра."""
from __future__ import annotations

import secrets
import shutil
import subprocess
from functools import wraps
from pathlib import Path

from flask import (Flask, flash, redirect, render_template, request, send_file,
                   session, url_for)

from cascade import relay, sni, vpn
from cascade.config import (CONFIG_PATH, SERVER_CREDS_DIR, load_config, save_config,
                            primary_exit, mtproto_exit, mtproto_port_exit)
from cascade.monitor import check_once
from cascade.panel import share as share_mod
from cascade.panel.auth import hash_password, verify_password
from cascade.ssh import ServerConnection
from cascade.wizard import _get_local_ip
from cascade.xray_config import client_profile_url, client_profile_json

SECRET_PATH = SERVER_CREDS_DIR / "panel_secret"


def _load_secret(secret_path: Path) -> str:
    """Постоянный ключ подписи сессий. Генерим один раз, храним 0600."""
    if secret_path.is_file():
        return secret_path.read_text(encoding="utf-8").strip()
    secret_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    val = secrets.token_hex(32)
    secret_path.write_text(val, encoding="utf-8")
    secret_path.chmod(0o600)
    return val


def _csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("auth"):
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


_RELAY_IP = {"v": ""}


def _relay_ip() -> str:
    # кэшируем непустой IP моста (стабилен) — не дёргать curl на каждый запрос /c/<token>
    if not _RELAY_IP["v"]:
        _RELAY_IP["v"] = _get_local_ip() or ""
    return _RELAY_IP["v"]


def _conns(c):
    return {ex.id: ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
            for ex in c.exit_servers}


# Активные тесты диагностики: имя → (заголовок, где выполнять).
# scope "bridge" — subprocess на мосту; "exit" — conn.run по SSH на выходе.
_DIAG_TESTS = {
    "speed":      ("Скорость канала мост↔выход (iperf3)", "bridge_shell"),
    "ss":         ("TCP-сессии каскада (cwnd/rtt/retrans)", "bridge"),
    "ping":       ("Канал мост→выход (latency/потери)", "bridge"),
    "mtr":        ("Трасса мост→выход (потери по хопам)", "bridge"),
    "exit_speed": ("Скорость выход→интернет", "exit"),
}
_DIAG_PKG = {"mtr": "mtr-tiny"}  # подсказка установки если утилиты нет


def _diag_cmd(name, ex):
    """Команда теста для выхода ex. ss/ping/mtr — список argv (мост, без shell),
    exit_speed — строка (SSH), speed — bash-скрипт (мост, scope bridge_shell).
    Аргументы только из конфига (ex.ip валидный IP, ex.ssh_port int) →
    пользовательского ввода нет, shell-инъекция невозможна."""
    if name == "speed":
        # iperf3 в обе стороны: выход→мост (RU-bound, главное) + мост→выход (upload).
        p, ip, user = ex.ssh_port, ex.ip, ex.ssh_user
        ssh = (f"ssh -p {p} -o BatchMode=yes -o StrictHostKeyChecking=accept-new "
               f"-o ConnectTimeout=10 {user}@{ip}")
        return (
            "command -v iperf3 >/dev/null 2>&1 || apt-get install -y iperf3 >/dev/null 2>&1\n"
            f"{ssh} 'command -v iperf3 >/dev/null 2>&1 || apt-get install -y iperf3 >/dev/null 2>&1 "
            "|| (apt-get update >/dev/null 2>&1 && apt-get install -y iperf3 >/dev/null 2>&1); "
            "pkill iperf3 2>/dev/null; sleep 1; iperf3 -s -D'\n"
            "sleep 2\n"
            "echo '===== выход -> мост (в сторону РФ, главное) ====='\n"
            f"iperf3 -c {ip} -p 5201 -R -t 15 -i 5\n"
            "echo '===== мост -> выход (upload) ====='\n"
            f"iperf3 -c {ip} -p 5201 -t 10 -i 5\n"
            f"{ssh} 'pkill iperf3' 2>/dev/null\n"
        )
    if name == "ss":
        return ["ss", "-tin", f"dst {ex.ip}"]
    if name == "ping":
        return ["ping", "-c", "20", "-i", "0.2", "-W", "2", ex.ip]
    if name == "mtr":
        return ["mtr", "--tcp", "--port", str(ex.vpn_port), "-c", "20",
                "--report", "--report-wide", ex.ip]
    if name == "exit_speed":
        return ("curl -o /dev/null -s --max-time 20 -w "
                "'down=%{speed_download}B/s ttfb=%{time_starttransfer}s "
                "total=%{time_total}s code=%{http_code}\\n' "
                "https://speed.cloudflare.com/__down?bytes=104857600")
    return None


def _qr_svg(data: str) -> str:
    """Inline-SVG QR через qrencode. Пусто, если qrencode нет."""
    if shutil.which("qrencode") is None:
        return ""
    r = subprocess.run(["qrencode", "-t", "SVG", "-o", "-", data],
                       capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def _mtproto_items(c, relay_ip: str) -> list:
    """MTProto-порты с секретом/ссылкой/QR/меткой для рендера (дашборд и клиенты)."""
    from cascade import mtproto as mtproto_mod
    items = []
    for p in (c.mtproto_ports if c else []):
        secret = c.mtproto_secrets.get(str(p), "")
        link = mtproto_mod.tg_link(relay_ip, p, secret) if (secret and relay_ip) else ""
        items.append({"port": p, "label": c.mtproto_labels.get(str(p), ""),
                      "secret": secret, "link": link,
                      "qr": _qr_svg(link) if link else ""})
    return items


def _bridge_mtproto_items(c) -> list:
    """TELEMT-записи на мосту с TG-ссылкой/QR для страницы «Клиенты»."""
    from cascade import mtproto as mtproto_mod
    items = []
    domain = c.domain if c else ""
    host = f"test.{domain}" if domain else ""
    for label, secret in (c.bridge_mtproto_secrets.items() if c else {}.items()):
        link = mtproto_mod.tg_link(host, 443, secret) if (host and secret) else ""
        items.append({
            "label": label,
            "secret": secret,
            "link": link,
            "qr": _qr_svg(link) if link else "",
        })
    return items


def _client_profiles(c, client, relay_ip: str) -> list:
    """vless-профили клиента: каждый выход × cascade/direct (url + QR)."""
    if not relay_ip:
        return []
    profiles = []
    for ex in c.exit_servers:
        for direct in (False, True):
            url = client_profile_url(client.uuid, ex, relay_ip, client.name,
                                     direct=direct, fingerprint=c.fingerprint)
            prof_json = client_profile_json(client.uuid, ex, relay_ip, direct=direct,
                                            remarks=f"{ex.location}-{client.name}"
                                                    + (" direct" if direct else ""),
                                            fingerprint=c.fingerprint)
            profiles.append({"exit": ex.location, "mode": "direct" if direct else "cascade",
                             "url": url, "qr": _qr_svg(url), "json": prof_json,
                             "eid": ex.id, "direct": direct})
    return profiles


def _clients_view(c, relay_ip: str) -> list:
    """Клиенты с их vless+JSON-профилями (per выход×режим) для страницы «Клиенты»."""
    result = []
    for cl in (c.clients if c else []):
        profiles = _client_profiles(c, cl, relay_ip)
        sub_qrs = []
        bootstrap_qrs = []
        if cl.sub_token and c.domain:
            for ex in c.exit_servers:
                sub_url = f"https://{c.domain}/sub/{cl.sub_token}?exit={ex.id}"
                sub_qr = _qr_svg(sub_url)
                cascade_url = next((p["url"] for p in profiles
                                    if p["mode"] == "cascade" and p["eid"] == ex.id), "")
                bootstrap_qr = _qr_svg(f"{cascade_url}\n{sub_url}") if cascade_url else ""
                sub_qrs.append({"exit": ex.location, "eid": ex.id, "url": sub_url, "qr": sub_qr})
                bootstrap_qrs.append({"exit": ex.location, "eid": ex.id, "url": cascade_url,
                                      "sub_url": sub_url, "qr": bootstrap_qr})
        result.append({"c": cl, "profiles": profiles,
                        "sub_token": cl.sub_token,
                        "sub_qrs": sub_qrs, "bootstrap_qrs": bootstrap_qrs})
    return result


def _ensure_host_key(ip: str, port: int) -> None:
    """Авто-добавить SSH host-key выхода в known_hosts, если его ещё нет.
    В вебе нет TTY для интерактивной проверки (как в CLI) — ключ admin-настроенного
    выхода доверяем через ssh-keyscan. Нужно и для check, и при смене SSH-порта
    выхода (ключ хранится в нотации [ip]:port — у разных портов разные записи)."""
    from cascade.ssh import _host_key_known
    if _host_key_known(ip, port):
        return
    keyscan = subprocess.run(
        ["ssh-keyscan", "-T", "5", "-p", str(port), ip],
        capture_output=True, text=True, timeout=10,
    )
    if keyscan.stdout:
        kh = Path.home() / ".ssh" / "known_hosts"
        kh.parent.mkdir(mode=0o700, exist_ok=True)
        with open(kh, "a") as f:
            f.write(keyscan.stdout)


def _suggest_port(c) -> int:
    """Следующий свободный порт для нового MTProto (max занятых + 1)."""
    from cascade.config import used_ports
    used = used_ports(c) if c else set()
    return (max(used) + 1) if used else 8443


def create_app(config_path: Path = CONFIG_PATH, secret_path: Path = SECRET_PATH) -> Flask:
    app = Flask(__name__)
    app.secret_key = _load_secret(secret_path)
    app.config["CONFIG_PATH"] = config_path
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.jinja_env.globals["csrf_token"] = _csrf_token

    def cfg():
        return load_config(config_path)

    @app.get("/robots.txt")
    def robots():
        return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain"}

    @app.get("/")
    def decoy():
        return render_template("decoy.html")

    @app.route("/boss", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            if not _check_csrf():
                return render_template("login.html", error="Сессия истекла, повторите"), 400
            c = cfg()
            panel = c.panel if c else None
            if (panel and panel.enabled
                    and request.form.get("user") == panel.user
                    and verify_password(request.form.get("password", ""), panel.password_hash)):
                session.clear()          # против session fixation
                session["auth"] = True
                return redirect(url_for("dashboard"))
            return render_template("login.html", error="Неверный логин или пароль"), 401
        if session.get("auth"):
            return redirect(url_for("dashboard"))
        return render_template("login.html", error=None)

    @app.get("/boss/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/boss/")
    @login_required
    def dashboard():
        c = cfg()
        targets = check_once(c) if c else []
        relay_ip = _relay_ip()
        return render_template(
            "dashboard.html", targets=targets,
            n_clients=len(c.clients) if c else 0,
            n_exits=len(c.exit_servers) if c else 0,
            mtproto_count=len(c.mtproto_ports) if c else 0,
            mtproto_ports=c.mtproto_ports if c else [],
            mtproto_links=_mtproto_items(c, relay_ip),
            interval=c.monitor_interval_min if c else 5,
            auto_restart=c.auto_restart if c else False,
        )

    def _check_csrf():
        # отсутствующий токен — невалиден (иначе None==None пропускает пустые формы)
        tok = session.get("csrf")
        return bool(tok) and request.form.get("csrf") == tok

    @app.get("/boss/clients")
    @login_required
    def clients():
        c = cfg()
        relay_ip = _relay_ip()
        return render_template("clients.html", clients=_clients_view(c, relay_ip),
                               mtproto=_mtproto_items(c, relay_ip), relay_ip=relay_ip,
                               bridge_mtproto=_bridge_mtproto_items(c),
                               panel_domain=c.domain if c else "",
                               suggest_port=_suggest_port(c),
                               exits=c.exit_servers if c else [],
                               mtproto_exit_id=(mtproto_exit(c).id if c and c.exit_servers else ""))

    @app.post("/boss/clients/<cid>/share")
    @login_required
    def client_share(cid):
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        ttl_s = request.form.get("ttl_hours", "24")
        ttl = int(ttl_s) if ttl_s.isdigit() and int(ttl_s) > 0 else 24
        st = share_mod.add_share(c, cid, ttl_hours=ttl)
        save_config(c, config_path)
        relay_ip = _relay_ip()
        return render_template("clients.html", clients=_clients_view(c, relay_ip),
                               mtproto=_mtproto_items(c, relay_ip), relay_ip=relay_ip,
                               bridge_mtproto=_bridge_mtproto_items(c),
                               panel_domain=c.domain if c else "",
                               suggest_port=_suggest_port(c),
                               exits=c.exit_servers if c else [],
                               mtproto_exit_id=(mtproto_exit(c).id if c and c.exit_servers else ""),
                               share_link=f"/c/{st.token}")

    @app.post("/boss/clients/<cid>/toggle")
    @login_required
    def clients_toggle(cid):
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        target = next((cl for cl in c.clients if cl.id == cid), None)
        if target:
            try:
                vpn.set_client_enabled(c, target.name, not target.enabled, _conns(c))
            except ValueError as e:
                flash(str(e), "error")
            except Exception as e:
                flash(f"Не удалось переключить (SSH/выход): {e}", "error")
        return redirect(url_for("clients"))

    @app.post("/boss/clients/<cid>/rename")
    @login_required
    def clients_rename(cid):
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        target = next((cl for cl in c.clients if cl.id == cid), None)
        new_name = request.form.get("name", "").strip()
        if target and new_name:
            try:
                vpn.rename_client(c, target.name, new_name, _conns(c))
            except ValueError as e:
                flash(str(e), "error")
            except Exception as e:
                flash(f"Не удалось переименовать (SSH/выход): {e}", "error")
        return redirect(url_for("clients"))

    @app.post("/boss/clients/add")
    @login_required
    def clients_add():
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        name = request.form.get("name", "").strip()
        if name:
            try:
                vpn.add_vpn_client(c, name, _conns(c))
            except ValueError as e:
                flash(str(e))
            except Exception as e:
                flash(f"Не удалось добавить (SSH/выход): {e}")
        return redirect(url_for("clients"))

    @app.post("/boss/clients/<cid>/remove")
    @login_required
    def clients_remove(cid):
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        target = next((cl for cl in c.clients if cl.id == cid), None)
        if target:
            try:
                vpn.remove_vpn_client(c, target.name, _conns(c))
            except ValueError as e:
                flash(str(e))
            except Exception as e:
                flash(f"Не удалось удалить (SSH/выход): {e}")
        return redirect(url_for("clients"))

    @app.get("/c/<token>")
    def share_page(token):
        c = cfg()
        st = share_mod.find_valid(c, token) if c else None
        if not st:
            return render_template("decoy.html")  # не раскрываем
        client = next((cl for cl in c.clients if cl.id == st.client_id), None)
        if not client:
            return render_template("decoy.html")
        relay_ip = _relay_ip()
        if not relay_ip:
            # без IP моста cascade-ссылки были бы битыми (host пустой) — не отдаём
            return render_template("client_share.html", profiles=[], name=client.name,
                                   error="Сервер временно недоступен, попробуйте позже")
        profiles = []
        for ex in c.exit_servers:
            sub_url = ""
            sub_qr = ""
            if client.sub_token and c.domain:
                sub_url = f"https://{c.domain}/sub/{client.sub_token}?exit={ex.id}"
                sub_qr = _qr_svg(sub_url)
            for direct in (False, True):
                url = client_profile_url(client.uuid, ex, relay_ip, client.name,
                                         direct=direct, fingerprint=c.fingerprint)
                bootstrap_qr = ""
                if sub_url and not direct:
                    bootstrap_qr = _qr_svg(f"{url}\n{sub_url}")
                profiles.append({"exit": ex.location, "eid": ex.id,
                                 "mode": "direct" if direct else "cascade",
                                 "url": url, "qr": _qr_svg(url),
                                 "sub_token": client.sub_token or "",
                                 "sub_url": sub_url, "sub_qr": sub_qr,
                                 "bootstrap_qr": bootstrap_qr})
        return render_template("client_share.html", profiles=profiles, name=client.name)

    @app.get("/boss/exits")
    @login_required
    def exits():
        c = cfg()
        pex = primary_exit(c) if c else None
        return render_template("exits.html", exits=c.exit_servers if c else [],
                               primary_id=pex.id if pex else "")

    @app.post("/boss/exits/<eid>/remove")
    @login_required
    def exits_remove(eid):
        if not _check_csrf():
            return redirect(url_for("exits"))
        c = cfg()
        ex = next((e for e in c.exit_servers if e.id == eid), None)
        if ex and len(c.exit_servers) > 1:
            relay.remove_rule(relay.RelayRule("tcp", ex.relay_port, ex.ip, ex.vpn_port),
                              quiet=True)
            c.exit_servers.remove(ex)
            save_config(c, config_path)
        return redirect(url_for("exits"))

    @app.get("/boss/mtproto")
    @login_required
    def mtproto():
        # MTProto управляется на странице «Клиенты» (слитый раздел)
        return redirect(url_for("clients"))

    @app.post("/boss/mtproto/add")
    @login_required
    def mtproto_add():
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        from cascade import mtproto as mtproto_mod
        from cascade.config import used_ports
        if not c or not c.exit_servers:
            flash("Нет выхода для MTProto", "error")
            return redirect(url_for("clients"))
        label = request.form.get("label", "").strip()
        domain = request.form.get("domain", "google.com").strip() or "google.com"
        port_s = request.form.get("port", "").strip()
        if not port_s.isdigit() or not (1 <= int(port_s) <= 65535):
            flash("Некорректный порт", "error")
            return redirect(url_for("clients"))
        port = int(port_s)
        # 3 слоя проверки коллизии: конфиг → мост → выход
        if port in used_ports(c):
            flash(f"Порт {port} уже занят в конфиге (выход/relay/mtproto)", "error")
            return redirect(url_for("clients"))
        if relay.port_listening(port):
            flash(f"Порт {port} уже слушается на мосту", "error")
            return redirect(url_for("clients"))
        exit_id = request.form.get("exit_id", "").strip()
        if exit_id and any(e.id == exit_id for e in c.exit_servers):
            c.mtproto_exit_id = exit_id
        first = mtproto_exit(c)
        conn = ServerConnection(first.ip, first.ssh_user, port=first.ssh_port)
        try:
            if mtproto_mod.exit_port_listening(conn, port):
                flash(f"Порт {port} уже занят на выходе", "error")
                return redirect(url_for("clients"))
            secret = mtproto_mod.deploy_mtproto(conn, port, domain=domain)
            relay.apply_rule(relay.RelayRule("tcp", port, first.ip, port))
            c.mtproto_ports.append(port)
            c.mtproto_secrets[str(port)] = secret
            c.mtproto_port_exits[str(port)] = first.id
            if label:
                c.mtproto_labels[str(port)] = label
            save_config(c, config_path)
            flash(f"MTProto порт {port} добавлен на «{first.location}»" + (f" ({label})" if label else ""))
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("clients"))

    @app.post("/boss/mtproto/<int:port>/rotate")
    @login_required
    def mtproto_rotate(port):
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        if not c or port not in c.mtproto_ports:
            flash("Неизвестный порт", "error")
            return redirect(url_for("clients"))
        from cascade import mtproto as mtproto_mod
        first = mtproto_port_exit(c, port)
        conn = ServerConnection(first.ip, first.ssh_user, port=first.ssh_port)
        try:
            old_secret = c.mtproto_secrets.get(str(port), "")
            try:
                domain = mtproto_mod.domain_from_secret(old_secret) if old_secret else "google.com"
            except Exception:
                domain = "google.com"
            new_secret = mtproto_mod.gen_secret(domain)
            mtproto_mod.deploy_mtproto(conn, port, domain=domain, secret=new_secret)
            c.mtproto_secrets[str(port)] = new_secret
            save_config(c, config_path)
            flash(f"Секрет MTProto порта {port} обновлён (старые ссылки больше не работают)")
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("clients"))

    @app.post("/boss/mtproto/<int:port>/remove")
    @login_required
    def mtproto_remove(port):
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        if not c or port not in c.mtproto_ports:
            flash("Неизвестный порт", "error")
            return redirect(url_for("clients"))
        from cascade import mtproto as mtproto_mod
        first = mtproto_port_exit(c, port)
        conn = ServerConnection(first.ip, first.ssh_user, port=first.ssh_port)
        try:
            mtproto_mod.remove_mtproto(conn, port)
            relay.remove_rule(relay.RelayRule("tcp", port, first.ip, port), quiet=True)
            c.mtproto_ports = [p for p in c.mtproto_ports if p != port]
            c.mtproto_secrets.pop(str(port), None)
            c.mtproto_labels.pop(str(port), None)
            c.mtproto_port_exits.pop(str(port), None)
            save_config(c, config_path)
            flash(f"MTProto порт {port} удалён")
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("clients"))

    @app.post("/boss/mtproto/<int:port>/restart")
    @login_required
    def mtproto_restart(port):
        if not _check_csrf():
            return redirect(url_for("mtproto"))
        c = cfg()
        if not c or port not in c.mtproto_ports:
            flash("Неизвестный порт", "error")
            return redirect(url_for("mtproto"))
        try:
            first = mtproto_port_exit(c, port)
            from cascade import mtproto as mtproto_mod
            conn = ServerConnection(first.ip, first.ssh_user, port=first.ssh_port)
            mtproto_mod.restart_mtproto(conn, port)
            flash(f"MTProto порт {port} перезапущен")
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("mtproto"))

    # --- Bridge MTProto (TELEMT на GER, relay через nginx на мосту) ---

    def _telemt_exit_conn(c):
        """SSH-подключение к первому серверу выхода (GER) для деплоя TELEMT."""
        if not c.exit_servers:
            raise RuntimeError("Нет серверов выхода — TELEMT требует GER")
        ex = c.exit_servers[0]
        _ensure_host_key(ex.ip, ex.ssh_port)
        return ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port), ex

    @app.post("/boss/bridge-mtproto/add")
    @login_required
    def bridge_mtproto_add():
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        if not c:
            flash("Конфиг недоступен", "error")
            return redirect(url_for("clients"))
        label = request.form.get("label", "").strip()
        mask_domain = request.form.get("mask_domain", "").strip()
        if not label:
            flash("Укажи имя пользователя", "error")
            return redirect(url_for("clients"))
        from cascade.sni import valid_domain
        if not mask_domain or not valid_domain(mask_domain):
            flash("Некорректный маска-домен (используй ASN-сосед из SNI-сканера)", "error")
            return redirect(url_for("clients"))
        if label in c.bridge_mtproto_secrets:
            flash(f"Метка '{label}' уже существует", "error")
            return redirect(url_for("clients"))
        from cascade import mtproto as mtproto_mod
        from cascade.panel.deploy import apply_nginx_stream
        try:
            conn, ex = _telemt_exit_conn(c)
            secret = mtproto_mod.gen_secret(mask_domain)
            new_users = dict(c.bridge_mtproto_secrets)
            new_users[label] = secret
            mtproto_mod.deploy_telemt_remote(conn, mask_domain, new_users)
            # nginx на мосту: SNI-default → GER:8448
            apply_nginx_stream(c.domain, telemt_host=ex.ip)
            # убрать локальный TELEMT с моста если был
            mtproto_mod.remove_telemt_local()
            c.bridge_mtproto_secrets = new_users
            c.bridge_mtproto_domain = mask_domain
            save_config(c, config_path)
            flash(f"Bridge MTProto '{label}' добавлен. DNS: test.{c.domain} → {_relay_ip()}")
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("clients"))

    @app.post("/boss/bridge-mtproto/<label>/remove")
    @login_required
    def bridge_mtproto_remove(label):
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        if not c or label not in c.bridge_mtproto_secrets:
            flash("Неизвестная метка", "error")
            return redirect(url_for("clients"))
        from cascade import mtproto as mtproto_mod
        try:
            conn, ex = _telemt_exit_conn(c)
            c.bridge_mtproto_secrets.pop(label)
            if c.bridge_mtproto_secrets:
                # остались другие юзеры — перестроить TOML на GER
                mtproto_mod.deploy_telemt_remote(conn, c.bridge_mtproto_domain, c.bridge_mtproto_secrets)
            else:
                # последний юзер удалён — остановить TELEMT на GER
                mtproto_mod.remove_telemt_remote(conn)
                c.bridge_mtproto_domain = ""
            save_config(c, config_path)
            flash(f"Bridge MTProto '{label}' удалён")
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("clients"))

    @app.post("/boss/bridge-mtproto/restart")
    @login_required
    def bridge_mtproto_restart():
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        from cascade import mtproto as mtproto_mod
        try:
            conn, _ = _telemt_exit_conn(c)
            ok = mtproto_mod.restart_telemt_remote(conn)
            flash("TELEMT перезапущен" if ok else "Не удалось перезапустить TELEMT", "error" if not ok else "")
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("clients"))

    @app.get("/boss/share")
    @login_required
    def share_tokens():
        c = cfg()
        tokens = [
            {"token": st.token,
             "client_name": next((cl.name for cl in c.clients if cl.id == st.client_id), "?"),
             "created": st.created,
             "ttl_hours": st.ttl_hours}
            for st in c.share_tokens
        ] if c else []
        return render_template("share.html", tokens=tokens)

    @app.post("/boss/share/<token>/revoke")
    @login_required
    def share_revoke(token):
        if not _check_csrf():
            return redirect(url_for("share_tokens"))
        c = cfg()
        share_mod.revoke(c, token)
        save_config(c, config_path)
        flash("Share-ссылка отозвана")
        return redirect(url_for("share_tokens"))

    @app.post("/boss/exits/add")
    @login_required
    def exits_add():
        if not _check_csrf():
            return redirect(url_for("exits"))
        c = cfg()
        from cascade.config import ExitServer
        eid = request.form.get("eid", "").strip().lower().replace(" ", "_")
        location = request.form.get("location", "").strip()
        ip = request.form.get("ip", "").strip()
        ssh_user = request.form.get("ssh_user", "root").strip() or "root"
        ssh_port_s = request.form.get("ssh_port", "22").strip()
        sni = request.form.get("sni", "www.google.com").strip() or "www.google.com"
        vpn_port_s = request.form.get("vpn_port", "8444").strip()
        if not eid or not location or not ip:
            flash("ID, локация и IP обязательны", "error")
            return redirect(url_for("exits"))
        if any(e.id == eid for e in c.exit_servers):
            flash(f"ID «{eid}» уже занят", "error")
            return redirect(url_for("exits"))
        ssh_port = int(ssh_port_s) if ssh_port_s.isdigit() else 22
        vpn_port = int(vpn_port_s) if vpn_port_s.isdigit() else 8444
        relay_port = max((e.relay_port for e in c.exit_servers), default=8434) + 10
        ex = ExitServer(id=eid, location=location, ip=ip, ssh_user=ssh_user,
                        ssh_port=ssh_port, relay_port=relay_port,
                        vpn_port=vpn_port, vpn_sni=sni)
        try:
            _ensure_host_key(ip, ssh_port)  # нет TTY в веб-контексте
            conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
            conn.check_ssh()
            vpn.deploy_vpn(conn, ex, c.clients)
            relay.apply_rule(relay.RelayRule("tcp", relay_port, ip, vpn_port))
            c.exit_servers.append(ex)
            save_config(c, config_path)
            flash(f"Выход {location} добавлен (relay-порт {relay_port})")
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("exits"))

    @app.post("/boss/exits/<eid>/port")
    @login_required
    def exits_port(eid):
        if not _check_csrf():
            return redirect(url_for("exits"))
        c = cfg()
        ex = next((e for e in c.exit_servers if e.id == eid), None)
        if not ex:
            flash("Выход не найден", "error")
            return redirect(url_for("exits"))
        port_s = request.form.get("vpn_port", "").strip()
        if not port_s.isdigit() or not (1 <= int(port_s) <= 65535):
            flash("Некорректный порт", "error")
            return redirect(url_for("exits"))
        new_port = int(port_s)
        if new_port == ex.vpn_port:
            flash("Порт не изменился")
            return redirect(url_for("exits"))
        # проверка коллизии: конфиг (кроме портов самого этого выхода) → мост
        from cascade.config import used_ports
        if new_port in (used_ports(c) - {ex.relay_port, ex.vpn_port}):
            flash(f"Порт {new_port} уже занят в конфиге", "error")
            return redirect(url_for("exits"))
        if relay.port_listening(new_port):
            flash(f"Порт {new_port} уже слушается на мосту", "error")
            return redirect(url_for("exits"))
        try:
            conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
            from cascade.mtproto import exit_port_listening
            if exit_port_listening(conn, new_port):
                flash(f"Порт {new_port} уже занят на выходе", "error")
                return redirect(url_for("exits"))
            relay.remove_rule(relay.RelayRule("tcp", ex.relay_port, ex.ip, ex.vpn_port), quiet=True)
            ex.relay_port = new_port
            ex.vpn_port = new_port
            relay.apply_rule(relay.RelayRule("tcp", new_port, ex.ip, new_port))
            from cascade.vpn import _rebuild_xray
            _rebuild_xray(conn, ex, c.clients)
            save_config(c, config_path)
            flash(f"Порт {ex.location} изменён на {new_port}")
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("exits"))

    @app.post("/boss/exits/<eid>/ip")
    @login_required
    def exits_ip(eid):
        if not _check_csrf():
            return redirect(url_for("exits"))
        c = cfg()
        ex = next((e for e in c.exit_servers if e.id == eid), None)
        if not ex:
            flash("Выход не найден", "error")
            return redirect(url_for("exits"))
        new_ip = request.form.get("ip", "").strip()
        if not relay.valid_ip(new_ip):
            flash("Некорректный IP", "error")
            return redirect(url_for("exits"))
        if new_ip == ex.ip:
            flash("IP не изменился")
            return redirect(url_for("exits"))
        old_ip = ex.ip
        try:
            _ensure_host_key(new_ip, ex.ssh_port)  # ключ нового сервера (нет TTY)
            conn = ServerConnection(new_ip, ex.ssh_user, port=ex.ssh_port)
            conn.check_ssh()
            # деплой Xray на новый IP, сохраняя reality-ключи → cascade-ссылки клиентов живут
            vpn.deploy_vpn(conn, ex, c.clients)
            # переключить DNAT моста на новый IP
            relay.remove_rule(relay.RelayRule("tcp", ex.relay_port, old_ip, ex.vpn_port), quiet=True)
            ex.ip = new_ip
            relay.apply_rule(relay.RelayRule("tcp", ex.relay_port, new_ip, ex.vpn_port))
            # mtg-порты, развёрнутые именно на ЭТОМ выходе — перенести на новый IP с теми же секретами
            mtg_ports = [p for p in c.mtproto_ports if mtproto_port_exit(c, p).id == ex.id]
            if mtg_ports:
                from cascade import mtproto as mtproto_mod
                for p in mtg_ports:
                    secret = c.mtproto_secrets.get(str(p), "")
                    if not secret:
                        continue
                    domain = mtproto_mod.domain_from_secret(secret)
                    mtproto_mod.deploy_mtproto(conn, p, domain=domain, secret=secret)
                    relay.remove_rule(relay.RelayRule("tcp", p, old_ip, p), quiet=True)
                    relay.apply_rule(relay.RelayRule("tcp", p, new_ip, p))
            save_config(c, config_path)
            flash(f"IP выхода {ex.location} изменён: {old_ip} → {new_ip}")
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("exits"))

    @app.post("/boss/exits/<eid>/sni")
    @login_required
    def exits_sni(eid):
        if not _check_csrf():
            return redirect(url_for("exits"))
        c = cfg()
        ex = next((e for e in c.exit_servers if e.id == eid), None)
        if not ex:
            flash("Выход не найден", "error")
            return redirect(url_for("exits"))
        new_sni = request.form.get("sni", "").strip()
        if not new_sni:
            flash("SNI не может быть пустым", "error")
            return redirect(url_for("exits"))
        try:
            conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
            vpn.change_sni(conn, ex, c, new_sni)
            save_config(c, config_path)
            flash(f"SNI выхода {ex.location} обновлён: {new_sni}")
        except Exception as e:
            flash(f"Ошибка SSH: {e}", "error")
        return redirect(url_for("exits"))

    @app.post("/boss/exits/<eid>/sni-legacy-clear")
    @login_required
    def exits_sni_legacy_clear(eid):
        if not _check_csrf():
            return redirect(url_for("exits"))
        c = cfg()
        ex = next((e for e in c.exit_servers if e.id == eid), None)
        if not ex:
            flash("Выход не найден", "error")
            return redirect(url_for("exits"))
        try:
            conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
            vpn.sni_legacy_clear(conn, ex, c)
            save_config(c, config_path)
            flash(f"Legacy SNI выхода {ex.location} очищены")
        except Exception as e:
            flash(f"Ошибка SSH: {e}", "error")
        return redirect(url_for("exits"))

    @app.get("/boss/clients/<cid>/profile.json")
    @login_required
    def client_profile_download(cid):
        c = cfg()
        client = next((cl for cl in c.clients if cl.id == cid), None)
        eid = request.args.get("exit", "").strip()
        ex = next((e for e in c.exit_servers if e.id == eid), None) or primary_exit(c)
        direct = request.args.get("direct", "") in ("1", "true", "on")
        if not client or not ex:
            from flask import abort
            abort(404)
        relay_ip = _relay_ip()
        from cascade.xray_config import client_profile_json
        data = client_profile_json(client.uuid, ex, relay_ip, direct=direct,
                                   remarks=f"{ex.location}-{client.name}" + (" direct" if direct else ""),
                                   fingerprint=c.fingerprint)
        from flask import Response
        suffix = "-direct" if direct else ""
        return Response(
            data,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={client.name}-{ex.location}{suffix}.json"},
        )

    @app.post("/boss/exits/<eid>/restart-xray")
    @login_required
    def exits_restart_xray(eid):
        if not _check_csrf():
            return redirect(url_for("exits"))
        c = cfg()
        ex = next((e for e in c.exit_servers if e.id == eid), None)
        if not ex:
            flash("Выход не найден", "error")
            return redirect(url_for("exits"))
        try:
            conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
            r = conn.run("systemctl restart xray && echo OK", timeout=20)
            if "OK" in (r.stdout or ""):
                flash(f"Xray на {ex.location} перезапущен")
            else:
                flash(f"Xray {ex.location}: {(r.stderr or r.stdout or 'нет ответа').strip()}", "error")
        except Exception as e:
            flash(f"SSH-ошибка ({ex.location}): {e}", "error")
        return redirect(url_for("exits"))

    @app.post("/boss/exits/<eid>/check")
    @login_required
    def exits_check(eid):
        if not _check_csrf():
            return redirect(url_for("exits"))
        c = cfg()
        ex = next((e for e in c.exit_servers if e.id == eid), None)
        if not ex:
            flash("Выход не найден", "error")
            return redirect(url_for("exits"))
        from cascade.ssh import tcp_connect
        msgs = []
        try:
            _ensure_host_key(ex.ip, ex.ssh_port)  # без TTY: добавить host-key если нет (иначе check_ssh падает)
            conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
            conn.check_ssh()
            msgs.append(f"SSH:{ex.ssh_port} ✓")
        except Exception as e:
            msgs.append(f"SSH:{ex.ssh_port} ✗ ({e})")
        ok = tcp_connect(ex.ip, ex.vpn_port, timeout=5)
        msgs.append(f"TCP:{ex.vpn_port} {'✓' if ok else '✗'}")
        flash(f"{ex.location} ({ex.ip}) — " + " | ".join(msgs))
        return redirect(url_for("exits"))

    @app.post("/boss/exits/<eid>/primary")
    @login_required
    def exits_primary(eid):
        if not _check_csrf():
            return redirect(url_for("exits"))
        c = cfg()
        ex = next((e for e in c.exit_servers if e.id == eid), None)
        if not ex:
            flash("Выход не найден", "error")
            return redirect(url_for("exits"))
        c.primary_exit_id = eid
        save_config(c, config_path)
        flash(f"Основной выход (подписка): {ex.location}. Клиенты подтянут за ≤3ч.")
        return redirect(url_for("exits"))

    @app.post("/boss/server/restart-panel")
    @login_required
    def server_restart_panel():
        if not _check_csrf():
            return redirect(url_for("settings"))
        try:
            # откладываем на 5 сек чтобы HTTP-ответ успел уйти
            subprocess.Popen(
                ["systemd-run", "--on-active=5", "systemctl", "restart", "cascade-panel"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            flash("Панель перезапускается через ~5 сек. Обновите страницу.")
        except Exception as e:
            flash(f"Ошибка: {e}", "error")
        return redirect(url_for("settings"))

    @app.get("/boss/config/download")
    @login_required
    def config_download():
        """Скачать текущий config.json — off-server копия для аварийного восстановления."""
        if not Path(config_path).is_file():
            flash("config.json не найден", "error")
            return redirect(url_for("settings"))
        return send_file(config_path, as_attachment=True,
                         download_name="cascade-config-backup.json",
                         mimetype="application/json")

    @app.post("/boss/config/backup")
    @login_required
    def config_backup():
        """Локальный бэкап конфига на мосту сейчас + включить ежесуточный cron."""
        if not _check_csrf():
            return redirect(url_for("settings"))
        from cascade import backup as backup_mod
        try:
            dest = backup_mod.backup_config(config_path)
            backup_mod.install_backup_cron(str(config_path))
            flash(f"Бэкап создан: {dest.name}. Авто-бэкап (ежесуточно) включён.")
        except Exception as e:
            flash(f"Ошибка бэкапа: {e}", "error")
        return redirect(url_for("settings"))

    @app.get("/boss/diag")
    @login_required
    def diag():
        sections = []

        # локальные команды на мосту
        bridge_lines: list[str] = []
        local_checks = [
            ("Панель (статус)", ["systemctl", "status", "cascade-panel", "--no-pager", "-n", "20"]),
            ("NAT-правила (relay)", ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"]),
            ("Занятые порты", ["ss", "-tlnp"]),
            ("Сетевые параметры", [
                "sysctl",
                "net.ipv4.ip_forward",
                "net.core.default_qdisc",
                "net.ipv4.tcp_congestion_control",
            ]),
        ]
        for title, cmd in local_checks:
            bridge_lines.append(f"=== {title} ===")
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                bridge_lines.extend((r.stdout or r.stderr or "(нет вывода)").splitlines())
            except Exception as e:
                bridge_lines.append(f"Ошибка: {e}")
            bridge_lines.append("")
        bridge_lines.append("=== Публичный IP (мост) ===")
        try:
            r = subprocess.run(["curl", "-s", "--max-time", "5", "ifconfig.me"],
                               capture_output=True, text=True, timeout=8)
            bridge_lines.append(r.stdout.strip() or "(нет ответа)")
        except Exception as e:
            bridge_lines.append(f"Ошибка: {e}")
        sections.append({"title": "Мост (локально)", "lines": bridge_lines})

        # выходы по SSH
        c = cfg()
        if c:
            for ex in c.exit_servers:
                try:
                    conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
                    cmd = (
                        "echo '=== Xray (статус) ===' && "
                        "systemctl status xray --no-pager -n 20; "
                        "echo && echo '=== MTProto (статус) ===' && "
                        "systemctl status 'cascade-mtg@*' --no-pager -n 10 2>/dev/null || echo нет; "
                        "echo && echo '=== Занятые порты ===' && ss -tlnp; "
                        "echo && echo '=== Сетевые параметры ===' && "
                        "sysctl net.ipv4.ip_forward net.core.default_qdisc "
                        "net.ipv4.tcp_congestion_control; "
                        "echo && echo '=== Публичный IP ===' && "
                        "curl -s --max-time 5 ifconfig.me"
                    )
                    r = conn.run(cmd, timeout=35)
                    lines = (r.stdout or r.stderr or "(нет вывода)").splitlines()
                except Exception as e:
                    lines = [f"SSH-ошибка: {e}"]
                sections.append({"title": f"Выход {ex.location} ({ex.ip})", "lines": lines})

        # Глубокая проверка: conntrack-таблица + реальный TLS-хендшейк до выходов
        # (TCP-up не ловит «слушает, но ТСПУ душит» — это ловит).
        from cascade.monitor import conntrack_usage, tls_handshake_ok
        deep_lines = ["=== Conntrack (использование таблицы) ==="]
        cnt, mx, pct = conntrack_usage()
        if cnt is None:
            deep_lines.append("недоступно (/proc/sys/net/netfilter/nf_conntrack_*)")
        else:
            warn = "  ⚠️ близко к лимиту" if pct >= 80 else ""
            deep_lines.append(f"{cnt}/{mx} ({pct}%){warn}")
        deep_lines += ["", "=== TLS-хендшейк до выходов (глубже TCP-up) ==="]
        for ex in (c.exit_servers if c else []):
            ok = tls_handshake_ok(ex.ip, ex.vpn_port, ex.vpn_sni)
            deep_lines.append(
                f"{'✅' if ok else '❌'} {ex.location} {ex.ip}:{ex.vpn_port} (SNI {ex.vpn_sni})"
            )
        sections.append({"title": "Глубокая проверка (conntrack + TLS)", "lines": deep_lines})

        return render_template("diag.html", sections=sections,
                               exits=c.exit_servers if c else [])

    @app.post("/boss/diag/test/<name>")
    @login_required
    def diag_test(name):
        if not _check_csrf():
            return redirect(url_for("diag"))
        c = cfg()
        if not c or not c.exit_servers:
            flash("Нет выходов для теста", "error")
            return redirect(url_for("diag"))
        names = ["speed", "ss", "ping", "exit_speed"] if name == "all" else [name]
        if any(n not in _DIAG_TESTS for n in names):
            flash("Неизвестный тест", "error")
            return redirect(url_for("diag"))
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sections = []
        eid = request.form.get("eid", "").strip()
        targets = [e for e in c.exit_servers if e.id == eid] or c.exit_servers
        for n in names:
            title, scope = _DIAG_TESTS[n]
            tmo = 120 if n == "speed" else 45   # iperf3 дольше (установка+обе стороны)
            for ex in targets:
                cmd = _diag_cmd(n, ex)
                try:
                    if scope == "bridge":
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=tmo)
                    elif scope == "bridge_shell":
                        r = subprocess.run(cmd, shell=True, executable="/bin/bash",
                                           capture_output=True, text=True, timeout=tmo)
                    else:
                        conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
                        r = conn.run(cmd, timeout=tmo)
                    lines = (r.stdout or r.stderr or "(нет вывода)").splitlines()
                except FileNotFoundError:
                    lines = [f"Утилита не установлена. Поставь: apt install {_DIAG_PKG.get(n, n)}"]
                except Exception as e:
                    lines = [f"Ошибка: {e}"]
                sections.append({"title": f"{title} · {ex.location} ({ex.ip}) · {ts}",
                                 "lines": lines})
        label = "Полная диагностика" if name == "all" else _DIAG_TESTS[name][0]
        return render_template("diag.html", sections=sections, test_name=label,
                               exits=c.exit_servers)

    @app.route("/boss/sni-check", methods=["GET", "POST"])
    @login_required
    def sni_check():
        """Проверка SNI-кандидата на условия Reality (TLS1.3+X25519+h2, без редиректа).
        Запуск с каждого выхода по SSH. Только проверка — смену SNI делает раздел «Выходы»."""
        results = None
        domain = ""
        if request.method == "POST":
            if not _check_csrf():
                return redirect(url_for("sni_check"))
            domain = (request.form.get("domain") or "").strip()
            if not sni.valid_domain(domain):
                flash("Некорректный домен", "error")
                return redirect(url_for("sni_check"))
            c = cfg()
            if not c or not c.exit_servers:
                flash("Нет выходов для проверки", "error")
                return redirect(url_for("sni_check"))
            cmd = sni.build_check_cmd(domain)
            results = []
            for ex in c.exit_servers:
                row = {"exit": f"{ex.location} ({ex.ip})"}
                try:
                    conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
                    r = conn.run(cmd, timeout=25)
                    row.update(sni.parse_check(r.stdout or "", domain))
                except Exception as e:
                    row["error"] = str(e)
                results.append(row)
        _c = cfg()
        return render_template("sni_check.html", candidates=sni.CANDIDATES,
                               results=results, domain=domain, scan_domains=None, scan_log=None,
                               exits=_c.exit_servers if _c else [])

    @app.post("/boss/sni-scan")
    @login_required
    def sni_scan():
        """Сканировать подсеть выходного сервера через RealiTLScanner.
        Находит соседей по провайдеру (ASN) с TLS1.3+X25519+h2 — реальные SNI-кандидаты."""
        if not _check_csrf():
            return redirect(url_for("sni_check"))
        c = cfg()
        if not c or not c.exit_servers:
            flash("Нет выходов для сканирования", "error")
            return redirect(url_for("sni_check"))
        eid = request.form.get("eid", "").strip()
        ex = next((e for e in c.exit_servers if e.id == eid), None) or c.exit_servers[0]
        cmd = sni.build_scan_cmd(ex.ip)
        scan_domains = []
        scan_log = ""
        try:
            conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
            r = conn.run(cmd, timeout=90)
            scan_log = (r.stderr or "").strip() or (r.stdout or "").strip()
            scan_domains = sni.parse_scan_csv(r.stdout or "")
        except Exception as e:
            scan_log = str(e)
        return render_template("sni_check.html", candidates=sni.CANDIDATES,
                               results=None, domain="", scan_domains=scan_domains,
                               scan_log=scan_log, exits=c.exit_servers)

    @app.get("/boss/logs")
    @login_required
    def logs():
        c = cfg()
        sections = []

        # Локальные логи панели (запускается прямо на мосту)
        try:
            r = subprocess.run(
                ["journalctl", "-u", "cascade-panel", "--since", "24 hours ago",
                 "--no-pager", "-n", "100", "--output=short"],
                capture_output=True, text=True, timeout=10,
            )
            lines = (r.stdout or r.stderr or "нет записей").strip().splitlines()
        except Exception as e:
            lines = [f"Ошибка: {e}"]
        sections.append({"title": "Панель (мост)", "lines": lines})

        # Логи Xray + MTProto на каждом выходе по SSH
        if c:
            for ex in c.exit_servers:
                try:
                    conn = ServerConnection(ex.ip, ex.ssh_user, port=ex.ssh_port)
                    cmd = (
                        "echo '--- Xray ---' && "
                        "journalctl -u xray --since '24 hours ago' --no-pager -n 100 --output=short; "
                        "echo '--- MTProto ---' && "
                        "journalctl -u 'cascade-mtg@*' --since '24 hours ago' --no-pager -n 50 --output=short"
                    )
                    r = conn.run(cmd, timeout=20)
                    lines = (r.stdout or r.stderr or "нет записей").strip().splitlines()
                except Exception as e:
                    lines = [f"SSH-ошибка: {e}"]
                sections.append({"title": f"{ex.location} ({ex.ip})", "lines": lines})

        return render_template("logs.html", sections=sections)

    @app.route("/boss/settings", methods=["GET", "POST"])
    @login_required
    def settings():
        c = cfg()
        if request.method == "POST" and _check_csrf():
            c.domain = request.form.get("domain", "").strip()
            c.telegram_bot_token = request.form.get("telegram_bot_token", "").strip()
            c.telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
            pw = request.form.get("password", "")
            if pw:
                c.panel.password_hash = hash_password(pw)
                c.panel.enabled = True
            v = request.form.get("monitor_interval_min", "")
            if v and v.isdigit() and int(v) > 0:
                c.monitor_interval_min = int(v)
                line = f"*/{c.monitor_interval_min} * * * * cascade --monitor"
                subprocess.run(
                    ["bash", "-c",
                     f"(crontab -l 2>/dev/null | grep -v 'cascade --monitor'; echo '{line}') | crontab -"],
                    check=False,
                )
            c.auto_restart = request.form.get("auto_restart") == "on"
            from cascade.xray_config import FINGERPRINTS
            fp = request.form.get("fingerprint", "")
            if fp in FINGERPRINTS:
                c.fingerprint = fp
            save_config(c, config_path)
            flash("Настройки сохранены")
            return redirect(url_for("settings"))
        from cascade.xray_config import FINGERPRINTS
        return render_template("settings.html", cfg=c, fingerprints=FINGERPRINTS)

    # ── Подписка Happ ──────────────────────────────────────────────────────────

    @app.get("/sub/<token>")
    def sub_page(token):
        """Публичный эндпоинт подписки: raw JSON (первый выход) для Happ.
        Формат подтверждён рабочим 2026-06-05. JSON содержит полный routing (split-tunnel).
        TODO: multi-server → протестировать base64 URL-список на реальном Happ перед переходом.
        Невалидный токен → decoy."""
        c = cfg()
        client = share_mod.find_by_sub_token(c, token) if c else None
        eid = request.args.get("exit", "").strip()
        ex = None
        if c:
            ex = next((e for e in c.exit_servers if e.id == eid), None) or primary_exit(c)
        if not client or not ex:
            return render_template("decoy.html")
        relay_ip = _relay_ip()
        data = client_profile_json(client.uuid, ex, relay_ip,
                                   remarks=f"{ex.location}-{client.name}",
                                   fingerprint=c.fingerprint)
        from flask import Response
        return Response(
            data,
            mimetype="application/json",
            headers={
                "profile-title": client.name,
                "profile-update-interval": "3",
            },
        )

    @app.post("/boss/clients/<cid>/sub-token")
    @login_required
    def clients_sub_token(cid):
        """Сгенерировать/сбросить постоянный sub-токен клиента для подписки Happ."""
        if not _check_csrf():
            return redirect(url_for("clients"))
        c = cfg()
        client = next((cl for cl in c.clients if cl.id == cid), None)
        if client:
            client.sub_token = share_mod.gen_sub_token()
            save_config(c, config_path)
            flash(f"Подписка для {client.name} создана")
        return redirect(url_for("clients"))

    @app.get("/qr/<token>/<eid>.png")
    def qr_png(token, eid):
        """PNG QR-код: /qr/<sub_token>/<exit_id>.png?type=sub|bootstrap"""
        import tempfile, os
        from flask import Response
        c = cfg()
        if not c:
            return "", 404
        client = share_mod.find_by_sub_token(c, token) if c else None
        ex = next((e for e in c.exit_servers if e.id == eid), None)
        if not client or not ex:
            return "", 404
        qr_type = request.args.get("type", "sub")
        if qr_type == "bootstrap":
            relay_ip = _relay_ip()
            if not relay_ip:
                return "", 503
            vless_url = client_profile_url(client.uuid, ex, relay_ip, client.name,
                                           direct=False, fingerprint=c.fingerprint)
            sub_url = f"https://{c.domain}/sub/{token}?exit={eid}"
            data = f"{vless_url}\n{sub_url}"
        else:
            data = f"https://{c.domain}/sub/{token}?exit={eid}"
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        try:
            tmp.write(data)
            tmp.close()
            r = subprocess.run(["qrencode", "-t", "PNG", "-o", "-", "-m", "2",
                                "-l", "L", "-s", "8", "-r", tmp.name],
                               capture_output=True, timeout=5)
            if r.returncode != 0:
                return "", 500
            return Response(r.stdout, mimetype="image/png",
                            headers={"Cache-Control": "no-cache"})
        finally:
            os.unlink(tmp.name)

    return app
