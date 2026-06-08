"""Конфиг CASCADE: один JSON в /etc/cascade/config.json."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

SERVER_CREDS_DIR = Path("/etc/cascade")
CONFIG_PATH = SERVER_CREDS_DIR / "config.json"


@dataclass
class ExitServer:
    id: str = ""
    location: str = ""          # отображаемое имя локации (было name)
    ip: str = ""
    ssh_user: str = "root"
    ssh_port: int = 22
    relay_port: int = 8444      # порт на РФ-мосту → DNAT на этот выход
    vpn_port: int = 8444        # порт Xray на самом выходе (для direct-профиля)
    vpn_sni: str = "www.google.com"
    vpn_sni_legacy: list = field(default_factory=list)  # старые SNI, пока клиенты обновляются
    vpn_sni_changed_at: str = ""  # ISO-дата последней смены SNI (для подсказки «когда безопасно очищать»)
    vpn_xhttp_enabled: bool = False
    vpn_xhttp_port: int = 8445
    vpn_xhttp_path: str = ""
    reality_private_key: str = ""
    reality_public_key: str = ""
    reality_short_id: str = ""


@dataclass
class Client:
    id: str
    name: str
    uuid: str
    enabled: bool = True
    created: str = ""   # ISO-дата, напр. "2026-05-29"
    sub_token: str = ""  # постоянный токен для подписки Happ (/sub/<token>)


@dataclass
class Panel:
    enabled: bool = False
    user: str = "admin"
    password_hash: str = ""
    port: int = 8088


@dataclass
class ShareToken:
    token: str = ""
    client_id: str = ""
    created: str = ""    # ISO datetime UTC
    ttl_hours: int = 24


@dataclass
class Config:
    exit_servers: list = field(default_factory=list)   # list[ExitServer]
    clients: list = field(default_factory=list)        # list[Client]
    vpn_name: str = "CASCADE VPN"
    fingerprint: str = "firefox"  # uTLS-отпечаток клиента (маскировка TLS); chrome режет РФ-DPI
    mtproto_ports: list = field(default_factory=lambda: [8443])
    monitor_interval_min: int = 5
    auto_restart: bool = True
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    mtproto_secrets: dict = field(default_factory=dict)  # {"порт": "секрет"} на первом выходе
    mtproto_labels: dict = field(default_factory=dict)   # {"порт": "имя юзера"} — чей это порт
    mtproto_port_exits: dict = field(default_factory=dict)  # {"порт": exit_id} — на каком выходе развёрнут mtg порта
    domain: str = ""
    primary_exit_id: str = ""   # id выхода, который отдаётся в подписке (дефолт — exit_servers[0])
    mtproto_exit_id: str = ""   # id выхода, хостящего mtg (дефолт — exit_servers[0])
    panel: "Panel" = field(default_factory=Panel)
    share_tokens: list = field(default_factory=list)   # list[ShareToken]
    # TELEMT на мосту (probe-resistance, domain:443 через nginx stream)
    bridge_mtproto_secrets: dict = field(default_factory=dict)  # {label: ee_secret}
    bridge_mtproto_domain: str = ""   # маска TLS (tls_domain в TELEMT TOML)


TELEMT_BRIDGE_PORT = 8448  # внутренний порт TELEMT; nginx :443 → :8448


def used_ports(cfg: "Config") -> set:
    """Все порты, уже занятые в конфиге (на мосту и/или выходе).
    Для проверки коллизий перед добавлением MTProto-порта или сменой порта выхода.
    Считаем relay_port (мост), vpn_port (выход), xhttp-порт (если включён), mtproto-порты
    и TELEMT_BRIDGE_PORT (если настроен bridge MTProto)."""
    ports = set()
    for ex in cfg.exit_servers:
        ports.add(ex.relay_port)
        ports.add(ex.vpn_port)
        if ex.vpn_xhttp_enabled:
            ports.add(ex.vpn_xhttp_port)
    ports.update(int(p) for p in cfg.mtproto_ports)
    if cfg.bridge_mtproto_secrets:
        ports.add(TELEMT_BRIDGE_PORT)
    return ports


def primary_exit(cfg: "Config"):
    """Выход для подписки /sub: primary_exit_id если задан и существует, иначе первый.
    Вернуть None если выходов нет."""
    if not cfg.exit_servers:
        return None
    if cfg.primary_exit_id:
        for ex in cfg.exit_servers:
            if ex.id == cfg.primary_exit_id:
                return ex
    return cfg.exit_servers[0]


def mtproto_exit(cfg: "Config"):
    """Выход, хостящий mtg: mtproto_exit_id если задан и существует, иначе первый.
    Вернуть None если выходов нет."""
    if not cfg.exit_servers:
        return None
    if cfg.mtproto_exit_id:
        for ex in cfg.exit_servers:
            if ex.id == cfg.mtproto_exit_id:
                return ex
    return cfg.exit_servers[0]


def mtproto_port_exit(cfg: "Config", port):
    """Выход, где развёрнут mtg конкретного порта. Из mtproto_port_exits;
    незамапленный (старый) порт → exit_servers[0] (где порты жили до per-port-карты).
    НЕ mtproto_exit — тот мог быть переключён, а старый порт остался на [0]."""
    if not cfg.exit_servers:
        return None
    eid = cfg.mtproto_port_exits.get(str(port))
    if eid:
        for ex in cfg.exit_servers:
            if ex.id == eid:
                return ex
    return cfg.exit_servers[0]


def _migrate(data: dict) -> dict:
    """Старый формат (один exit_server + vpn_clients dict + top-level ключи)
    → exit_servers[] + clients[]. Идемпотентно (новый формат не трогает)."""
    if "exit_servers" in data:
        return data  # уже новый формат
    es = data.pop("exit_server", {})
    # старый vpn_uuid → vpn_clients (доп. шаг прошлой миграции)
    if "vpn_uuid" in data and "vpn_clients" not in data:
        data["vpn_clients"] = {"default": data.pop("vpn_uuid")}
    vpn_clients = data.pop("vpn_clients", {})
    exit_one = {
        "id": "default",
        "location": es.get("name", ""),
        "ip": es.get("ip", ""),
        "ssh_user": es.get("ssh_user", "root"),
        "ssh_port": es.get("ssh_port", 22),
        "relay_port": data.get("vpn_port", 8444),
        "vpn_port": data.pop("vpn_port", 8444),
        "vpn_sni": data.pop("vpn_sni", "www.google.com"),
        "vpn_xhttp_enabled": data.pop("vpn_xhttp_enabled", False),
        "vpn_xhttp_port": data.pop("vpn_xhttp_port", 8445),
        "vpn_xhttp_path": data.pop("vpn_xhttp_path", ""),
        "reality_private_key": data.pop("vpn_private_key", ""),
        "reality_public_key": data.pop("vpn_public_key", ""),
        "reality_short_id": data.pop("vpn_short_id", ""),
    }
    data["exit_servers"] = [exit_one] if exit_one["ip"] else []
    data["clients"] = [
        {"id": name, "name": name, "uuid": uid, "enabled": True, "created": ""}
        for name, uid in vpn_clients.items()
    ]
    return data


def load_config(path: Path = CONFIG_PATH) -> "Config | None":
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    data = _migrate(data)   # см. Task 5
    es_fields = ExitServer.__dataclass_fields__
    cl_fields = Client.__dataclass_fields__
    exit_servers = [ExitServer(**{k: v for k, v in e.items() if k in es_fields})
                    for e in data.pop("exit_servers", [])]
    clients = [Client(**{k: v for k, v in c.items() if k in cl_fields})
               for c in data.pop("clients", [])]
    pn_fields = Panel.__dataclass_fields__
    panel = Panel(**{k: v for k, v in data.pop("panel", {}).items() if k in pn_fields})
    st_fields = ShareToken.__dataclass_fields__
    share_tokens = [ShareToken(**{k: v for k, v in s.items() if k in st_fields})
                    for s in data.pop("share_tokens", [])]
    known = Config.__dataclass_fields__
    return Config(exit_servers=exit_servers, clients=clients,
                  panel=panel, share_tokens=share_tokens,
                  **{k: v for k, v in data.items() if k in known})


def save_config(cfg: "Config", path: Path = CONFIG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(cfg), ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
