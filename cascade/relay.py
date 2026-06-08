"""iptables DNAT-relay на РФ-сервере. Логика из compmaniya (VPN/install.sh)."""
from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass
from pathlib import Path


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


@dataclass
class RelayRule:
    proto: str          # tcp|udp
    in_port: int
    target_ip: str
    out_port: int

    def __post_init__(self):
        if self.proto not in ("tcp", "udp"):
            raise ValueError(f"proto должен быть tcp|udp, не {self.proto!r}")
        if not valid_ip(self.target_ip):
            raise ValueError(f"Некорректный IP: {self.target_ip!r}")
        for p in (self.in_port, self.out_port):
            if not (1 <= p <= 65535):
                raise ValueError(f"Порт вне диапазона: {p}")


def dnat_rules(rule: RelayRule, iface: str) -> "list[list[str]]":
    """Список iptables-команд (без бинаря iptables) для одного правила.

    MASQUERADE сюда НЕ входит — это общая для всех правил инфраструктура,
    добавляется отдельно идемпотентно (см. _ensure_masquerade). Иначе несколько
    правил плодят дубли, а удаление одного снимает общий MASQUERADE у остальных.
    """
    t, ip, ip_o = rule.proto, rule.target_ip, rule.out_port
    dest = f"{ip}:{ip_o}"
    return [
        ["-A", "INPUT", "-p", t, "--dport", str(rule.in_port), "-j", "ACCEPT"],
        ["-t", "nat", "-A", "PREROUTING", "-p", t, "--dport", str(rule.in_port),
         "-j", "DNAT", "--to-destination", dest],
        ["-A", "FORWARD", "-p", t, "-d", ip, "--dport", str(ip_o),
         "-m", "state", "--state", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["-A", "FORWARD", "-p", t, "-s", ip, "--sport", str(ip_o),
         "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]


def _ensure_ip_forward() -> None:
    """Включить IPv4 forwarding (idempotent) + персист через sysctl.d."""
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    sysctl_file = "/etc/sysctl.d/99-cascade.conf"
    try:
        with open(sysctl_file) as f:
            existing = f.read()
    except FileNotFoundError:
        existing = ""
    if "net.ipv4.ip_forward" not in existing:
        with open(sysctl_file, "a") as f:
            f.write("net.ipv4.ip_forward=1\n")


def _ensure_masquerade(iface: str) -> None:
    """Добавить MASQUERADE на iface один раз (идемпотентно через -C проверку)."""
    check = subprocess.run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
        capture_output=True,
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
            check=False,
        )


# net-тюнинг моста: BBR + fq + mtu_probing + буферы + защита от RST-инъекций ТСПУ.
_NET_TUNING = (
    "net.core.default_qdisc=fq\n"
    "net.ipv4.tcp_congestion_control=bbr\n"
    "net.ipv4.tcp_mtu_probing=1\n"
    "net.core.rmem_max=16777216\n"
    "net.core.wmem_max=16777216\n"
    "net.ipv4.tcp_rmem=4096 87380 16777216\n"
    "net.ipv4.tcp_wmem=4096 65536 16777216\n"
    # ТСПУ инжектирует RST с неверным ACK — conntrack без этого помечает их INVALID,
    # nfqws не перехватывает, соединение рвётся. Liberal mode игнорирует «грязные» RST.
    "net.netfilter.nf_conntrack_tcp_be_liberal=1\n"
)


def _ensure_net_tuning() -> None:
    """BBR+fq+mtu_probing+буферы на мосту (idempotent). Модуль tcp_bbr грузим до sysctl."""
    subprocess.run(["modprobe", "tcp_bbr"], check=False)
    with open("/etc/modules-load.d/cascade-bbr.conf", "w") as f:
        f.write("tcp_bbr\n")
    net_file = "/etc/sysctl.d/99-cascade-net.conf"
    try:
        if open(net_file).read() == _NET_TUNING:
            return  # уже применено — sysctl не дёргаем
    except FileNotFoundError:
        pass
    with open(net_file, "w") as f:
        f.write(_NET_TUNING)
    subprocess.run(["sysctl", "--system"], check=False, capture_output=True)


def _ensure_mss_clamp() -> None:
    """MSS clamp на FORWARD (страховка от MTU-блэкхола). 1340 = предсказуемо для TCP-в-TCP."""
    rule = ["FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", "--set-mss", "1340"]
    check = subprocess.run(["iptables", "-t", "mangle", "-C", *rule], capture_output=True)
    if check.returncode != 0:
        subprocess.run(["iptables", "-t", "mangle", "-A", *rule], check=False)


# ---------------------------------------------------------------------------
# zapret/nfqws — DPI-десинхронизация на мосту (FORWARD mangle, только хендшейк)
# ---------------------------------------------------------------------------

_NFQWS_NUM = 200
_ZAPRET_SERVICE = "cascade-zapret"
_ZAPRET_UNIT = f"/etc/systemd/system/{_ZAPRET_SERVICE}.service"
# Type=simple (без --daemon): systemd управляет процессом напрямую.
# Restart=always + queue-bypass: при падении nfqws трафик идёт без десинхронизации
# (клиенты не теряют связь), systemd поднимает за 3 сек.
_ZAPRET_UNIT_CONTENT = (
    "[Unit]\n"
    "Description=Cascade DPI desync (zapret nfqws)\n"
    "After=network.target\n"
    "\n"
    "[Service]\n"
    "Type=simple\n"
    f"ExecStart=/usr/sbin/nfqws --qnum={_NFQWS_NUM}"
    " --dpi-desync-any-protocol"
    " --dpi-desync=fake,multisplit --dpi-desync-ttl=5\n"
    "Restart=always\n"
    "RestartSec=3\n"
    "\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n"
)


def _install_nfqws() -> None:
    """Установить nfqws (из apt или собрать из bol-van/zapret).

    apt-get install завершается быстро (нет пакета → fail). git clone + make медленные
    (~30-60 сек) — capture_output=True не используется чтобы не казалось что завис.
    libcap-dev обязателен для сборки sec.c (sys/capability.h).
    """
    r = subprocess.run(["apt-get", "install", "-y", "nfqws"], capture_output=True)
    if r.returncode == 0:
        return
    # nfqws нет в стандартных репо Ubuntu — собираем из исходников
    subprocess.run(
        ["apt-get", "install", "-y",
         "build-essential", "git",
         "libnetfilter-queue-dev", "libnfnetlink-dev", "libmnl-dev", "libcap-dev"],
        check=False,
    )
    subprocess.run(
        ["git", "clone", "--depth=1",
         "https://github.com/bol-van/zapret", "/opt/zapret"],
        check=False,
    )
    subprocess.run(["make", "-C", "/opt/zapret/nfq"], check=False)
    subprocess.run(
        ["install", "-m755", "/opt/zapret/nfq/nfqws", "/usr/sbin/nfqws"],
        check=False,
    )


def _ensure_zapret_service() -> None:
    """Создать/обновить systemd-юнит nfqws (idempotent по содержимому)."""
    try:
        existing = Path(_ZAPRET_UNIT).read_text()
    except FileNotFoundError:
        existing = ""
    if existing != _ZAPRET_UNIT_CONTENT:
        Path(_ZAPRET_UNIT).write_text(_ZAPRET_UNIT_CONTENT)
        subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", "--now", _ZAPRET_SERVICE], check=False)


def _ensure_zapret_rule(target_ip: str, target_port: int) -> None:
    """Добавить NFQUEUE правило в mangle FORWARD (idempotent через -C).

    FORWARD (не POSTROUTING): для DNAT-транзита в iptables NFQUEUE в POSTROUTING
    не работает корректно — фейк-пакеты нfqws не выходят в сеть.
    connbytes 0:6: только первые 6 пакетов (TLS-хендшейк) — data-поток идёт мимо,
    CPU моста не нагружается.
    --queue-bypass: при падении nfqws ядро пропускает пакеты (ACCEPT), не дропает.
    mark: защита от зацикливания обработанных пакетов.
    """
    args = ["-p", "tcp", "-d", target_ip, "--dport", str(target_port),
            "-m", "connbytes", "--connbytes", "0:6",
            "--connbytes-dir", "original", "--connbytes-mode", "packets",
            "-m", "mark", "!", "--mark", "0x40000000/0x40000000",
            "-j", "NFQUEUE", "--queue-num", str(_NFQWS_NUM), "--queue-bypass"]
    check = subprocess.run(
        ["iptables", "-t", "mangle", "-C", "FORWARD", *args],
        capture_output=True,
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-t", "mangle", "-A", "FORWARD", *args],
            check=False,
        )


def _ensure_zapret(target_ip: str, target_port: int) -> None:
    """DPI-десинхронизация через nfqws на трафик мост→выход (idempotent)."""
    if subprocess.run(["which", "nfqws"], capture_output=True).returncode != 0:
        _install_nfqws()
    _ensure_zapret_service()
    _ensure_zapret_rule(target_ip, target_port)


# ---------------------------------------------------------------------------
# Применение (subprocess, локально на РФ-сервере) — проверка на сервере
# ---------------------------------------------------------------------------


def port_listening(port: int) -> bool:
    """Слушает ли кто-то :port на мосту (проверка коллизий перед DNAT/firewall)."""
    r = subprocess.run(["ss", "-Hltn", f"sport = :{port}"],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def detect_iface() -> str:
    """Дефолтный сетевой интерфейс (как `ip route get 8.8.8.8`)."""
    r = subprocess.run(["ip", "route", "get", "8.8.8.8"],
                       capture_output=True, text=True)
    toks = r.stdout.split()
    if "dev" in toks:
        return toks[toks.index("dev") + 1]
    return "eth0"


def apply_rule(rule: RelayRule) -> None:
    from cascade.console import ok

    iface = detect_iface()
    _ensure_ip_forward()
    _ensure_net_tuning()                              # BBR+fq+буферы+conntrack liberal
    _ensure_zapret(rule.target_ip, rule.out_port)     # DPI-десинхронизация нfqws
    remove_rule(rule, quiet=True)                     # снять старое с тем же in_port
    _ensure_masquerade(iface)                         # общий MASQUERADE на iface
    _ensure_mss_clamp()                               # MSS 1340 на FORWARD
    for args in dnat_rules(rule, iface):
        subprocess.run(["iptables", *args], check=True)
    subprocess.run(["netfilter-persistent", "save"], check=False)
    ok(f"Relay: {rule.proto} :{rule.in_port} → {rule.target_ip}:{rule.out_port}")


def remove_rule(rule: RelayRule, quiet: bool = False) -> None:
    from cascade.console import ok

    iface = detect_iface()
    for args in dnat_rules(rule, iface):
        del_args = ["-D" if a == "-A" else a for a in args]
        subprocess.run(["iptables", *del_args], capture_output=True, check=False)
    subprocess.run(["netfilter-persistent", "save"], check=False)
    if not quiet:
        ok(f"Relay-правило удалено: :{rule.in_port}")


def list_dnat() -> str:
    """Текущие PREROUTING DNAT-правила (для экрана статуса)."""
    r = subprocess.run(["iptables", "-t", "nat", "-S", "PREROUTING"],
                       capture_output=True, text=True)
    return "\n".join(l for l in r.stdout.splitlines() if "DNAT" in l)
