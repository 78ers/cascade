"""Проверка SNI-домена на пригодность как dest для VLESS+Reality.

Reality требует от dest: TLS 1.3 + X25519 в обмене ключами + ALPN h2, без редиректа
на другой домен (иначе ломается маскировка). Проверка запускается на сервере ВЫХОДА
по SSH — именно оттуда Xray контактирует dest (мост в РФ дал бы ложные отказы из-за ТСПУ).
"""
from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

# Пресеты-кандидаты (немецкие — гео-правдоподобны для выхода в Германии; TLS1.3+h2 проверены).
CANDIDATES = [
    "www.bmw.de",
    "www.siemens.com",
    "www.sap.com",
    "www.telekom.de",
    "www.spiegel.de",
    "www.zalando.de",
]

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")

# TLD и ключевые слова, раскрывающие нашу маскировку или бесполезные как dest
_BAD_TLD = {".ru", ".ua", ".by", ".kz"}
_BAD_KEYWORDS = {"vpn", "proxy", "cavevpn", "vk.com", ".vk", "yandex", "tinkoff",
                 "petrovich", "mail.ru", "ok.ru"}


def _good_sni_candidate(domain: str) -> bool:
    """Отсеять домены, которые плохи для Reality-маскировки с немецкого VPS."""
    d = domain.lower()
    if any(d.endswith(tld) for tld in _BAD_TLD):
        return False
    if any(kw in d for kw in _BAD_KEYWORDS):
        return False
    return True

# RealiTLScanner (XTLS) — ищет соседей по подсети провайдера с TLS1.3+X25519+h2.
# Запускается на выходном сервере (нужен его ASN, не мак/мост).
_SCANNER_BIN = "/usr/local/bin/realitls_scanner"
_SCANNER_URL = ("https://github.com/XTLS/RealiTLScanner/releases/latest"
                "/download/RealiTLScanner-linux-amd64")


def valid_domain(d: str) -> bool:
    """Только буквы/цифры/дефис/точка, есть TLD. Отсекает пробелы/`;`/инъекции/пустое."""
    return bool(_DOMAIN_RE.match(d or ""))


def build_check_cmd(domain: str) -> str:
    """Bash-команда для выхода: openssl (форсим TLS1.3+X25519+ALPN h2) + curl (код/редирект).
    Сырой вывод парсит parse_check. Домен обёрнут shlex.quote (без инъекций)."""
    d = shlex.quote(domain)
    return (
        f"d={d}; "
        'echo "===OPENSSL==="; '
        'printf "" | timeout 8 openssl s_client -connect "$d:443" '
        '-servername "$d" -tls1_3 -groups X25519 -alpn h2 2>/dev/null; '
        'echo "===CURL==="; '
        'curl -sI -m 8 --tlsv1.3 "https://$d/" -o /dev/null '
        '-w "HTTP=%{http_code} REDIR=%{redirect_url}" 2>/dev/null '
        '|| echo "HTTP=000 REDIR="'
    )


def build_scan_cmd(ip: str, threads: int = 16, timeout_s: int = 3) -> str:
    """Команда для выхода: установить сканер если нет, найти соседей в подсети.
    Вывод — CSV (IP,ORIGIN,CERT_DOMAIN,...). threads=16, timeout=3 → ~45 сек на /24."""
    url = shlex.quote(_SCANNER_URL)
    safe_ip = shlex.quote(ip)
    fname = shlex.quote("/tmp/realitls_" + re.sub(r"[^0-9a-zA-Z]", "_", ip) + ".csv")
    # /24 CIDR — конечное сканирование; одиночный IP → infinite mode (никогда не завершается)
    cidr = shlex.quote(ip + "/24") if "/" not in ip else safe_ip
    install = (f"test -x {_SCANNER_BIN} || "
               f"(curl -fsSL {url} -o {_SCANNER_BIN} && chmod +x {_SCANNER_BIN})")
    scan = (f"{_SCANNER_BIN} -addr {cidr} "
            f"-thread {threads} -timeout {timeout_s} -out {fname} 2>/dev/null")
    return f"{install}; {scan}; cat {fname} 2>/dev/null"


def parse_scan_csv(output: str) -> list[str]:
    """Извлечь уникальные валидные домены из CSV-вывода build_scan_cmd.
    Формат v0.2.3: IP,ORIGIN,TLS,ALPN,CURVE,CERT_LENGTH,CERT_SIGNATURE,CERT_PUBLICKEY,CERT_DOMAIN,...
    Индекс CERT_DOMAIN читаем из заголовка (совместимо с любой версией сканера)."""
    seen: set[str] = set()
    result = []
    cert_idx = 2  # fallback на старый формат
    for line in output.splitlines():
        if not line.strip():
            continue
        if line.startswith("IP,"):
            cols = line.split(",")
            if "CERT_DOMAIN" in cols:
                cert_idx = cols.index("CERT_DOMAIN")
            continue
        parts = line.split(",")
        if len(parts) <= cert_idx:
            continue
        dom = parts[cert_idx].strip().lstrip("*.")
        if valid_domain(dom) and _good_sni_candidate(dom) and dom not in seen:
            seen.add(dom)
            result.append(dom)
    return result


def _norm_host(h: str) -> str:
    return h[4:] if h.startswith("www.") else h


def parse_check(output: str, domain: str = "") -> dict:
    """Разобрать вывод build_check_cmd. ok = TLS1.3 + X25519 + h2 + без редиректа.

    Форсим -groups X25519 -tls1_3: если хендшейк прошёл, в выводе есть и 'TLSv1.3',
    и 'X25519'; иначе оба отсутствуют (домен не годится как dest).
    Редирект на тот же хост (path-redirect, напр. bmw.de → bmw.de/de/) НЕ дисквалифицирует —
    Reality перехватывает на уровне TLS, путь не важен. Отклоняем только кросс-доменный."""
    tls13 = "TLSv1.3" in output
    x25519 = "X25519" in output
    h2 = "ALPN protocol: h2" in output
    m = re.search(r"HTTP=(\d+)", output)
    http_code = m.group(1) if m else "?"
    m = re.search(r"REDIR=(\S*)", output)
    redirect = m.group(1) if m else ""
    if redirect and domain:
        try:
            redir_host = urlparse(redirect).hostname or ""
            redirected = _norm_host(redir_host) != _norm_host(domain)
        except Exception:
            redirected = True
    else:
        redirected = bool(redirect) or http_code.startswith("3")
    ok = tls13 and x25519 and h2 and not redirected
    return {
        "tls13": tls13,
        "x25519": x25519,
        "h2": h2,
        "http_code": http_code,
        "redirect": redirect,
        "redirected": redirected,
        "ok": ok,
    }
