"""Цветной вывод и тема questionary (лайм на чёрном)."""
from __future__ import annotations

import shutil
import subprocess
import sys

LIME = "\033[0;32m"   # стандартный зелёный — виден на любом фоне
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
DIM = "\033[2m"
BOLD = "\033[1m"
NC = "\033[0m"


def info(msg: str) -> None:
    print(f"{CYAN}[*]{NC} {msg}")


def ok(msg: str) -> None:
    print(f"{GREEN}[OK]{NC} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[!]{NC} {msg}")


def err(msg: str) -> None:
    print(f"{RED}[ERROR]{NC} {msg}", file=sys.stderr)


class _ErrConsole:
    """Минимальный shim под meridian ssh.py (err_console.print с rich-разметкой)."""

    _TAGS = {
        "[warn]": YELLOW, "[/warn]": NC, "[error]": RED, "[/error]": NC,
        "[info]": CYAN, "[/info]": NC, "[dim]": DIM, "[/dim]": NC,
        "[bold]": BOLD, "[/bold]": NC,
    }

    def print(self, msg: str = "", end: str = "\n") -> None:
        for tag, code in self._TAGS.items():
            msg = msg.replace(tag, code)
        print(msg, end=end, file=sys.stderr)


err_console = _ErrConsole()

_qr_warned = False


def qr(data: str) -> None:
    """Печать QR в терминал через системный qrencode. Тихо деградирует."""
    global _qr_warned
    if shutil.which("qrencode") is None:
        if not _qr_warned:
            warn("qrencode не установлен — QR пропущен (apt install qrencode)")
            _qr_warned = True
        return
    subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "1", data], check=False)


def questionary_style():
    """Лайм-тема для questionary. Импорт внутри — questionary опционален в тестах."""
    from questionary import Style

    return Style([
        ("qmark", "fg:ansigreen bold"),
        ("question", "bold"),
        ("pointer", "fg:ansigreen bold"),
        ("highlighted", "fg:ansigreen bold"),
        ("selected", "fg:ansigreen bold"),
        ("answer", "fg:ansigreen bold"),
    ])
