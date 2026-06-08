"""Точка входа CASCADE VPN."""
from __future__ import annotations

import os
import sys


def _serve_panel() -> None:
    import logging

    from waitress import serve
    from cascade.config import load_config
    from cascade.panel.app import create_app

    cfg = load_config()
    if cfg is None:
        print("Панель: конфиг /etc/cascade/config.json недоступен "
              "(запустите от root после установки и настройки панели)")
        sys.exit(1)
    port = cfg.panel.port if cfg.panel else 8088
    # depth 1-6 при блокирующих SSH/QR-запросах безвреден на админ-панели — не шумим в лог
    logging.getLogger("waitress.queue").setLevel(logging.ERROR)
    # 8 потоков: запас под медленные запросы (SSH к выходу, subprocess qrencode/ss)
    serve(create_app(), host="127.0.0.1", port=port, threads=8)


def main() -> None:
    # режим cron-мониторинга: не требует root-меню
    if "--monitor" in sys.argv:
        from cascade.config import load_config
        from cascade.monitor import run_check

        cfg = load_config()
        if cfg:
            run_check(cfg)
        return

    # режим веб-панели (waitress на 127.0.0.1)
    if "--panel" in sys.argv:
        _serve_panel()
        return

    # root-проверка до импорта меню, чтобы дружелюбно падать
    if os.geteuid() != 0:
        print("Запустите от root: sudo cascade")
        sys.exit(1)
    from cascade.menu import main_menu

    main_menu()


if __name__ == "__main__":
    main()
