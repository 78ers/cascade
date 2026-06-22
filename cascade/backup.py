"""Бэкап конфига CASCADE.

`/etc/cascade/config.json` — единственный источник правды (reality-ключи, UUID
клиентов, секреты). Терялся при переустановке → восстановление с нуля. Здесь:
- `backup_config` — локальная копия на мосту с ротацией (защита от порчи/правки).
- `install_backup_cron` — ежесуточный авто-бэкап через cron.d (без CLI-зависимостей).
Off-server копию (на случай потери моста) даёт скачивание из панели — `/boss/config/download`.
"""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

BACKUP_DIR = Path("/etc/cascade/backups")
CRON_PATH = Path("/etc/cron.d/cascade-config-backup")
KEEP = 7


def backup_config(config_path, backup_dir=BACKUP_DIR, keep: int = KEEP):
    """Скопировать config.json → backup_dir/config.<UTC>.json, оставить keep свежих.
    Вернуть Path созданного бэкапа."""
    config_path, backup_dir = Path(config_path), Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = backup_dir / f"config.{ts}.json"
    shutil.copy2(config_path, dest)
    dest.chmod(0o600)
    _prune(backup_dir, keep)
    return dest


def _prune(backup_dir, keep: int) -> None:
    """Оставить keep самых свежих бэкапов (имена сортируемы по таймстампу)."""
    if keep <= 0:
        return
    backups = sorted(Path(backup_dir).glob("config.*.json"))
    for old in backups[:-keep]:
        old.unlink(missing_ok=True)


def latest_backup(backup_dir=BACKUP_DIR):
    """Самый свежий бэкап (Path) или None."""
    backups = sorted(Path(backup_dir).glob("config.*.json"))
    return backups[-1] if backups else None


def cron_line(config_path="/etc/cascade/config.json",
              backup_dir=BACKUP_DIR, keep: int = KEEP) -> str:
    """Строка для /etc/cron.d/cascade-config-backup — бэкап ежесуточно в 04:00.
    Инлайн-команда (без CLI cascade): cp + ротация. `%` в cron экранируется как `\\%`."""
    bdir = str(backup_dir)
    return (
        f"0 4 * * * root mkdir -p {bdir} && "
        f"cp {config_path} {bdir}/config.$(date -u +\\%Y\\%m\\%d-\\%H\\%M\\%S).json && "
        f"ls -1t {bdir}/config.*.json | tail -n +{keep + 1} | xargs -r rm -f\n"
    )


def install_backup_cron(config_path="/etc/cascade/config.json",
                        backup_dir=BACKUP_DIR, keep: int = KEEP) -> None:
    """Записать cron.d-файл ежесуточного бэкапа (idempotent — перезапись)."""
    CRON_PATH.write_text(cron_line(config_path, backup_dir, keep), encoding="utf-8")
    CRON_PATH.chmod(0o644)


def cron_installed() -> bool:
    return CRON_PATH.is_file()
