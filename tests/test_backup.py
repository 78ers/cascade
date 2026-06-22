from cascade import backup


def test_backup_creates_copy(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text('{"k": 1}', encoding="utf-8")
    bdir = tmp_path / "backups"
    dest = backup.backup_config(cfg, backup_dir=bdir)
    assert dest.exists()
    assert dest.read_text(encoding="utf-8") == '{"k": 1}'
    assert dest.name.startswith("config.") and dest.name.endswith(".json")


def test_prune_keeps_newest(tmp_path):
    bdir = tmp_path / "backups"
    bdir.mkdir()
    # 10 бэкапов с сортируемыми по времени именами
    for i in range(10):
        (bdir / f"config.2026010{i % 10}-00000{i % 10}.json").write_text("x")
    names = sorted(p.name for p in bdir.glob("config.*.json"))
    backup._prune(bdir, keep=7)
    left = sorted(p.name for p in bdir.glob("config.*.json"))
    assert len(left) == 7
    assert left == names[-7:]  # остались 7 самых свежих (по имени = по времени)


def test_latest_backup(tmp_path):
    bdir = tmp_path / "backups"
    bdir.mkdir()
    assert backup.latest_backup(bdir) is None
    (bdir / "config.20260101-000001.json").write_text("a")
    (bdir / "config.20260102-000001.json").write_text("b")
    assert backup.latest_backup(bdir).name == "config.20260102-000001.json"


def test_cron_line_content():
    line = backup.cron_line(config_path="/etc/cascade/config.json", keep=7)
    assert line.startswith("0 4 * * * root ")
    assert "cp /etc/cascade/config.json" in line
    assert "tail -n +8" in line          # keep=7 → удаляем с 8-го
    assert "\\%Y\\%m\\%d" in line          # % экранирован для cron
    assert line.endswith("\n")
