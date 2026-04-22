from pathlib import Path

from guardian_av.config import load_config
from guardian_av.scanner import Scanner


def test_engine_info_exposes_optional_capabilities(tmp_path: Path):
    config = load_config(None)
    config["report_dir"] = str(tmp_path / "reports")
    config["quarantine_dir"] = str(tmp_path / "quarantine")
    config["rules_dir"] = str(tmp_path / "rules")
    config["cache_path"] = str(tmp_path / "cache.json")
    (tmp_path / "rules").mkdir()
    db = tmp_path / "sig.json"
    db.write_text('{"sha256": []}', encoding="utf-8")

    scanner = Scanner(tmp_path, config, db)
    info = scanner.engine_info()

    assert info["cache_enabled"] is True
    assert "yara_available" in info
    assert "watchdog_available" in info
