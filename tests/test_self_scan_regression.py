from pathlib import Path

from guardian_av.config import load_config
from guardian_av.scanner import Scanner


def test_self_scan_like_project_stays_clean(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "rules").mkdir()
    (tmp_path / "src" / "config.py").write_text('suspicious_strings = ["powershell -enc", "mshta"]', encoding="utf-8")
    (tmp_path / "config.json").write_text('{"trusted_relative_paths": ["src", "config.json", "rules"], "exclude_dirs": ["rules"]}', encoding="utf-8")
    (tmp_path / "rules" / "sample.yar").write_text('rule A { condition: false }', encoding="utf-8")
    db = tmp_path / "data" / "signature_db.json"
    db.write_text('{"sha256": []}', encoding="utf-8")

    config = load_config(str(tmp_path / "config.json"))
    config["report_dir"] = str(tmp_path / "reports")
    config["quarantine_dir"] = str(tmp_path / "quarantine")
    config["rules_dir"] = str(tmp_path / "rules")
    config["cache_path"] = str(tmp_path / "data" / "hash_cache.json")

    scanner = Scanner(tmp_path, config, db, enable_yara=False)
    payload = scanner.scan()

    assert payload["stats"]["suspicious"] == 0
    assert payload["stats"]["suspicious-high"] == 0
    assert payload["stats"]["malicious"] == 0
