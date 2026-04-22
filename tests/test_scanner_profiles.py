from pathlib import Path

from guardian_av.config import load_config
from guardian_av.scanner import Scanner


def test_quick_profile_limits_extensions(tmp_path: Path):
    (tmp_path / "safe.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "run.ps1").write_text("powershell -enc abc", encoding="utf-8")

    config = load_config(None)
    config["report_dir"] = str(tmp_path / "reports")
    config["quarantine_dir"] = str(tmp_path / "quarantine")
    db = tmp_path / "sig.json"
    db.write_text('{"sha256": []}', encoding="utf-8")

    scanner = Scanner(tmp_path, config, db)
    files = list(scanner.iter_files(include_extensions=[".ps1"]))
    assert len(files) == 1
    assert files[0].suffix == ".ps1"
