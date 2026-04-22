from pathlib import Path

from guardian_av.heuristics import evaluate_file


BASE_CONFIG = {
    "suspicious_extensions": [".ps1"],
    "trusted_code_extensions": [".py", ".md", ".json", ".txt"],
    "suspicious_strings": ["powershell -enc", "frombase64string"],
    "dangerous_string_weights": {"powershell -enc": 20, "frombase64string": 15},
    "entropy_threshold": 7.2,
    "max_file_size_mb": 1,
    "min_string_matches_for_text_suspicion": 2,
}


def test_suspicious_extension_and_strings(tmp_path: Path):
    sample = tmp_path / "script.ps1"
    sample.write_text("powershell -enc AAAA frombase64string BBBB", encoding="utf-8")

    result = evaluate_file(sample, BASE_CONFIG)

    assert result.score >= 35
    assert "extension" in result.indicators
    assert "strings" in result.indicators


def test_trusted_python_file_is_downgraded(tmp_path: Path):
    sample = tmp_path / "config.py"
    sample.write_text("powershell -enc", encoding="utf-8")

    result = evaluate_file(sample, BASE_CONFIG, is_trusted_path=True)

    assert result.score < 20
    assert any("trusted project path downgrade" in r for r in result.informational)
