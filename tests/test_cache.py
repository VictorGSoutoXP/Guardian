from pathlib import Path

from guardian_av.cache import HashCache


def test_hash_cache_roundtrip(tmp_path: Path):
    cache = HashCache(tmp_path / "cache.json")
    sample = tmp_path / "a.txt"
    sample.write_text("hello", encoding="utf-8")

    count = {"n": 0}

    def compute(path: Path) -> str:
        count["n"] += 1
        return "abc123"

    hash1, hit1 = cache.get_or_set(sample, compute)
    hash2, hit2 = cache.get_or_set(sample, compute)

    assert hash1 == hash2 == "abc123"
    assert hit1 is False
    assert hit2 is True
    assert count["n"] == 1
