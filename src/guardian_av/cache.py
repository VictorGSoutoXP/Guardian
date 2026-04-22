from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict, Tuple


class HashCache:
    def __init__(self, cache_path: str | Path):
        self.cache_path = Path(cache_path)
        self._lock = threading.Lock()
        self._entries: Dict[str, Dict[str, str | int]] = {}
        self._dirty = False
        self.load()

    def load(self) -> None:
        if not self.cache_path.exists():
            self._entries = {}
            return
        try:
            self._entries = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            self._entries = {}

    def save(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._entries, ensure_ascii=False, indent=2), encoding="utf-8")
            self._dirty = False

    def _key(self, path: Path) -> str:
        return str(path.resolve())

    def get(self, path: str | Path, size_bytes: int, mtime_ns: int) -> str | None:
        key = self._key(Path(path))
        entry = self._entries.get(key)
        if not entry:
            return None
        if int(entry.get("size_bytes", -1)) != int(size_bytes):
            return None
        if int(entry.get("mtime_ns", -1)) != int(mtime_ns):
            return None
        sha256 = entry.get("sha256")
        return str(sha256) if isinstance(sha256, str) else None

    def put(self, path: str | Path, size_bytes: int, mtime_ns: int, sha256: str) -> None:
        key = self._key(Path(path))
        with self._lock:
            self._entries[key] = {
                "size_bytes": int(size_bytes),
                "mtime_ns": int(mtime_ns),
                "sha256": sha256,
            }
            self._dirty = True

    def get_or_set(self, path: str | Path, compute_sha256) -> Tuple[str, bool]:
        file_path = Path(path)
        stat = file_path.stat()
        cached = self.get(file_path, stat.st_size, stat.st_mtime_ns)
        if cached:
            return cached, True
        sha256 = compute_sha256(file_path)
        self.put(file_path, stat.st_size, stat.st_mtime_ns, sha256)
        return sha256, False
