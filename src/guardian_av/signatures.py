from __future__ import annotations

import json
from pathlib import Path
from typing import Set


class SignatureDatabase:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.hashes: Set[str] = set()
        self.load()

    def load(self) -> None:
        if not self.db_path.exists():
            self.hashes = set()
            return
        with self.db_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        self.hashes = {h.lower() for h in data.get("sha256", []) if isinstance(h, str)}

    def is_malicious_hash(self, sha256_hash: str) -> bool:
        return sha256_hash.lower() in self.hashes
