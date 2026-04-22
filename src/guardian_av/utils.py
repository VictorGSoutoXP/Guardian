from __future__ import annotations

import hashlib
import math
from pathlib import Path


READ_CHUNK = 1024 * 1024


def sha256_file(path: str | Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(READ_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def shannon_entropy(path: str | Path, sample_size: int = 1024 * 256) -> float:
    with open(path, "rb") as f:
        data = f.read(sample_size)
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    total = len(data)
    for count in freq:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def safe_read_text_snippet(path: str | Path, max_bytes: int = 32768) -> str:
    with open(path, "rb") as f:
        raw = f.read(max_bytes)
    return raw.decode("utf-8", errors="ignore").lower()
