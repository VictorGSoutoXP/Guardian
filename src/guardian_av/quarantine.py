from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict


def quarantine_file(src_path: str | Path, quarantine_dir: str | Path, metadata: Dict) -> Path:
    src = Path(src_path)
    qdir = Path(quarantine_dir)
    qdir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest_name = f"{timestamp}__{src.name}"
    dest = qdir / dest_name

    shutil.move(str(src), str(dest))

    meta_path = dest.with_suffix(dest.suffix + ".json")
    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    return dest
