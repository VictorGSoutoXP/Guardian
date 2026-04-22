from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List

try:
    import yara  # type: ignore
except Exception as exc:  # pragma: no cover - depends on optional package
    yara = None
    _YARA_IMPORT_ERROR = exc
else:  # pragma: no cover - depends on optional package
    _YARA_IMPORT_ERROR = None


DEFAULT_TAG_WEIGHTS = {
    "critical": 80,
    "high": 50,
    "suspicious": 20,
    "medium": 20,
    "low": 10,
}
BASE_MATCH_SCORE = 20
DEFINITIVE_TAGS = {"critical", "definitive", "malware", "eicar"}


@dataclass
class YaraMatch:
    rule: str
    tags: List[str]
    namespace: str | None = None


@dataclass
class YaraEvaluation:
    available: bool
    score: int
    matches: List[YaraMatch]
    definitive: bool
    error: str | None = None


class YaraEngine:
    def __init__(self, rules_dir: str | Path, tag_weights: Dict[str, int] | None = None, enabled: bool = True):
        self.rules_dir = Path(rules_dir)
        self.tag_weights = {**DEFAULT_TAG_WEIGHTS, **(tag_weights or {})}
        self.enabled = enabled
        self.available = bool(enabled and yara is not None)
        self._rules = None
        self.error: str | None = None
        if self.available:
            self._compile()
        elif enabled and _YARA_IMPORT_ERROR is not None:
            self.error = str(_YARA_IMPORT_ERROR)

    def _iter_rule_files(self) -> Iterable[Path]:
        if not self.rules_dir.exists():
            return []
        return sorted(p for p in self.rules_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".yar", ".yara"})

    def _compile(self) -> None:  # pragma: no cover - requires yara package
        file_map = {f"rule_{idx}": str(path) for idx, path in enumerate(self._iter_rule_files(), start=1)}
        if not file_map:
            self._rules = None
            return
        try:
            self._rules = yara.compile(filepaths=file_map)
        except Exception as exc:
            self.error = str(exc)
            self._rules = None

    def info(self) -> Dict[str, object]:
        return {
            "yara_available": bool(self.available),
            "rules_dir": str(self.rules_dir),
            "rule_files": len(list(self._iter_rule_files())) if self.rules_dir.exists() else 0,
            "yara_error": self.error,
        }

    def evaluate_path(self, path: str | Path) -> YaraEvaluation:
        if not self.available:
            return YaraEvaluation(available=False, score=0, matches=[], definitive=False, error=self.error)
        if self._rules is None:
            return YaraEvaluation(available=True, score=0, matches=[], definitive=False, error=self.error)
        try:
            raw_matches = self._rules.match(str(path))
        except Exception as exc:  # pragma: no cover - requires yara package
            return YaraEvaluation(available=True, score=0, matches=[], definitive=False, error=str(exc))

        matches: List[YaraMatch] = []
        score = 0
        definitive = False
        for item in raw_matches:
            tags = list(getattr(item, "tags", []) or [])
            matches.append(YaraMatch(rule=str(getattr(item, "rule", "unknown")), tags=tags, namespace=getattr(item, "namespace", None)))
            item_score = BASE_MATCH_SCORE
            for tag in tags:
                tag_key = str(tag).lower()
                item_score = max(item_score, int(self.tag_weights.get(tag_key, BASE_MATCH_SCORE)))
                if tag_key in DEFINITIVE_TAGS:
                    definitive = True
            score += item_score
        return YaraEvaluation(available=True, score=score, matches=matches, definitive=definitive, error=None)
