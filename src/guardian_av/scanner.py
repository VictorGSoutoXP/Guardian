from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Sequence

from .cache import HashCache
from .heuristics import evaluate_file
from .quarantine import quarantine_file
from .reporting import write_report
from .signatures import SignatureDatabase
from .utils import sha256_file
from .watcher import WatchCoordinator
from .yara_engine import YaraEngine


@dataclass
class FileScanResult:
    path: str
    sha256: str
    size_bytes: int
    matched_signature: bool
    heuristic_score: int
    verdict: str
    reasons: List[str]
    informational: List[str]
    yara_score: int = 0
    yara_matches: List[str] | None = None
    cache_hit: bool = False
    quarantined_to: str | None = None


ProgressCallback = Callable[[int, int, FileScanResult, Dict[str, int]], None]


class Scanner:
    def __init__(
        self,
        root_path: str | Path,
        config: Dict,
        signature_db_path: str | Path,
        *,
        rules_dir: str | Path | None = None,
        cache_path: str | Path | None = None,
        enable_yara: bool = True,
        enable_cache: bool = True,
    ):
        self.root_path = Path(root_path).resolve()
        self.config = config
        self.sig_db = SignatureDatabase(signature_db_path)
        self.suspicious_threshold = int(self.config.get("suspicious_threshold", 35))
        self.high_confidence_threshold = int(self.config.get("high_confidence_threshold", 70))
        self.min_indicators_for_suspicious = int(self.config.get("min_indicators_for_suspicious", 2))
        self.rules_dir = Path(rules_dir or self.config.get("rules_dir", "rules"))
        self.cache_path = Path(cache_path or self.config.get("cache_path", "data/hash_cache.json"))
        self.yara_engine = YaraEngine(self.rules_dir, self.config.get("yara_tag_weights", {}), enabled=enable_yara)
        self.hash_cache = HashCache(self.cache_path) if enable_cache else None
        self.watcher = WatchCoordinator(self)

    def engine_info(self) -> Dict[str, object]:
        info = {
            "version": "0.5.0",
            "root_path": str(self.root_path),
            "cache_enabled": self.hash_cache is not None,
            "cache_path": str(self.cache_path),
            "signature_db_path": str(self.sig_db.db_path),
        }
        info.update(self.yara_engine.info())
        info.update(self.watcher.info())
        return info

    def _is_trusted_relative_path(self, path: Path) -> bool:
        trusted_items = [str(p).replace("\\", "/").strip("/") for p in self.config.get("trusted_relative_paths", [])]
        try:
            rel = path.resolve().relative_to(self.root_path).as_posix()
        except ValueError:
            rel = path.resolve().as_posix()
        return any(item and (rel == item or rel.startswith(item + "/")) for item in trusted_items)

    def iter_files(self, include_extensions: Sequence[str] | None = None) -> Iterable[Path]:
        excluded_dirs = set(self.config.get("exclude_dirs", []))
        excluded_exts = {ext.lower() for ext in self.config.get("exclude_extensions", [])}
        include_exts = {ext.lower() for ext in include_extensions or []}
        for path in self.root_path.rglob("*"):
            if not path.is_file():
                continue
            if any(part in excluded_dirs for part in path.parts):
                continue
            if path.suffix.lower() in excluded_exts:
                continue
            if include_exts and path.suffix.lower() not in include_exts:
                continue
            yield path

    def _hash_with_optional_cache(self, path: Path) -> tuple[str, bool]:
        if self.hash_cache is None:
            return sha256_file(path), False
        return self.hash_cache.get_or_set(path, sha256_file)

    def scan_file(self, path: str | Path) -> FileScanResult:
        file_path = Path(path)
        stat = file_path.stat()
        sha256, cache_hit = self._hash_with_optional_cache(file_path)
        matched_signature = self.sig_db.is_malicious_hash(sha256)

        is_trusted_path = self._is_trusted_relative_path(file_path)
        heuristic = evaluate_file(file_path, self.config, is_trusted_path=is_trusted_path)
        informational = list(heuristic.informational)
        reasons = list(heuristic.reasons)
        yara_matches: List[str] = []
        yara_score = 0
        definitive_yara = False

        yara_eval = self.yara_engine.evaluate_path(file_path)
        if yara_eval.error and yara_eval.available:
            informational.append(f"yara error: {yara_eval.error}")
        if yara_eval.matches:
            yara_matches = [match.rule for match in yara_eval.matches]
            definitive_yara = yara_eval.definitive
            if is_trusted_path and not definitive_yara:
                informational.append("trusted project path suppressed non-definitive YARA matches")
            else:
                yara_score = yara_eval.score
                reasons.append(f"yara matches: {', '.join(yara_matches[:4])}")

        total_score = heuristic.score + yara_score
        indicators = set(heuristic.indicators)
        if yara_score > 0:
            indicators.add("yara")

        verdict = "clean"
        quarantined_to = None
        if matched_signature:
            verdict = "malicious"
            reasons = ["known malicious signature matched"] + reasons
        elif definitive_yara and yara_score >= self.high_confidence_threshold:
            verdict = "suspicious-high"
        else:
            indicator_count = len(indicators)
            if total_score >= self.high_confidence_threshold and indicator_count >= self.min_indicators_for_suspicious:
                verdict = "suspicious-high"
            elif total_score >= self.suspicious_threshold and indicator_count >= self.min_indicators_for_suspicious:
                verdict = "suspicious"
            elif total_score >= self.high_confidence_threshold and not is_trusted_path:
                verdict = "suspicious"

        if verdict in {"malicious", "suspicious-high"} and self.config.get("quarantine_on_high_confidence", True):
            metadata = {
                "original_path": str(file_path),
                "sha256": sha256,
                "matched_signature": matched_signature,
                "heuristic_score": heuristic.score,
                "yara_score": yara_score,
                "yara_matches": yara_matches,
                "verdict": verdict,
                "reasons": reasons,
                "quarantined_at_utc": datetime.now(timezone.utc).isoformat(),
            }
            quarantined_to = str(quarantine_file(file_path, self.config["quarantine_dir"], metadata))

        return FileScanResult(
            path=str(file_path),
            sha256=sha256,
            size_bytes=stat.st_size,
            matched_signature=matched_signature,
            heuristic_score=total_score,
            verdict=verdict,
            reasons=reasons if verdict != "clean" else [],
            informational=informational,
            yara_score=yara_score,
            yara_matches=yara_matches,
            cache_hit=cache_hit,
            quarantined_to=quarantined_to,
        )

    def scan(self, *, include_extensions: Sequence[str] | None = None, progress_callback: ProgressCallback | None = None, stop_event=None) -> Dict:
        started = datetime.now(timezone.utc).isoformat()
        results: List[FileScanResult] = []
        stats = {"scanned": 0, "clean": 0, "suspicious": 0, "suspicious-high": 0, "malicious": 0, "error": 0}
        files = list(self.iter_files(include_extensions=include_extensions))
        total = len(files)
        interrupted = False
        for idx, file_path in enumerate(files, start=1):
            if stop_event is not None and stop_event.is_set():
                interrupted = True
                break
            try:
                result = self.scan_file(file_path)
            except Exception as exc:
                result = FileScanResult(
                    path=str(file_path), sha256="", size_bytes=0, matched_signature=False,
                    heuristic_score=0, verdict="error", reasons=[f"scan failed: {exc}"],
                    informational=[], yara_matches=[]
                )
            results.append(result)
            stats["scanned"] += 1
            stats[result.verdict] = stats.get(result.verdict, 0) + 1
            if progress_callback is not None:
                progress_callback(idx, total, result, dict(stats))
        if self.hash_cache is not None:
            self.hash_cache.save()
        payload = {
            "started_at_utc": started,
            "finished_at_utc": datetime.now(timezone.utc).isoformat(),
            "root_path": str(self.root_path),
            "stats": stats,
            "results": [asdict(r) for r in results],
            "interrupted": interrupted,
            "engine": self.engine_info(),
        }
        payload["report_path"] = str(write_report(self.config["report_dir"], payload))
        return payload

    def watch(self, interval_seconds: int | None = None, initial_scan: bool = True, stop_event=None, on_result=None) -> None:
        self.watcher.watch(interval_seconds=interval_seconds, initial_scan=initial_scan, stop_event=stop_event, on_result=on_result)
