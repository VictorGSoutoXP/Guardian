from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from .utils import safe_read_text_snippet, shannon_entropy


@dataclass
class HeuristicEvaluation:
    score: int
    reasons: List[str]
    indicators: List[str]
    informational: List[str]


def evaluate_file(path: str | Path, config: Dict, is_trusted_path: bool = False) -> HeuristicEvaluation:
    path = Path(path)
    reasons: List[str] = []
    informational: List[str] = []
    indicators: List[str] = []
    score = 0

    ext = path.suffix.lower()
    size_mb = path.stat().st_size / (1024 * 1024)
    suspicious_exts = set(config.get("suspicious_extensions", []))
    trusted_code_exts = set(config.get("trusted_code_extensions", []))

    if ext in suspicious_exts:
        score += 20
        indicators.append("extension")
        reasons.append(f"suspicious extension: {ext}")

    scriptish_exts = suspicious_exts | {".py", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".jar"}
    if size_mb > float(config.get("max_file_size_mb", 100)) and ext in scriptish_exts:
        score += 12
        indicators.append("size")
        reasons.append(f"oversized executable/script: {size_mb:.2f} MB")

    try:
        entropy = shannon_entropy(path)
        threshold = float(config.get("entropy_threshold", 7.4))
        if entropy >= threshold:
            score += 20
            indicators.append("entropy")
            reasons.append(f"high entropy: {entropy:.2f}")
    except Exception as exc:
        informational.append(f"entropy unreadable: {exc}")

    try:
        snippet = safe_read_text_snippet(path)
        matches: List[str] = []
        weights = config.get("dangerous_string_weights", {})
        for marker in config.get("suspicious_strings", []):
            marker_lc = str(marker).lower()
            if marker_lc in snippet:
                matches.append(marker)
        if matches:
            string_score = sum(int(weights.get(m, 10)) for m in matches)
            min_matches_for_text = int(config.get("min_string_matches_for_text_suspicion", 2))
            is_probably_safe_text = ext in trusted_code_exts or ext == ""
            if is_probably_safe_text and len(matches) < min_matches_for_text and not is_trusted_path:
                string_score = min(string_score, 10)
            elif is_trusted_path and is_probably_safe_text:
                string_score = min(string_score, 8)
            score += min(45, string_score)
            indicators.append("strings")
            reasons.append(f"suspicious strings: {', '.join(matches[:5])}")
    except Exception:
        pass

    if is_trusted_path and ext in trusted_code_exts:
        score = max(0, score - 20)
        if reasons:
            informational.append("trusted project path downgrade applied")

    if score == 0:
        reasons = []
    return HeuristicEvaluation(score=score, reasons=reasons, indicators=list(dict.fromkeys(indicators)), informational=informational)
