from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_config
from .scanner import Scanner


QUICK_SCAN_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".scr", ".hta", ".jar", ".py", ".pyw", ".msi", ".com", ".lnk"
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guardian AV - educational antivirus-style scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a directory once")
    scan.add_argument("--path", required=True)
    scan.add_argument("--config", default=None)
    scan.add_argument("--signatures", default="data/signature_db.json")
    scan.add_argument("--rules", default=None)
    scan.add_argument("--cache", default=None)
    scan.add_argument("--profile", choices=["quick", "full"], default="full")
    scan.add_argument("--no-yara", action="store_true")
    scan.add_argument("--no-cache", action="store_true")

    watch = subparsers.add_parser("watch", help="Watch a directory continuously")
    watch.add_argument("--path", required=True)
    watch.add_argument("--config", default=None)
    watch.add_argument("--signatures", default="data/signature_db.json")
    watch.add_argument("--rules", default=None)
    watch.add_argument("--cache", default=None)
    watch.add_argument("--interval", type=int, default=None)
    watch.add_argument("--no-initial-scan", action="store_true")
    watch.add_argument("--no-yara", action="store_true")
    watch.add_argument("--no-cache", action="store_true")

    info = subparsers.add_parser("info", help="Show runtime capabilities")
    info.add_argument("--path", default=".")
    info.add_argument("--config", default=None)
    info.add_argument("--signatures", default="data/signature_db.json")
    info.add_argument("--rules", default=None)
    info.add_argument("--cache", default=None)
    info.add_argument("--no-yara", action="store_true")
    info.add_argument("--no-cache", action="store_true")
    return parser


def _prepare_config_paths(config: dict, project_root: Path) -> dict:
    for key in ("quarantine_dir", "report_dir", "rules_dir", "cache_path"):
        value = Path(config[key])
        if not value.is_absolute():
            config[key] = str((project_root / value).resolve())
    return config


def _build_scanner(args) -> Scanner:
    config = _prepare_config_paths(load_config(args.config), Path(__file__).resolve().parents[2])
    project_root = Path(__file__).resolve().parents[2]
    signatures = Path(args.signatures)
    if not signatures.is_absolute():
        signatures = (project_root / signatures).resolve()
    rules = Path(args.rules).resolve() if args.rules else Path(config["rules_dir"])
    cache = Path(args.cache).resolve() if args.cache else Path(config["cache_path"])
    return Scanner(
        root_path=args.path,
        config=config,
        signature_db_path=signatures,
        rules_dir=rules,
        cache_path=cache,
        enable_yara=not getattr(args, "no_yara", False),
        enable_cache=not getattr(args, "no_cache", False),
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    scanner = _build_scanner(args)
    if args.command == "scan":
        include_extensions = QUICK_SCAN_EXTENSIONS if args.profile == "quick" else None
        payload = scanner.scan(include_extensions=include_extensions)
        print(json.dumps(payload["stats"], ensure_ascii=False, indent=2))
        print(f"Report: {payload['report_path']}")
    elif args.command == "watch":
        scanner.watch(interval_seconds=args.interval, initial_scan=not args.no_initial_scan)
    elif args.command == "info":
        print(json.dumps(scanner.engine_info(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
