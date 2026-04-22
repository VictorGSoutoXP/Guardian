from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

try:
    from watchdog.events import FileSystemEventHandler  # type: ignore
    from watchdog.observers import Observer  # type: ignore
except Exception as exc:  # pragma: no cover - depends on optional package
    FileSystemEventHandler = object
    Observer = None
    _WATCHDOG_IMPORT_ERROR = exc
else:  # pragma: no cover - depends on optional package
    _WATCHDOG_IMPORT_ERROR = None


class _ScanEventHandler(FileSystemEventHandler):  # pragma: no cover - requires watchdog
    def __init__(self, on_file: Callable[[Path], None]):
        super().__init__()
        self.on_file = on_file

    def on_created(self, event):
        if not event.is_directory:
            self.on_file(Path(event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            self.on_file(Path(event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            self.on_file(Path(event.dest_path))


class WatchCoordinator:
    def __init__(self, scanner):
        self.scanner = scanner
        self.available = Observer is not None
        self.error = str(_WATCHDOG_IMPORT_ERROR) if _WATCHDOG_IMPORT_ERROR else None

    def info(self) -> dict:
        return {
            "watchdog_available": bool(self.available),
            "watchdog_error": self.error,
        }

    def watch(self, *, interval_seconds: int | None = None, initial_scan: bool = True, stop_event=None, on_result=None) -> None:
        if self.available:
            self._watchdog_watch(initial_scan=initial_scan, stop_event=stop_event, on_result=on_result)
            return
        self._polling_watch(interval_seconds=interval_seconds, initial_scan=initial_scan, stop_event=stop_event, on_result=on_result)

    def _emit(self, path: Path, on_result=None):
        try:
            result = self.scanner.scan_file(path)
            if on_result is not None:
                on_result(result)
            else:
                print(f"[{result.verdict}] {result.path}")
                if result.reasons:
                    print("  -> " + " | ".join(result.reasons))
        except Exception as exc:
            print(f"[error] {path}: {exc}")

    def _watchdog_watch(self, *, initial_scan: bool, stop_event=None, on_result=None) -> None:  # pragma: no cover - requires watchdog
        if initial_scan:
            self.scanner.scan(stop_event=stop_event)
        observer = Observer()
        handler = _ScanEventHandler(lambda path: self._emit(path, on_result=on_result))
        observer.schedule(handler, str(self.scanner.root_path), recursive=True)
        observer.start()
        try:
            while stop_event is None or not stop_event.is_set():
                time.sleep(0.25)
        finally:
            observer.stop()
            observer.join(timeout=2)

    def _polling_watch(self, *, interval_seconds: int | None, initial_scan: bool, stop_event=None, on_result=None) -> None:
        interval = interval_seconds or int(self.scanner.config.get("watch_interval_seconds", 15))
        seen_mtimes: dict[str, float] = {}
        if initial_scan:
            self.scanner.scan(stop_event=stop_event)
        while stop_event is None or not stop_event.is_set():
            for path in self.scanner.iter_files():
                key = str(path)
                try:
                    mtime = path.stat().st_mtime
                except FileNotFoundError:
                    continue
                if key not in seen_mtimes or mtime > seen_mtimes[key]:
                    seen_mtimes[key] = mtime
                    self._emit(path, on_result=on_result)
            time.sleep(interval)
