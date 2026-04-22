from __future__ import annotations

import json
import os
import platform
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .config import load_config
from .scanner import FileScanResult, Scanner

QUICK_SCAN_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".scr", ".hta", ".jar", ".py", ".pyw", ".msi", ".com", ".lnk"
]


@dataclass
class HistoryRow:
    filename: str
    timestamp: str
    root_path: str
    scanned: int
    suspicious: int
    malicious: int
    interrupted: bool
    full_path: str


def open_path(path: str | Path) -> None:
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(str(target))
    system = platform.system()
    if system == "Windows":
        os.startfile(str(target))
    elif system == "Darwin":
        subprocess.Popen(["open", str(target)])
    else:
        subprocess.Popen(["xdg-open", str(target)])


class GuardianApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Guardian AV V5")
        self.root.geometry("1320x860")
        self.root.minsize(1100, 720)

        self.path_var = tk.StringVar(value=str(Path.cwd()))
        self.profile_var = tk.StringVar(value="Quick")
        self.filter_var = tk.StringVar(value="All")
        self.status_var = tk.StringVar(value="Ready for a new scan")
        self.report_var = tk.StringVar(value="No report yet")
        self.scanned_var = tk.StringVar(value="0")
        self.clean_var = tk.StringVar(value="0")
        self.suspicious_var = tk.StringVar(value="0")
        self.malicious_var = tk.StringVar(value="0")
        self.progress_var = tk.DoubleVar(value=0)
        self.last_scan_var = tk.StringVar(value="Last scan: not started")
        self.engine_var = tk.StringVar(value="Engine: Guardian AV 0.5")

        self.stop_event = threading.Event()
        self.scan_thread: threading.Thread | None = None
        self.last_report_path: Path | None = None
        self.current_results: list[dict] = []
        self.current_history: list[HistoryRow] = []

        self.project_root = Path(__file__).resolve().parents[2]
        self.config = self._load_runtime_config()
        self.reports_dir = Path(self.config["report_dir"])
        self.quarantine_dir = Path(self.config["quarantine_dir"])

        self._build_ui()
        self._refresh_history()
        self._refresh_engine_banner()

    def _load_runtime_config(self) -> dict:
        config = load_config(None)
        for key in ("quarantine_dir", "report_dir", "rules_dir", "cache_path"):
            value = Path(config[key])
            if not value.is_absolute():
                config[key] = str((self.project_root / value).resolve())
        return config

    def _refresh_engine_banner(self) -> None:
        try:
            signatures = (self.project_root / "data" / "signature_db.json").resolve()
            scanner = Scanner(
                root_path=self.path_var.get(),
                config=self.config,
                signature_db_path=signatures,
                rules_dir=self.config.get("rules_dir"),
                cache_path=self.config.get("cache_path"),
            )
            info = scanner.engine_info()
            yara_flag = "YARA on" if info.get("yara_available") else "YARA off"
            watch_flag = "watchdog on" if info.get("watchdog_available") else "watchdog fallback"
            cache_flag = "cache on" if info.get("cache_enabled") else "cache off"
            self.engine_var.set(f"Engine: Guardian AV 0.5 | {yara_flag} | {watch_flag} | {cache_flag}")
        except Exception:
            self.engine_var.set("Engine: Guardian AV 0.5")

    def _build_ui(self) -> None:
        self.root.configure(bg="#09111f")
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background="#09111f")
        style.configure("Panel.TFrame", background="#0f1a2e")
        style.configure("Card.TFrame", background="#111f36")
        style.configure("Header.TLabel", background="#09111f", foreground="#f8fafc", font=("Segoe UI", 24, "bold"))
        style.configure("Muted.TLabel", background="#09111f", foreground="#97a6ba", font=("Segoe UI", 10))
        style.configure("PanelTitle.TLabel", background="#0f1a2e", foreground="#e2e8f0", font=("Segoe UI", 11, "bold"))
        style.configure("CardTitle.TLabel", background="#111f36", foreground="#8fb3ff", font=("Segoe UI", 10, "bold"))
        style.configure("CardValue.TLabel", background="#111f36", foreground="#f8fafc", font=("Segoe UI", 24, "bold"))
        style.configure("CardSub.TLabel", background="#111f36", foreground="#a8b5c8", font=("Segoe UI", 9))
        style.configure("TLabel", background="#09111f", foreground="#e2e8f0")
        style.configure("TLabelframe", background="#09111f", foreground="#dbeafe")
        style.configure("TLabelframe.Label", background="#09111f", foreground="#dbeafe")
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.map("Accent.TButton", background=[("active", "#22c55e"), ("!disabled", "#16a34a")], foreground=[("!disabled", "white")])
        style.configure("TEntry", fieldbackground="#08111d", foreground="#f8fafc")
        style.configure("TCombobox", fieldbackground="#08111d")
        style.configure("Treeview", background="#0f1a2e", fieldbackground="#0f1a2e", foreground="#e2e8f0", rowheight=28, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background="#16253f", foreground="#f8fafc", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#1d4ed8")])
        style.configure("TNotebook", background="#09111f", borderwidth=0)
        style.configure("TNotebook.Tab", background="#0f1a2e", foreground="#b8c4d6", padding=(16, 8), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#16253f")], foreground=[("selected", "#ffffff")])
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor="#0b1321",
            background="#22c55e",
            bordercolor="#0b1321",
            lightcolor="#22c55e",
            darkcolor="#22c55e",
        )

        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 12))
        left = ttk.Frame(header)
        left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text="Guardian AV", style="Header.TLabel").pack(anchor="w")
        ttk.Label(left, text="Desktop scanner prototype with premium dashboard, YARA-ready engine, cache and history", style="Muted.TLabel").pack(anchor="w", pady=(2, 0))
        right = ttk.Frame(header)
        right.pack(side="right")
        ttk.Label(right, textvariable=self.engine_var, style="Muted.TLabel").pack(anchor="e")
        ttk.Label(right, textvariable=self.last_scan_var, style="Muted.TLabel").pack(anchor="e", pady=(4, 0))

        controls = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        controls.pack(fill="x", pady=(0, 12))
        ttk.Label(controls, text="Scan target", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(controls, text="Profile", style="PanelTitle.TLabel").grid(row=0, column=2, sticky="w", padx=(12, 0))
        ttk.Entry(controls, textvariable=self.path_var).grid(row=1, column=0, columnspan=2, sticky="ew", padx=(0, 8), pady=(8, 0))
        ttk.Combobox(controls, textvariable=self.profile_var, values=["Quick", "Full"], state="readonly", width=12).grid(row=1, column=2, sticky="w", padx=(12, 8), pady=(8, 0))
        ttk.Button(controls, text="Browse", command=self.browse_path).grid(row=1, column=3, padx=(0, 8), pady=(8, 0))
        self.scan_btn = ttk.Button(controls, text="Scan now", style="Accent.TButton", command=self.start_scan)
        self.scan_btn.grid(row=1, column=4, padx=(0, 8), pady=(8, 0))
        self.stop_btn = ttk.Button(controls, text="Stop", command=self.stop_scan)
        self.stop_btn.grid(row=1, column=5, pady=(8, 0))
        controls.columnconfigure(0, weight=1)

        cards = ttk.Frame(outer)
        cards.pack(fill="x", pady=(0, 12))
        self._card(cards, "Scanned", self.scanned_var, "files inspected").pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._card(cards, "Clean", self.clean_var, "healthy items").pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._card(cards, "Suspicious", self.suspicious_var, "needs attention").pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._card(cards, "Malicious", self.malicious_var, "high risk hits").pack(side="left", fill="x", expand=True)

        progress = ttk.Frame(outer, style="Panel.TFrame", padding=14)
        progress.pack(fill="x", pady=(0, 12))
        ttk.Label(progress, text="Current activity", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Progressbar(progress, variable=self.progress_var, maximum=100).pack(fill="x", pady=(10, 8))
        ttk.Label(progress, textvariable=self.status_var, background="#0f1a2e", foreground="#dbeafe", font=("Segoe UI", 10)).pack(anchor="w")
        ttk.Label(progress, textvariable=self.report_var, background="#0f1a2e", foreground="#94a3b8", font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)

        dashboard_tab = ttk.Frame(notebook)
        results_tab = ttk.Frame(notebook)
        history_tab = ttk.Frame(notebook)
        notebook.add(dashboard_tab, text="Dashboard")
        notebook.add(results_tab, text="Results")
        notebook.add(history_tab, text="History")

        self._build_dashboard_tab(dashboard_tab)
        self._build_results_tab(results_tab)
        self._build_history_tab(history_tab)

        self.stop_btn.state(["disabled"])

    def _build_dashboard_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=2)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(0, weight=1)

        activity_panel = ttk.Frame(parent, style="Panel.TFrame", padding=14)
        activity_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=(8, 0))
        ttk.Label(activity_panel, text="Activity log", style="PanelTitle.TLabel").pack(anchor="w")
        self.activity_text = tk.Text(
            activity_panel,
            height=18,
            bg="#08111d",
            fg="#dbeafe",
            insertbackground="#dbeafe",
            relief="flat",
            font=("Consolas", 10),
            wrap="word",
        )
        self.activity_text.pack(fill="both", expand=True, pady=(10, 0))
        self.activity_text.configure(state="disabled")

        side_panel = ttk.Frame(parent, style="Panel.TFrame", padding=14)
        side_panel.grid(row=0, column=1, sticky="nsew", pady=(8, 0))
        ttk.Label(side_panel, text="Actions", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Button(side_panel, text="Open reports folder", command=self.open_reports).pack(fill="x", pady=(10, 8))
        ttk.Button(side_panel, text="Open quarantine folder", command=self.open_quarantine).pack(fill="x", pady=(0, 8))
        ttk.Button(side_panel, text="Open last report", command=self.open_last_report).pack(fill="x", pady=(0, 8))
        ttk.Button(side_panel, text="Refresh history", command=self._refresh_history).pack(fill="x", pady=(0, 8))
        ttk.Separator(side_panel).pack(fill="x", pady=12)
        ttk.Label(
            side_panel,
            text="Quick profile scans execution-capable files first. Full profile scans every eligible file in the selected folder.",
            background="#0f1a2e",
            foreground="#a8b5c8",
            wraplength=260,
            justify="left",
        ).pack(anchor="w")

    def _build_results_tab(self, parent: ttk.Frame) -> None:
        toolbar = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        toolbar.pack(fill="x", pady=(8, 8))
        ttk.Label(toolbar, text="View", style="PanelTitle.TLabel").pack(side="left")
        ttk.Combobox(toolbar, textvariable=self.filter_var, values=["All", "Clean", "Suspicious", "Malicious", "Error"], state="readonly", width=14).pack(side="left", padx=(8, 12))
        ttk.Button(toolbar, text="Apply filter", command=self.apply_filter).pack(side="left")
        ttk.Button(toolbar, text="Clear results", command=self.clear_results_view).pack(side="left", padx=(8, 0))

        table_frame = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        table_frame.pack(fill="both", expand=True)

        columns = ("path", "verdict", "score", "reasons")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.tree.heading("path", text="Path")
        self.tree.heading("verdict", text="Verdict")
        self.tree.heading("score", text="Score")
        self.tree.heading("reasons", text="Reasons")
        self.tree.column("path", width=520, anchor="w")
        self.tree.column("verdict", width=120, anchor="center")
        self.tree.column("score", width=80, anchor="center")
        self.tree.column("reasons", width=520, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.tag_configure("clean", foreground="#c7d2fe")
        self.tree.tag_configure("suspicious", foreground="#facc15")
        self.tree.tag_configure("suspicious-high", foreground="#fb923c")
        self.tree.tag_configure("malicious", foreground="#f87171")
        self.tree.tag_configure("error", foreground="#fda4af")

    def _build_history_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        top.pack(fill="x", pady=(8, 8))
        ttk.Button(top, text="Refresh", command=self._refresh_history).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Open selected report", command=self.open_selected_history_report).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Open reports folder", command=self.open_reports).pack(side="left")

        frame = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        frame.pack(fill="both", expand=True)
        cols = ("file", "timestamp", "root", "scanned", "suspicious", "malicious", "interrupted")
        self.history_tree = ttk.Treeview(frame, columns=cols, show="headings")
        headings = {
            "file": "Report",
            "timestamp": "Timestamp",
            "root": "Scanned path",
            "scanned": "Scanned",
            "suspicious": "Suspicious",
            "malicious": "Malicious",
            "interrupted": "Stopped",
        }
        widths = {"file": 250, "timestamp": 170, "root": 390, "scanned": 90, "suspicious": 100, "malicious": 90, "interrupted": 80}
        for col in cols:
            self.history_tree.heading(col, text=headings[col])
            self.history_tree.column(col, width=widths[col], anchor="w" if col in {"file", "timestamp", "root"} else "center")
        self.history_tree.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.history_tree.yview)
        scroll.pack(side="right", fill="y")
        self.history_tree.configure(yscrollcommand=scroll.set)

    def _card(self, parent: ttk.Frame, title: str, value_var: tk.StringVar, subtitle: str) -> ttk.Frame:
        frame = ttk.Frame(parent, style="Card.TFrame", padding=14)
        ttk.Label(frame, text=title, style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(frame, textvariable=value_var, style="CardValue.TLabel").pack(anchor="w", pady=(4, 0))
        ttk.Label(frame, text=subtitle, style="CardSub.TLabel").pack(anchor="w", pady=(4, 0))
        return frame

    def browse_path(self) -> None:
        selected = filedialog.askdirectory(initialdir=self.path_var.get() or str(Path.cwd()))
        if selected:
            self.path_var.set(selected)

    def log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_text.configure(state="normal")
        self.activity_text.insert("end", f"[{timestamp}] {message}\n")
        self.activity_text.see("end")
        self.activity_text.configure(state="disabled")

    def stop_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_event.set()
            self.status_var.set("Stopping scan...")
            self.log("Stop requested by user")

    def start_scan(self) -> None:
        target = Path(self.path_var.get()).expanduser().resolve()
        if not target.exists() or not target.is_dir():
            messagebox.showerror("Guardian AV", "Choose a valid folder to scan.")
            return
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Guardian AV", "A scan is already running.")
            return

        self.stop_event.clear()
        self.progress_var.set(0)
        self.status_var.set("Preparing scan...")
        self.report_var.set("No report yet")
        self.last_report_path = None
        self.current_results = []
        self.clear_results_view()
        self._update_stats({"scanned": 0, "clean": 0, "suspicious": 0, "suspicious-high": 0, "malicious": 0})
        self.log(f"Starting {self.profile_var.get().lower()} scan on {target}")

        self.scan_btn.state(["disabled"])
        self.stop_btn.state(["!disabled"])
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(target, self.profile_var.get()), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, target: Path, profile: str) -> None:
        try:
            signatures = (self.project_root / "data" / "signature_db.json").resolve()
            scanner = Scanner(root_path=target, config=self.config, signature_db_path=signatures, rules_dir=self.config.get("rules_dir"), cache_path=self.config.get("cache_path"))
            include_extensions = QUICK_SCAN_EXTENSIONS if profile.lower() == "quick" else None

            def on_progress(index: int, total: int, result: FileScanResult, stats: dict) -> None:
                progress = (index / total * 100) if total else 100
                result_dict = {
                    "path": result.path,
                    "sha256": result.sha256,
                    "size_bytes": result.size_bytes,
                    "matched_signature": result.matched_signature,
                    "heuristic_score": result.heuristic_score,
                    "verdict": result.verdict,
                    "reasons": result.reasons,
                    "informational": result.informational,
                    "yara_score": result.yara_score,
                    "yara_matches": result.yara_matches,
                    "cache_hit": result.cache_hit,
                    "quarantined_to": result.quarantined_to,
                }
                self.current_results.append(result_dict)
                self.root.after(0, self._append_result, result_dict)
                self.root.after(0, self._update_stats, stats.copy())
                self.root.after(0, self.progress_var.set, progress)
                self.root.after(0, self.status_var.set, f"Scanning... {index}/{total}")
                self.root.after(0, self.log, f"{result.verdict.upper():<15} {Path(result.path).name}")

            payload = scanner.scan(include_extensions=include_extensions, progress_callback=on_progress, stop_event=self.stop_event)
            self.last_report_path = Path(payload["report_path"])
            interrupted = payload.get("interrupted", False)
            finished = "Scan stopped" if interrupted else "Scan finished"
            self.root.after(0, self.report_var.set, str(self.last_report_path))
            self.root.after(0, self.status_var.set, f"{finished}. Report saved.")
            self.root.after(0, self.progress_var.set, 100 if payload["stats"].get("scanned", 0) else 0)
            self.root.after(0, self.last_scan_var.set, f"Last scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.root.after(0, self.log, f"{finished}. {payload['stats']}")
            self.root.after(0, self._refresh_history)
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Guardian AV", f"Failed to run GUI scan:\n{exc}"))
            self.root.after(0, self.status_var.set, "Scan failed")
            self.root.after(0, self.log, f"Scan failed: {exc}")
        finally:
            self.root.after(0, lambda: self.scan_btn.state(["!disabled"]))
            self.root.after(0, lambda: self.stop_btn.state(["disabled"]))
            self.stop_event.clear()

    def clear_results_view(self) -> None:
        if hasattr(self, "tree"):
            for row in self.tree.get_children():
                self.tree.delete(row)

    def _append_result(self, result: dict) -> None:
        if self._matches_filter(result["verdict"]):
            self.tree.insert(
                "",
                "end",
                values=(result["path"], result["verdict"], result["heuristic_score"], " | ".join(result["reasons"][:4])),
                tags=(result["verdict"],),
            )

    def _matches_filter(self, verdict: str) -> bool:
        selected = self.filter_var.get().lower()
        if selected == "all":
            return True
        if selected == "suspicious":
            return verdict in {"suspicious", "suspicious-high"}
        if selected == "malicious":
            return verdict == "malicious"
        if selected == "error":
            return verdict == "error"
        return verdict == selected

    def apply_filter(self) -> None:
        self.clear_results_view()
        for result in self.current_results:
            self._append_result(result)

    def _update_stats(self, stats: dict) -> None:
        self.scanned_var.set(str(stats.get("scanned", 0)))
        self.clean_var.set(str(stats.get("clean", 0)))
        suspicious = stats.get("suspicious", 0) + stats.get("suspicious-high", 0)
        self.suspicious_var.set(str(suspicious))
        self.malicious_var.set(str(stats.get("malicious", 0)))

    def _load_history_rows(self) -> list[HistoryRow]:
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        rows: list[HistoryRow] = []
        for report in sorted(self.reports_dir.glob("scan_report_*.json"), reverse=True):
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
            except Exception:
                continue
            stats = data.get("stats", {})
            suspicious = int(stats.get("suspicious", 0)) + int(stats.get("suspicious-high", 0))
            timestamp = data.get("finished_at_utc") or report.stem.replace("scan_report_", "")
            rows.append(
                HistoryRow(
                    filename=report.name,
                    timestamp=str(timestamp),
                    root_path=str(data.get("root_path", "")),
                    scanned=int(stats.get("scanned", 0)),
                    suspicious=suspicious,
                    malicious=int(stats.get("malicious", 0)),
                    interrupted=bool(data.get("interrupted", False)),
                    full_path=str(report),
                )
            )
        return rows

    def _refresh_history(self) -> None:
        if not hasattr(self, "history_tree"):
            return
        self.current_history = self._load_history_rows()
        for row in self.history_tree.get_children():
            self.history_tree.delete(row)
        for item in self.current_history:
            self.history_tree.insert(
                "",
                "end",
                values=(
                    item.filename,
                    item.timestamp,
                    item.root_path,
                    item.scanned,
                    item.suspicious,
                    item.malicious,
                    "yes" if item.interrupted else "no",
                ),
            )

    def _selected_history_row(self) -> HistoryRow | None:
        selection = self.history_tree.selection()
        if not selection:
            return self.current_history[0] if self.current_history else None
        values = self.history_tree.item(selection[0], "values")
        filename = values[0] if values else None
        for row in self.current_history:
            if row.filename == filename:
                return row
        return None

    def open_selected_history_report(self) -> None:
        row = self._selected_history_row()
        if not row:
            messagebox.showinfo("Guardian AV", "No report found yet.")
            return
        try:
            open_path(row.full_path)
        except Exception as exc:
            messagebox.showerror("Guardian AV", str(exc))

    def open_reports(self) -> None:
        try:
            open_path(self.reports_dir)
        except Exception as exc:
            messagebox.showerror("Guardian AV", str(exc))

    def open_quarantine(self) -> None:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        try:
            open_path(self.quarantine_dir)
        except Exception as exc:
            messagebox.showerror("Guardian AV", str(exc))

    def open_last_report(self) -> None:
        if not self.last_report_path or not self.last_report_path.exists():
            latest = self.current_history[0].full_path if self.current_history else None
            if latest:
                self.last_report_path = Path(latest)
            else:
                messagebox.showinfo("Guardian AV", "No report created yet.")
                return
        try:
            open_path(self.last_report_path)
        except Exception as exc:
            messagebox.showerror("Guardian AV", str(exc))


def main() -> None:
    root = tk.Tk()
    GuardianApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
