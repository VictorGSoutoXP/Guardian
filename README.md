# Guardian AV V5

Guardian AV V5 is an educational antivirus-style scanner prototype with:

- premium desktop UI
- CLI scan, watch and info commands
- heuristic scoring
- SHA-256 signature lookup
- optional YARA rule engine
- optional watchdog-based file monitoring
- hash cache for faster rescans
- quarantine and JSON reports

## Windows quick start

```bat
cd "C:\Users\Nágela\Documents\GitHub\Projeto Antivírus"
.\.venv\Scripts\activate.bat
python -m pip install -e .
python -m guardian_av.gui
```

Optional extras for YARA and real-time watch:

```bat
python -m pip install -r requirements.txt
```

Check capabilities:

```bat
python -m guardian_av.cli info --path .
```

Run a quick scan:

```bat
python -m guardian_av.cli scan --path . --profile quick
```

Run a full scan:

```bat
python -m guardian_av.cli scan --path . --profile full
```

Watch a folder continuously:

```bat
python -m guardian_av.cli watch --path "C:\Users\Downloads"
```

## Notes

- Without `yara-python`, the app still works and simply disables YARA.
- Without `watchdog`, `watch` falls back to polling.
- The included signature database is empty by default for safe experimentation.
- This is a serious prototype, not a kernel-level commercial antivirus.
