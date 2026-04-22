# Guardian AV

Guardian AV is an educational antivirus-style scanner prototype built in Python.
It combines a desktop UI, CLI commands, heuristic scoring, SHA-256 lookup, optional YARA rules, optional real-time monitoring with watchdog, and JSON scan reports.

## Important notice

Guardian AV is a **serious prototype for study and portfolio use**. It is **not** a replacement for Microsoft Defender or any commercial security suite.

It does **not** include a kernel driver, cloud reputation service, sandboxing, enterprise telemetry, or threat intelligence infrastructure.

Use it for learning, experimentation, and local scanning in controlled environments.

## Features

- Desktop UI with scan dashboard and results view
- CLI commands for `scan`, `watch`, and `info`
- Heuristic risk scoring
- SHA-256 signature lookup
- Optional YARA rule support
- Optional watchdog-based file monitoring
- Hash cache for faster rescans
- Quarantine flow and JSON reports
- Trusted-path handling to reduce self-scan false positives

## Project structure

```text
Guardian AV/
├── src/guardian_av/
├── data/
├── rules/
├── tests/
├── config.json
├── pyproject.toml
└── requirements.txt
```

## Requirements

- Python 3.10+
- Windows is the primary tested environment for this repository

## Quick start (Windows)

Use a path without accented characters when possible, for example:

```bat
C:\Guardian
```

### 1) Create and activate a virtual environment

```bat
cd /d C:\Guardian
python -m venv .venv
.\.venv\Scripts\activate.bat
```

### 2) Install the project

```bat
python -m pip install -e .
```

### 3) Install optional extras for YARA and real-time watch

```bat
python -m pip install -r requirements.txt
```

## Usage

### Open the desktop UI

```bat
python -m guardian_av.gui
```

### Show environment capabilities

```bat
python -m guardian_av.cli info --path .
```

### Run a quick scan

```bat
python -m guardian_av.cli scan --path . --profile quick
```

### Run a full scan

```bat
python -m guardian_av.cli scan --path . --profile full
```

### Watch a folder continuously

```bat
python -m guardian_av.cli watch --path "C:\Users\Public\Downloads"
```

## GitHub / repository notes

Before pushing your own clone publicly, keep generated files out of version control.
This repository includes a `.gitignore` for:

- `.venv/`
- `reports/`
- `quarantine/`
- `data/hash_cache.json`
- build and cache artifacts

## Security guidance

- Do not treat this project as your only line of defense on a real machine.
- Do not execute unknown files just to test detections.
- Use isolated samples and controlled environments for experiments.
- Keep any real malware research out of your daily-use system.

## License

This project is released under the MIT License. See `LICENSE`.
