# Log Analyzer

![CI](https://github.com/Souza2003/log-analyzer/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A Python security tool that parses system logs and detects threats using rule-based detection. Supports multiple log formats with both a CLI and a Streamlit dashboard.

---

## Screenshot

![Streamlit dashboard](docs/screenshot.png)

<img width="1902" height="883" alt="Screenshot 2026-03-30 082802" src="https://github.com/user-attachments/assets/24cce9b5-c4a9-4f90-a3b8-5b8513c700d0" />

<img width="1907" height="886" alt="Screenshot 2026-03-30 082824" src="https://github.com/user-attachments/assets/d98cc2c5-9b66-47fc-a09e-6fa28547b5fe" />

---

## Supported log formats

| Format | Auto-detected | Notes |
|---|---|---|
| Linux `auth.log` | Yes | SSH, sudo, PAM events |
| Apache / Nginx access log | Yes | Combined log format |
| Windows Event Log XML | Yes | Exported from Event Viewer |
| Windows Event Log CSV | Yes | Exported from Event Viewer |
| Generic syslog | Yes | RFC 3164 format |

## Detection rules

| Rule | Severity | Description |
|---|---|---|
| `BRUTE_FORCE` | HIGH | ≥5 failed logins from one IP within 10 min |
| `SUCCESS_AFTER_BRUTE` | CRITICAL | Successful login from IP after ≥5 failures |
| `PASSWORD_SPRAY` | HIGH | One IP targeting ≥3 distinct usernames |
| `PRIV_ESC_ATTEMPT` | HIGH | ≥3 sudo denials by one user within 1 hour |
| `PRIV_ESC_SUCCESS` | CRITICAL | Sudo success for user with prior denials |
| `PORT_SCAN_PATTERN` | MEDIUM | ≥15 distinct rapid requests from one IP |

---

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/log-analyzer
cd log-analyzer
pip install -r requirements.txt
```

**Streamlit dashboard:**
```bash
streamlit run app.py
```

**CLI — auto-detect format:**
```bash
python analyzer.py /var/log/auth.log
```

**CLI — force format:**
```bash
python analyzer.py server.log --format apache
```

**CLI — JSON output (pipe-friendly):**
```bash
python analyzer.py /var/log/auth.log --json | jq '.[] | select(.severity == "CRITICAL")'
```

**CLI — minimum severity filter:**
```bash
python analyzer.py /var/log/auth.log --min-severity HIGH
```

---

## CLI output example

```
  Log Analyzer  —  auth.log
  ──────────────────────────────────────────────────
  Format   : auth
  Entries  : 20
  Alerts   : 4

  CRITICAL   1 alert(s)
  HIGH       3 alert(s)

  [1] CRITICAL  SUCCESS_AFTER_BRUTE
      Successful login from 192.168.1.105 after 6 failures — possible compromise
      IP       : 192.168.1.105
      User     : root
      Time     : 2025-01-15 08:01:12  →  2025-01-15 08:01:24
      Count    : 7 event(s)
      Evidence :
        Jan 15 08:01:12 server sshd[1234]: Failed password for root from 192.168.1.105
        ...
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | No alerts |
| `1` | Alerts found (below CRITICAL) |
| `2` | CRITICAL alerts found |

---

## Project structure

```
log-analyzer/
├── .github/
│   └── workflows/
│       └── ci.yml          # CI: tests on Python 3.10/3.11/3.12 + lint
├── docs/
│   └── screenshot.png      # Add after running streamlit run app.py
├── sample_logs/
│   ├── auth.log            # Linux SSH/sudo sample
│   └── access.log          # Apache access log sample
├── analyzer.py             # CLI entry point
├── app.py                  # Streamlit dashboard
├── parsers.py              # Log parsers (one per format)
├── rules.py                # Detection rules
├── detector.py             # Auto-format detection
├── models.py               # LogEntry, Alert, Severity dataclasses
├── tests.py                # 12 unit tests
├── requirements.txt
└── README.md
```

---

## Use as a module

```python
from parsers import parse
from rules import run_all
from detector import detect_format
from pathlib import Path

path = Path("/var/log/auth.log")
fmt = detect_format(path)
entries = parse(path.read_text(), fmt)
alerts = run_all(entries)

for alert in alerts:
    print(alert.severity.value, alert.rule, alert.description)
```

---

## Technical concepts

- **Sliding window detection** — brute force and spray rules use a time-windowed burst algorithm, not just raw counts, to avoid false positives from spread-out events.
- **Auto format detection** — regex signature matching on the first 4KB of the file; falls back to file extension.
- **Meaningful exit codes** — `0/1/2` map to clean/alerts/critical, making it usable in CI pipelines and shell scripts.
- **Separation of concerns** — parsers, rules, models, and UI are fully decoupled; any component is importable independently.

---

## Running tests

```bash
python tests.py
```

Zero external dependencies for the test suite.

---

## License

MIT
