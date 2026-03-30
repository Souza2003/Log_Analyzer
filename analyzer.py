"""
CLI entry point: python analyzer.py <logfile> [options]
"""
import argparse
import json
import sys
from pathlib import Path

from detector import detect_format
from models import LogFormat, Severity
from parsers import parse
from rules import run_all

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"

SEV_COLOR = {
    Severity.CRITICAL: RED,
    Severity.HIGH:     YELLOW,
    Severity.MEDIUM:   BLUE,
    Severity.LOW:      GREEN,
    Severity.INFO:     DIM,
}


def _print_report(path: Path, fmt: LogFormat, entries: list, alerts: list) -> None:
    print()
    print(f"  {BOLD}Log Analyzer{RESET}  —  {path.name}")
    print(f"  {'─' * 50}")
    print(f"  Format   : {fmt.value}")
    print(f"  Entries  : {len(entries):,}")
    print(f"  Alerts   : {len(alerts)}")
    print()

    if not alerts:
        print(f"  {GREEN}No threats detected.{RESET}")
        print()
        return

    sev_counts: dict[str, int] = {}
    for a in alerts:
        sev_counts[a.severity.value] = sev_counts.get(a.severity.value, 0) + 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = sev_counts.get(sev, 0)
        if n:
            c = SEV_COLOR.get(Severity(sev), "")
            print(f"  {c}{sev:<10}{RESET} {n} alert(s)")
    print()

    for i, alert in enumerate(alerts, 1):
        c = SEV_COLOR.get(alert.severity, "")
        print(f"  {BOLD}[{i}] {c}{alert.severity.value}{RESET}  {alert.rule}")
        print(f"      {alert.description}")
        if alert.source_ip:
            print(f"      IP       : {alert.source_ip}")
        if alert.username:
            print(f"      User     : {alert.username}")
        print(f"      Time     : {alert.first_seen}  →  {alert.last_seen}")
        print(f"      Count    : {alert.count} event(s)")
        if alert.evidence:
            print("      Evidence :")
            for ev in alert.evidence[:3]:
                print(f"        {DIM}{ev}{RESET}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description="Analyse log files for security threats.",
    )
    parser.add_argument("logfile", help="Path to the log file to analyse.")
    parser.add_argument(
        "--format", "-f",
        choices=[f.value for f in LogFormat if f != LogFormat.UNKNOWN],
        default=None,
        help="Force a specific log format (default: auto-detect).",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output alerts as JSON.",
    )
    parser.add_argument(
        "--min-severity", "-s",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity to display (default: LOW).",
    )
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    fmt = LogFormat(args.format) if args.format else detect_format(path)
    if fmt == LogFormat.UNKNOWN:
        print("Error: could not detect log format. Use --format to specify.", file=sys.stderr)
        sys.exit(1)

    text = path.read_text(errors="replace")
    entries = parse(text, fmt)
    alerts = run_all(entries)

    sev_order = {s: i for i, s in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])}
    min_sev = sev_order[args.min_severity]
    alerts = [a for a in alerts if sev_order.get(a.severity.value, 9) <= min_sev]

    if args.json:
        print(json.dumps([a.to_dict() for a in alerts], indent=2, default=str))
    else:
        _print_report(path, fmt, entries, alerts)

    # Exit code: 0 = clean, 1 = alerts found, 2 = critical alerts
    if any(a.severity == Severity.CRITICAL for a in alerts):
        sys.exit(2)
    if alerts:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()