from datetime import datetime
from models import LogEntry, LogFormat, Severity
from parsers import parse_auth, parse_apache
from rules import (
    detect_brute_force,
    detect_login_after_failures,
    detect_privilege_escalation,
    detect_password_spray,
    run_all,
)

# ── helpers ───────────────────────────────────────────────────────────────────

def make_entry(event_type, ip="1.2.3.4", user="testuser", minute=0):
    return LogEntry(
        timestamp=datetime(2025, 1, 15, 8, minute, 0),
        source_ip=ip,
        username=user,
        event_type=event_type,
        message=f"test {event_type}",
        raw=f"raw line for {event_type}",
        log_format=LogFormat.AUTH,
    )


# ── parser tests ──────────────────────────────────────────────────────────────

def test_parse_auth_failed():
    log = "Jan 15 08:01:12 server sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2"
    entries = list(parse_auth(log))
    assert len(entries) == 1
    assert entries[0].event_type == "failed_login"
    assert entries[0].source_ip == "10.0.0.1"
    assert entries[0].username == "root"


def test_parse_auth_success():
    log = "Jan 15 08:01:12 server sshd[1]: Accepted password for alice from 10.0.0.2 port 22 ssh2"
    entries = list(parse_auth(log))
    assert len(entries) == 1
    assert entries[0].event_type == "successful_login"


def test_parse_auth_sudo_denied():
    log = "Jan 15 08:10:00 server sudo[1]: bob : command not allowed ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
    entries = list(parse_auth(log))
    assert len(entries) == 1
    assert entries[0].event_type == "sudo_denied"


def test_parse_apache_401():
    log = '10.0.0.1 - - [15/Jan/2025:10:00:00 -0000] "GET /admin HTTP/1.1" 401 512'
    entries = list(parse_apache(log))
    assert len(entries) == 1
    assert entries[0].event_type == "auth_failure"
    assert entries[0].source_ip == "10.0.0.1"


def test_parse_apache_traversal():
    log = '10.0.0.1 - - [15/Jan/2025:10:00:00 -0000] "GET /../../../etc/passwd HTTP/1.1" 400 0'
    entries = list(parse_apache(log))
    assert entries[0].event_type == "path_traversal"


# ── detection tests ───────────────────────────────────────────────────────────

def test_brute_force_triggers():
    entries = [make_entry("failed_login", minute=i) for i in range(6)]
    alerts = detect_brute_force(entries)
    assert len(alerts) == 1
    assert alerts[0].rule == "BRUTE_FORCE"
    assert alerts[0].severity == Severity.HIGH


def test_brute_force_no_trigger_below_threshold():
    entries = [make_entry("failed_login", minute=i) for i in range(4)]
    alerts = detect_brute_force(entries)
    assert len(alerts) == 0


def test_success_after_brute():
    entries = [make_entry("failed_login", minute=i) for i in range(6)]
    entries.append(make_entry("successful_login", minute=7))
    alerts = detect_login_after_failures(entries)
    assert any(a.rule == "SUCCESS_AFTER_BRUTE" for a in alerts)
    assert any(a.severity == Severity.CRITICAL for a in alerts)


def test_priv_esc_triggers():
    entries = [make_entry("sudo_denied", user="eve", minute=i) for i in range(3)]
    alerts = detect_privilege_escalation(entries)
    assert any(a.rule == "PRIV_ESC_ATTEMPT" for a in alerts)


def test_password_spray():
    users = ["admin", "root", "ubuntu", "pi"]
    entries = [make_entry("invalid_user", user=u, minute=i) for i, u in enumerate(users)]
    alerts = detect_password_spray(entries)
    assert any(a.rule == "PASSWORD_SPRAY" for a in alerts)


def test_run_all_with_sample_auth():
    from pathlib import Path
    sample = Path("sample_logs/auth.log")
    if not sample.exists():
        print("  SKIP  test_run_all_with_sample_auth (no sample file)")
        return
    from parsers import parse
    text = sample.read_text()
    entries = parse(text, LogFormat.AUTH)
    alerts = run_all(entries)
    assert len(alerts) >= 3
    sev_values = {a.severity for a in alerts}
    assert Severity.CRITICAL in sev_values


def test_no_false_positive_clean_log():
    entries = [
        make_entry("successful_login", ip="1.2.3.4", minute=0),
        make_entry("successful_login", ip="5.6.7.8", minute=5),
    ]
    alerts = run_all(entries)
    assert len(alerts) == 0


# ── runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_parse_auth_failed,
        test_parse_auth_success,
        test_parse_auth_sudo_denied,
        test_parse_apache_401,
        test_parse_apache_traversal,
        test_brute_force_triggers,
        test_brute_force_no_trigger_below_threshold,
        test_success_after_brute,
        test_priv_esc_triggers,
        test_password_spray,
        test_run_all_with_sample_auth,
        test_no_false_positive_clean_log,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n  {passed} passed, {failed} failed")