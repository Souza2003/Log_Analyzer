"""
Detection rules — each rule scans a list of LogEntry objects and returns Alerts.
"""
from collections import defaultdict
from datetime import timedelta

from models import Alert, LogEntry, Severity

# ── tuneable thresholds ───────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5        # failed logins from same IP within window
BRUTE_FORCE_WINDOW    = timedelta(minutes=10)
SPRAY_THRESHOLD       = 3        # distinct usernames targeted from one IP
PORT_SCAN_THRESHOLD   = 15       # distinct ports hit by one IP
PRIV_ESC_THRESHOLD    = 3        # sudo denials before alerting


# ── helpers ───────────────────────────────────────────────────────────────────

def _group(entries: list[LogEntry], key) -> dict:
    groups: dict = defaultdict(list)
    for e in entries:
        groups[key(e)].append(e)
    return dict(groups)


def _window_bursts(
    events: list[LogEntry],
    threshold: int,
    window: timedelta,
) -> list[list[LogEntry]]:
    """Return runs of events where ≥threshold happen within a sliding window."""
    if len(events) < threshold:
        return []
    sorted_ev = sorted(events, key=lambda e: e.timestamp)
    bursts = []
    i = 0
    while i < len(sorted_ev):
        j = i
        while j < len(sorted_ev) and (sorted_ev[j].timestamp - sorted_ev[i].timestamp) <= window:
            j += 1
        if j - i >= threshold:
            bursts.append(sorted_ev[i:j])
            i = j
        else:
            i += 1
    return bursts


# ── rule 1: brute force ───────────────────────────────────────────────────────

def detect_brute_force(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    failed = [e for e in entries if e.event_type in ("failed_login", "invalid_user", "auth_failure")]
    by_ip = _group(failed, lambda e: e.source_ip)

    for ip, events in by_ip.items():
        if ip is None:
            continue
        bursts = _window_bursts(events, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW)
        for burst in bursts:
            usernames = {e.username for e in burst if e.username}
            alerts.append(Alert(
                rule="BRUTE_FORCE",
                severity=Severity.HIGH,
                description=(
                    f"{len(burst)} failed login attempts from {ip} "
                    f"in {BRUTE_FORCE_WINDOW.seconds // 60} minutes"
                ),
                source_ip=ip,
                username=", ".join(usernames) if usernames else None,
                count=len(burst),
                first_seen=burst[0].timestamp,
                last_seen=burst[-1].timestamp,
                evidence=[e.raw[:120] for e in burst[:5]],
            ))
    return alerts


# ── rule 2: successful login after failures ───────────────────────────────────

def detect_login_after_failures(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    by_ip = _group(entries, lambda e: e.source_ip)

    for ip, events in by_ip.items():
        if ip is None:
            continue
        sorted_ev = sorted(events, key=lambda e: e.timestamp)
        failure_window: list[LogEntry] = []

        for ev in sorted_ev:
            # Expire old failures outside the window
            if failure_window:
                failure_window = [
                    f for f in failure_window
                    if (ev.timestamp - f.timestamp) <= BRUTE_FORCE_WINDOW
                ]

            if ev.event_type in ("failed_login", "invalid_user", "auth_failure"):
                failure_window.append(ev)
            elif ev.event_type == "successful_login" and len(failure_window) >= BRUTE_FORCE_THRESHOLD:
                alerts.append(Alert(
                    rule="SUCCESS_AFTER_BRUTE",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Successful login from {ip} after "
                        f"{len(failure_window)} failures — possible compromise"
                    ),
                    source_ip=ip,
                    username=ev.username,
                    count=len(failure_window) + 1,
                    first_seen=failure_window[0].timestamp,
                    last_seen=ev.timestamp,
                    evidence=[e.raw[:120] for e in failure_window[:3]] + [ev.raw[:120]],
                ))
                failure_window = []

    return alerts


# ── rule 3: port scan (HTTP logs) ─────────────────────────────────────────────

def detect_port_scan_patterns(entries: list[LogEntry]) -> list[Alert]:
    """
    In HTTP logs, rapid scanning shows up as many distinct paths hit by one IP
    in a short time, often with 404s. This is a heuristic approximation.
    """
    alerts = []
    scan_candidates = [
        e for e in entries
        if e.event_type in ("auth_failure", "request", "path_traversal", "sql_injection_attempt")
    ]
    by_ip = _group(scan_candidates, lambda e: e.source_ip)

    for ip, events in by_ip.items():
        if ip is None:
            continue
        window_events = _window_bursts(events, PORT_SCAN_THRESHOLD, timedelta(minutes=2))
        for burst in window_events:
            paths = {e.message for e in burst}
            if len(paths) >= PORT_SCAN_THRESHOLD:
                alerts.append(Alert(
                    rule="PORT_SCAN_PATTERN",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(burst)} rapid distinct requests from {ip} — "
                        "possible scanning or enumeration"
                    ),
                    source_ip=ip,
                    username=None,
                    count=len(burst),
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    evidence=[e.raw[:120] for e in burst[:5]],
                ))
    return alerts


# ── rule 4: privilege escalation ─────────────────────────────────────────────

def detect_privilege_escalation(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    sudo_denied = [e for e in entries if e.event_type == "sudo_denied"]
    by_user = _group(sudo_denied, lambda e: e.username)

    for user, events in by_user.items():
        if user is None:
            continue
        bursts = _window_bursts(events, PRIV_ESC_THRESHOLD, timedelta(hours=1))
        for burst in bursts:
            alerts.append(Alert(
                rule="PRIV_ESC_ATTEMPT",
                severity=Severity.HIGH,
                description=(
                    f"User '{user}' had {len(burst)} sudo denials — "
                    "possible privilege escalation attempt"
                ),
                source_ip=burst[0].source_ip,
                username=user,
                count=len(burst),
                first_seen=burst[0].timestamp,
                last_seen=burst[-1].timestamp,
                evidence=[e.raw[:120] for e in burst[:5]],
            ))

    # Also flag any sudo success immediately after denials
    sudo_success = [e for e in entries if e.event_type == "sudo_success"]
    denied_users = {e.username for e in sudo_denied}
    for ev in sudo_success:
        if ev.username in denied_users:
            alerts.append(Alert(
                rule="PRIV_ESC_SUCCESS",
                severity=Severity.CRITICAL,
                description=(
                    f"User '{ev.username}' achieved sudo after prior denials"
                ),
                source_ip=ev.source_ip,
                username=ev.username,
                count=1,
                first_seen=ev.timestamp,
                last_seen=ev.timestamp,
                evidence=[ev.raw[:120]],
            ))
    return alerts


# ── rule 5: credential stuffing (password spray) ─────────────────────────────

def detect_password_spray(entries: list[LogEntry]) -> list[Alert]:
    """One IP targeting many different usernames = spray attack."""
    alerts = []
    failed = [e for e in entries if e.event_type in ("failed_login", "invalid_user")]
    by_ip = _group(failed, lambda e: e.source_ip)

    for ip, events in by_ip.items():
        if ip is None:
            continue
        bursts = _window_bursts(events, SPRAY_THRESHOLD, BRUTE_FORCE_WINDOW)
        for burst in bursts:
            usernames = {e.username for e in burst if e.username}
            if len(usernames) >= SPRAY_THRESHOLD:
                alerts.append(Alert(
                    rule="PASSWORD_SPRAY",
                    severity=Severity.HIGH,
                    description=(
                        f"{ip} targeted {len(usernames)} distinct usernames — "
                        "possible password spray attack"
                    ),
                    source_ip=ip,
                    username=", ".join(sorted(usernames)),
                    count=len(burst),
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    evidence=[e.raw[:120] for e in burst[:5]],
                ))
    return alerts


# ── dispatcher ────────────────────────────────────────────────────────────────

ALL_RULES = [
    detect_brute_force,
    detect_login_after_failures,
    detect_port_scan_patterns,
    detect_privilege_escalation,
    detect_password_spray,
]


def run_all(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    for rule_fn in ALL_RULES:
        alerts.extend(rule_fn(entries))
    # Sort by severity then time
    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                 Severity.LOW: 3, Severity.INFO: 4}
    alerts.sort(key=lambda a: (sev_order.get(a.severity, 9), a.last_seen), reverse=False)
    return alerts