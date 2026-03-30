"""
Parsers for each supported log format.
Each parser is a generator that yields LogEntry objects.
"""
import csv
import io
import re
import xml.etree.ElementTree as ET
from collections.abc import Generator
from datetime import datetime

from models import LogEntry, LogFormat

# ── helpers ──────────────────────────────────────────────────────────────────

_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}

_CURRENT_YEAR = datetime.now().year


def _syslog_ts(month: str, day: str, time_str: str) -> datetime:
    """Parse syslog-style timestamp (no year)."""
    m = _MONTHS.get(month, 1)
    d = int(day)
    h, mi, s = (int(x) for x in time_str.split(":"))
    return datetime(_CURRENT_YEAR, m, d, h, mi, s)


def _apache_ts(raw: str) -> datetime:
    """Parse Apache/Nginx combined log timestamp: 10/Oct/2024:13:55:36 -0700"""
    try:
        return datetime.strptime(raw[:20], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return datetime.now()


# ── auth.log ─────────────────────────────────────────────────────────────────

_AUTH_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+):\s+(?P<msg>.+)"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(
    r"(?:for(?: invalid user)?|user)\s+(\S+)|"
    r"USER=(\S+)|"
    r"for user (\S+)"
)


def _classify_auth(msg: str, proc: str = "") -> str:
    msg_l = msg.lower()
    proc_l = proc.lower()
    is_sudo = "sudo" in proc_l or "sudo" in msg_l
    if "failed password" in msg_l or "authentication failure" in msg_l:
        return "failed_login"
    if "accepted password" in msg_l or "accepted publickey" in msg_l:
        return "successful_login"
    if "invalid user" in msg_l:
        return "invalid_user"
    if is_sudo and "command not allowed" in msg_l:
        return "sudo_denied"
    if is_sudo and ("; TTY=" in msg or "session opened" in msg_l):
        return "sudo_success"
    if "connection closed" in msg_l or "disconnected" in msg_l:
        return "disconnect"
    return "other"


def parse_auth(text: str) -> Generator[LogEntry, None, None]:
    for raw in text.splitlines():
        m = _AUTH_RE.match(raw)
        if not m:
            continue
        ts = _syslog_ts(m["month"], m["day"], m["time"])
        msg = m["msg"]
        ip_m = _IP_RE.search(msg)
        user_m = _USER_RE.search(msg)
        ip = ip_m.group(0) if ip_m else None
        user = next((g for g in (user_m.groups() if user_m else []) if g), None)
        yield LogEntry(
            timestamp=ts,
            source_ip=ip,
            username=user,
            event_type=_classify_auth(msg, m["proc"]),
            message=msg,
            raw=raw,
            log_format=LogFormat.AUTH,
        )


# ── generic syslog ────────────────────────────────────────────────────────────

_SYSLOG_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:]+):\s+(?P<msg>.+)"
)


def parse_syslog(text: str) -> Generator[LogEntry, None, None]:
    for raw in text.splitlines():
        m = _SYSLOG_RE.match(raw)
        if not m:
            continue
        ts = _syslog_ts(m["month"], m["day"], m["time"])
        msg = m["msg"]
        ip_m = _IP_RE.search(msg)
        yield LogEntry(
            timestamp=ts,
            source_ip=ip_m.group(0) if ip_m else None,
            username=None,
            event_type="syslog",
            message=msg,
            raw=raw,
            log_format=LogFormat.SYSLOG,
        )


# ── Apache / Nginx combined log ───────────────────────────────────────────────

_COMBINED_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)


def _classify_http(status: int, path: str, method: str) -> str:
    if status == 401 or status == 403:
        return "auth_failure"
    if status >= 500:
        return "server_error"
    if method in ("POST", "PUT", "DELETE") and status < 400:
        return "write_request"
    p = path.lower()
    if any(k in p for k in ["..", "etc/passwd", "cmd=", "exec(", "../"]):
        return "path_traversal"
    if any(k in p for k in ["select ", "union ", "drop ", "' or ", "--"]):
        return "sql_injection_attempt"
    return "request"


def parse_apache(text: str) -> Generator[LogEntry, None, None]:
    for raw in text.splitlines():
        m = _COMBINED_RE.match(raw)
        if not m:
            continue
        ts = _apache_ts(m["ts"])
        status = int(m["status"])
        path = m["path"]
        method = m["method"]
        yield LogEntry(
            timestamp=ts,
            source_ip=m["ip"],
            username=None,
            event_type=_classify_http(status, path, method),
            message=f'{method} {path} -> {status}',
            raw=raw,
            log_format=LogFormat.APACHE,
        )


# ── Windows Event Log XML ─────────────────────────────────────────────────────

_WIN_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

_WIN_EVENT_TYPES = {
    4625: "failed_login",
    4624: "successful_login",
    4648: "explicit_credential_logon",
    4720: "account_created",
    4728: "group_member_added",
    4732: "group_member_added",
    4740: "account_locked",
    4756: "group_member_added",
    4771: "kerberos_failure",
    4776: "ntlm_auth_attempt",
}


def _win_data(event: ET.Element, name: str) -> str | None:
    el = event.find(f'.//e:Data[@Name="{name}"]', _WIN_NS)
    return el.text if el is not None else None


def parse_windows_xml(text: str) -> Generator[LogEntry, None, None]:
    try:
        root = ET.fromstring(f"<root>{text}</root>")
    except ET.ParseError:
        return

    for event in root.findall(".//e:Event", _WIN_NS) or root.findall(".//Event"):
        try:
            sys_el = event.find("e:System", _WIN_NS) or event.find("System")
            if sys_el is None:
                continue

            event_id_el = sys_el.find("e:EventID", _WIN_NS) or sys_el.find("EventID")
            ts_el = sys_el.find("e:TimeCreated", _WIN_NS) or sys_el.find("TimeCreated")
            if event_id_el is None or ts_el is None:
                continue

            event_id = int(event_id_el.text or 0)
            ts_raw = ts_el.get("SystemTime", "")
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                ts = datetime.now()

            ip = _win_data(event, "IpAddress") or _win_data(event, "WorkstationName")
            user = _win_data(event, "TargetUserName") or _win_data(event, "SubjectUserName")
            event_type = _WIN_EVENT_TYPES.get(event_id, f"event_{event_id}")

            yield LogEntry(
                timestamp=ts,
                source_ip=ip if ip and ip not in ("-", "::1", "127.0.0.1") else None,
                username=user,
                event_type=event_type,
                message=f"EventID {event_id}: {event_type}",
                raw=ET.tostring(event, encoding="unicode")[:200],
                log_format=LogFormat.WINDOWS_XML,
            )
        except (ValueError, AttributeError):
            continue


# ── Windows Event Log CSV ─────────────────────────────────────────────────────

def parse_windows_csv(text: str) -> Generator[LogEntry, None, None]:
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        try:
            ts_raw = row.get("TimeCreated", row.get("Date and Time", ""))
            try:
                ts = datetime.strptime(ts_raw[:19], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                ts = datetime.now()

            event_id = int(row.get("Id", row.get("EventID", 0)) or 0)
            msg = row.get("Message", row.get("Task Category", ""))
            ip_m = _IP_RE.search(msg)
            event_type = _WIN_EVENT_TYPES.get(event_id, f"event_{event_id}")

            yield LogEntry(
                timestamp=ts,
                source_ip=ip_m.group(0) if ip_m else None,
                username=row.get("User", None),
                event_type=event_type,
                message=msg[:200],
                raw=str(row)[:200],
                log_format=LogFormat.WINDOWS_CSV,
            )
        except (ValueError, KeyError):
            continue


# ── dispatcher ────────────────────────────────────────────────────────────────

def parse(text: str, fmt: LogFormat) -> list[LogEntry]:
    dispatch = {
        LogFormat.AUTH: parse_auth,
        LogFormat.SYSLOG: parse_syslog,
        LogFormat.APACHE: parse_apache,
        LogFormat.NGINX: parse_apache,
        LogFormat.WINDOWS_XML: parse_windows_xml,
        LogFormat.WINDOWS_CSV: parse_windows_csv,
    }
    fn = dispatch.get(fmt)
    if fn is None:
        return []
    return list(fn(text))