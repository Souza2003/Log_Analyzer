import re
from pathlib import Path
from models import LogFormat


_SIGNATURES: list[tuple[LogFormat, str]] = [
    (LogFormat.WINDOWS_XML, r"<Event\s+xmlns"),
    (LogFormat.WINDOWS_CSV, r"TimeCreated,Id,LevelDisplayName"),
    (LogFormat.APACHE,  r'\d{1,3}(\.\d{1,3}){3} - .+ \[.+\] "[A-Z]+ .+ HTTP'),
    (LogFormat.NGINX,   r'\d{1,3}(\.\d{1,3}){3} - .+ \[.+\] "[A-Z]+ .+ HTTP'),
    (LogFormat.AUTH,    r"(sshd|sudo|su|PAM)\["),
    (LogFormat.SYSLOG,  r"^\w{3}\s+\d+ \d{2}:\d{2}:\d{2} \S+ \S+\["),
]


def detect_format(path: Path) -> LogFormat:
    try:
        sample = path.read_text(errors="replace")[:4096]
    except OSError:
        return LogFormat.UNKNOWN

    for fmt, pattern in _SIGNATURES:
        if re.search(pattern, sample, re.MULTILINE):
            return fmt

    suffix = path.suffix.lower()
    if suffix == ".xml":
        return LogFormat.WINDOWS_XML
    if suffix == ".csv":
        return LogFormat.WINDOWS_CSV

    return LogFormat.UNKNOWN