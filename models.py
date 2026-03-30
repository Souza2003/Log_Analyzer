from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class LogFormat(str, Enum):
    AUTH = "auth"
    SYSLOG = "syslog"
    APACHE = "apache"
    NGINX = "nginx"
    WINDOWS_XML = "windows_xml"
    WINDOWS_CSV = "windows_csv"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class LogEntry:
    timestamp: datetime
    source_ip: str | None
    username: str | None
    event_type: str
    message: str
    raw: str
    log_format: LogFormat = LogFormat.UNKNOWN


@dataclass
class Alert:
    rule: str
    severity: Severity
    description: str
    source_ip: str | None
    username: str | None
    count: int
    first_seen: datetime
    last_seen: datetime
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "description": self.description,
            "source_ip": self.source_ip,
            "username": self.username,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "evidence": self.evidence[:5],
        }