import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from detector import detect_format
from models import LogFormat, Severity
from parsers import parse
from rules import run_all

st.set_page_config(
    page_title="Log Analyzer",
    page_icon="🔍",
    layout="wide",
)

SEV_COLOR = {
    "CRITICAL": "#E24B4A",
    "HIGH":     "#EF9F27",
    "MEDIUM":   "#378ADD",
    "LOW":      "#1D9E75",
    "INFO":     "#888780",
}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

st.title("Log Analyzer")
st.caption("Upload a log file to detect threats — brute force, privilege escalation, password spray, and more.")

# ── sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("Settings")
    force_format = st.selectbox(
        "Log format",
        options=["Auto-detect"] + [f.value for f in LogFormat if f != LogFormat.UNKNOWN],
    )
    min_sev = st.select_slider(
        "Minimum severity",
        options=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        value="LOW",
    )
    st.divider()
    st.subheader("Sample logs")
    sample_dir = Path(__file__).parent / "sample_logs"
    sample_files = list(sample_dir.glob("*")) if sample_dir.exists() else []
    if sample_files:
        selected_sample = st.selectbox(
            "Load a sample",
            options=["— none —"] + [f.name for f in sample_files],
        )
    else:
        selected_sample = "— none —"
    st.divider()
    st.markdown("**Detected threats**")
    st.markdown("""
- Brute force login  
- Success after brute force  
- Password spray  
- Privilege escalation (sudo)  
- HTTP scanning / enumeration  
""")

# ── file input ────────────────────────────────────────────────────────────────

uploaded = st.file_uploader(
    "Upload log file",
    type=["log", "txt", "xml", "csv"],
    label_visibility="collapsed",
)

log_text: str | None = None
log_name = ""

if uploaded:
    log_text = uploaded.read().decode(errors="replace")
    log_name = uploaded.name
elif selected_sample != "— none —":
    sample_path = sample_dir / selected_sample
    log_text = sample_path.read_text(errors="replace")
    log_name = selected_sample

if not log_text:
    st.info("Upload a log file above, or choose a sample from the sidebar.")
    st.stop()

# ── parse + detect ────────────────────────────────────────────────────────────

with st.spinner("Parsing and analysing..."):
    if force_format == "Auto-detect":
        with tempfile.NamedTemporaryFile(suffix=f"_{log_name}", delete=False) as tmp:
            tmp.write(log_text.encode())
            tmp_path = Path(tmp.name)
        fmt = detect_format(tmp_path)
        tmp_path.unlink(missing_ok=True)
    else:
        fmt = LogFormat(force_format)

    if fmt == LogFormat.UNKNOWN:
        st.error("Could not detect log format. Try selecting one manually in the sidebar.")
        st.stop()

    entries = parse(log_text, fmt)
    all_alerts = run_all(entries)

min_order = SEV_ORDER[min_sev]
alerts = [a for a in all_alerts if SEV_ORDER.get(a.severity.value, 9) <= min_order]

# ── summary metrics ───────────────────────────────────────────────────────────

st.divider()
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Log entries", f"{len(entries):,}")
col2.metric("Total alerts", len(alerts))
for sev, col in zip(["CRITICAL", "HIGH", "MEDIUM"], [col3, col4, col5]):
    n = sum(1 for a in alerts if a.severity.value == sev)
    col.metric(sev.title(), n, delta=None)

# ── alerts table ──────────────────────────────────────────────────────────────

st.divider()
st.subheader("Alerts")

if not alerts:
    st.success("No threats detected above the selected severity threshold.")
else:
    for alert in alerts:
        c = SEV_COLOR.get(alert.severity.value, "#888")
        with st.expander(
            f"**{alert.severity.value}** — {alert.rule} — {alert.description[:80]}",
            expanded=alert.severity.value in ("CRITICAL", "HIGH"),
        ):
            dcol1, dcol2 = st.columns(2)
            with dcol1:
                st.markdown(f"**Rule:** `{alert.rule}`")
                st.markdown(f"**Severity:** :{alert.severity.value.lower()}[{alert.severity.value}]")
                st.markdown(f"**Source IP:** `{alert.source_ip or '—'}`")
                st.markdown(f"**Username:** `{alert.username or '—'}`")
            with dcol2:
                st.markdown(f"**Event count:** {alert.count}")
                st.markdown(f"**First seen:** {alert.first_seen}")
                st.markdown(f"**Last seen:** {alert.last_seen}")

            if alert.evidence:
                st.markdown("**Evidence (first 5 lines):**")
                st.code("\n".join(alert.evidence[:5]), language="text")

# ── timeline chart ────────────────────────────────────────────────────────────

if entries:
    st.divider()
    st.subheader("Event timeline")
    df = pd.DataFrame([
        {"timestamp": e.timestamp, "event_type": e.event_type}
        for e in entries
    ])
    df["minute"] = df["timestamp"].dt.floor("min")
    timeline = df.groupby(["minute", "event_type"]).size().reset_index(name="count")
    pivot = timeline.pivot(index="minute", columns="event_type", values="count").fillna(0)
    st.area_chart(pivot, use_container_width=True)

# ── top offenders ─────────────────────────────────────────────────────────────

if alerts:
    st.divider()
    st.subheader("Top offending IPs")
    from collections import Counter
    ip_counts = Counter(a.source_ip for a in alerts if a.source_ip)
    if ip_counts:
        ip_df = pd.DataFrame(ip_counts.most_common(10), columns=["IP", "Alert count"])
        st.bar_chart(ip_df.set_index("IP"))

# ── raw log preview ───────────────────────────────────────────────────────────

with st.expander("Raw log preview (first 100 lines)"):
    preview = "\n".join(log_text.splitlines()[:100])
    st.code(preview, language="text")

# ── export ────────────────────────────────────────────────────────────────────

if alerts:
    st.divider()
    import json
    json_out = json.dumps([a.to_dict() for a in alerts], indent=2, default=str)
    st.download_button(
        label="Export alerts as JSON",
        data=json_out,
        file_name="alerts.json",
        mime="application/json",
    )