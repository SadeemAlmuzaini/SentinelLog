"""
CyberSight AI - validators.py
Schema validation and row-level normalization for uploaded firewall CSV logs.

Design goals (per project spec):
- Recognize supported column names with reasonable case/whitespace tolerance.
- Map equivalent column names only when their meaning is unambiguous.
- Report missing required columns explicitly (fail fast, no silent guessing).
- Validate each row independently; keep invalid rows out of the dataset
  but keep a count + reason instead of silently dropping them.
- Never fabricate a value that wasn't in the source data.
- Never silently coerce an unrecognized Action value into ALLOW or BLOCK.
"""

import ipaddress
import re
from datetime import datetime

# Canonical schema this app understands.
REQUIRED_COLUMNS = [
    "Timestamp", "Source_IP", "Destination_IP",
    "Source_Port", "Destination_Port",
    "Protocol", "Action", "Country", "Bytes",
]

# Only columns whose meaning is unambiguous are auto-mapped.
# Keys are lowercase/underscored aliases -> canonical column name.
COLUMN_ALIASES = {
    "timestamp": "Timestamp", "time": "Timestamp", "datetime": "Timestamp",
    "date_time": "Timestamp", "event_time": "Timestamp",

    "source_ip": "Source_IP", "src_ip": "Source_IP", "srcip": "Source_IP",
    "source": "Source_IP",

    "destination_ip": "Destination_IP", "dest_ip": "Destination_IP",
    "dst_ip": "Destination_IP", "destination": "Destination_IP",

    "source_port": "Source_Port", "src_port": "Source_Port", "sport": "Source_Port",

    "destination_port": "Destination_Port", "dest_port": "Destination_Port",
    "dst_port": "Destination_Port", "dport": "Destination_Port", "port": "Destination_Port",

    "protocol": "Protocol", "proto": "Protocol",

    "action": "Action", "verdict": "Action", "decision": "Action", "result": "Action",

    "country": "Country", "src_country": "Country", "source_country": "Country",
    "geo": "Country", "geo_country": "Country",

    "bytes": "Bytes", "byte_count": "Bytes", "traffic_bytes": "Bytes", "size": "Bytes",
}

ALLOW_VALUES = {"ALLOW", "ALLOWED", "PERMIT", "PERMITTED", "ACCEPT", "ACCEPTED"}
BLOCK_VALUES = {"BLOCK", "BLOCKED", "DENY", "DENIED", "DROP", "DROPPED", "REJECT", "REJECTED"}

VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}

_PORT_RE = re.compile(r"^\d+$")


def _normalize_header(raw_header):
    h = raw_header.strip().lower()
    h = re.sub(r"[\s\-]+", "_", h)
    h = re.sub(r"[^a-z0-9_]", "", h)
    return h


def resolve_schema(raw_headers):
    mapping = {}
    unmapped = []

    for raw in raw_headers:
        norm = _normalize_header(raw)
        canonical = COLUMN_ALIASES.get(norm)
        if canonical is None and raw.strip() in REQUIRED_COLUMNS:
            canonical = raw.strip()
        if canonical:
            mapping.setdefault(canonical, raw)
        else:
            unmapped.append(raw)

    missing = [c for c in REQUIRED_COLUMNS if c not in mapping]
    return mapping, missing, unmapped


def validate_row(row, mapping, row_number):
    def get(canonical):
        raw_key = mapping.get(canonical)
        if raw_key is None:
            return ""
        return (row.get(raw_key) or "").strip()

    errors = []

    ts_raw = get("Timestamp")
    ts_parsed = None
    if ts_raw:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                ts_parsed = datetime.strptime(ts_raw, fmt)
                break
            except ValueError:
                continue
        if ts_parsed is None:
            errors.append("invalid Timestamp")

    src_ip = get("Source_IP")
    dst_ip = get("Destination_IP")
    for label, value in (("Source_IP", src_ip), ("Destination_IP", dst_ip)):
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                errors.append(f"invalid {label} '{value}'")

    src_port_raw = get("Source_Port")
    dst_port_raw = get("Destination_Port")
    dst_port = None
    if dst_port_raw:
        if _PORT_RE.match(dst_port_raw) and 0 <= int(dst_port_raw) <= 65535:
            dst_port = int(dst_port_raw)
        else:
            errors.append(f"invalid Destination_Port '{dst_port_raw}'")

    src_port = None
    if src_port_raw:
        if _PORT_RE.match(src_port_raw) and 0 <= int(src_port_raw) <= 65535:
            src_port = int(src_port_raw)
        else:
            errors.append(f"invalid Source_Port '{src_port_raw}'")

    protocol_raw = get("Protocol").upper()
    protocol = protocol_raw if protocol_raw else "UNKNOWN"

    action_raw = get("Action").upper()
    if action_raw in ALLOW_VALUES:
        action = "ALLOW"
    elif action_raw in BLOCK_VALUES:
        action = "BLOCK"
    elif action_raw == "":
        errors.append("missing Action")
        action = None
    else:
        action = "UNKNOWN"

    country = get("Country") or "Unknown"

    bytes_raw = get("Bytes")
    bytes_val = None
    if bytes_raw:
        try:
            bytes_val = int(float(bytes_raw))
            if bytes_val < 0:
                errors.append(f"negative Bytes '{bytes_raw}'")
                bytes_val = None
        except ValueError:
            errors.append(f"invalid Bytes '{bytes_raw}'")

    hard_fail = action is None or dst_port is None

    if hard_fail:
        reason = "; ".join(errors) if errors else "missing required field(s)"
        return None, f"row {row_number}: rejected ({reason})"

    clean = {
        "Timestamp": ts_parsed,
        "Timestamp_raw": ts_raw,
        "Source_IP": src_ip or None,
        "Destination_IP": dst_ip or None,
        "Source_Port": src_port,
        "Destination_Port": dst_port,
        "Protocol": protocol,
        "Action": action,
        "Country": country,
        "Bytes": bytes_val if bytes_val is not None else 0,
    }

    warning = f"row {row_number}: accepted with issue(s) ({'; '.join(errors)})" if errors else None
    return clean, warning
