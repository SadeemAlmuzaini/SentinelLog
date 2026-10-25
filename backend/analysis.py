"""
CyberSight AI - analysis.py
Core analysis engine. Pure functions, no Flask/HTTP concerns, so they can be
unit-tested directly and reused by both the API and the test suite.
"""

import csv
import io
from collections import Counter, defaultdict

from validators import resolve_schema, validate_row

MAX_ROWS = 200_000  # sanity limit; project scope doesn't need more

# Cap on how many timestamps we retain per source IP for time-window
# (burst) analysis. A source already past this many events in the dataset
# is high-volume regardless, so bounding memory here does not lose any
# detection signal in practice for this project's scope.
MAX_TIMESTAMPS_PER_SOURCE = 2000


class CSVParseError(Exception):
    """Raised for schema-level failures (missing columns, empty file, etc.)."""
    pass


def parse_and_validate_csv(file_text):
    """
    Parse raw CSV text into clean rows + a validation summary.
    """
    if file_text is None or not file_text.strip():
        raise CSVParseError("The file is empty.")

    reader = csv.DictReader(io.StringIO(file_text))
    if reader.fieldnames is None:
        raise CSVParseError("Could not read a header row from this file.")

    mapping, missing, unmapped = resolve_schema(reader.fieldnames)

    if missing:
        raise CSVParseError(
            "Missing required column(s): " + ", ".join(missing) +
            ". Recognized columns: " + ", ".join(mapping.values())
        )

    rows = []
    rejected_reasons = []
    warnings = []
    total = 0

    for i, raw_row in enumerate(reader, start=2):  # row 1 is the header
        total += 1
        if total > MAX_ROWS:
            rejected_reasons.append(f"row {i}: skipped (exceeds {MAX_ROWS} row limit)")
            continue
        clean, note = validate_row(raw_row, mapping, i)
        if clean is None:
            rejected_reasons.append(note)
        else:
            rows.append(clean)
            if note:
                warnings.append(note)

    if total == 0:
        raise CSVParseError("The file has a header but no data rows.")

    return {
        "rows": rows,
        "total_rows": total,
        "valid_rows": len(rows),
        "rejected_rows": total - len(rows),
        "rejected_reasons": rejected_reasons[:25],
        "warnings": warnings[:25],
        "unmapped_columns": unmapped,
    }


def compute_statistics(rows):
    """Build the full statistics object from a list of clean rows.

    NOTE on truncation: several "top_*" fields below are intentionally
    capped at 10 entries for compact chart/UI display. Detection logic in
    detection_engine.py MUST NOT use those capped fields to decide whether
    something is present (a high-risk port that isn't in the top 10 by
    volume would otherwise be invisible to detection). Full, uncapped
    aggregates used by detection are kept under separate keys:
    "destination_port_counts", "destination_port_action_counts",
    "source_to_ports", "dest_hit_counts", "blocked_source_ip_counts",
    "blocked_source_to_ports", and "source_ip_timestamps".
    """

    total = len(rows)
    stats = {
        "total_records": total,
        "allowed_connections": 0,
        "blocked_connections": 0,
        "unrecognized_action_count": 0,
        "unique_source_ips": set(),
        "unique_destination_ips": set(),
        "countries": set(),
        "protocols": set(),
        "destination_ports": set(),
        "total_traffic_bytes": 0,
    }

    country_dist = Counter()
    protocol_dist = Counter()
    dest_port_counts = Counter()                       # FULL, uncapped
    dest_port_action_counts = defaultdict(Counter)      # FULL: port -> {ALLOW:n, BLOCK:n}
    source_ip_counts = Counter()
    dest_ip_counts = Counter()
    blocked_source_ip_counts = Counter()
    blocked_source_to_ports = defaultdict(set)          # FULL: source -> {blocked dest ports}
    protocol_bytes = Counter()
    source_to_ports = defaultdict(set)
    dest_hit_counts = Counter()
    hourly_bytes = [0] * 6
    timestamps = []
    source_ip_timestamps = defaultdict(list)            # FULL (capped per-source): source -> [datetime]

    for r in rows:
        action = r["Action"]
        if action == "ALLOW":
            stats["allowed_connections"] += 1
        elif action == "BLOCK":
            stats["blocked_connections"] += 1
            if r["Source_IP"]:
                blocked_source_ip_counts[r["Source_IP"]] += 1
                if r["Destination_Port"] is not None:
                    blocked_source_to_ports[r["Source_IP"]].add(r["Destination_Port"])
        else:
            stats["unrecognized_action_count"] += 1

        if r["Source_IP"]:
            stats["unique_source_ips"].add(r["Source_IP"])
            source_ip_counts[r["Source_IP"]] += 1
        if r["Destination_IP"]:
            stats["unique_destination_ips"].add(r["Destination_IP"])
            dest_ip_counts[r["Destination_IP"]] += 1
            dest_hit_counts[r["Destination_IP"]] += 1

        stats["countries"].add(r["Country"])
        country_dist[r["Country"]] += 1

        stats["protocols"].add(r["Protocol"])
        protocol_dist[r["Protocol"]] += 1
        protocol_bytes[r["Protocol"]] += r["Bytes"]

        stats["destination_ports"].add(r["Destination_Port"])
        dest_port_counts[r["Destination_Port"]] += 1
        if action in ("ALLOW", "BLOCK"):
            dest_port_action_counts[r["Destination_Port"]][action] += 1

        stats["total_traffic_bytes"] += r["Bytes"]

        if r["Source_IP"] and r["Destination_Port"] is not None:
            source_to_ports[r["Source_IP"]].add(r["Destination_Port"])

        if r["Timestamp"] is not None:
            timestamps.append(r["Timestamp"])
            bucket = min(5, r["Timestamp"].hour // 4)
            hourly_bytes[bucket] += r["Bytes"]
            if r["Source_IP"]:
                bucket_list = source_ip_timestamps[r["Source_IP"]]
                if len(bucket_list) < MAX_TIMESTAMPS_PER_SOURCE:
                    bucket_list.append(r["Timestamp"])

    avg_bytes = (stats["total_traffic_bytes"] / total) if total else 0

    result = {
        "total_records": total,
        "valid_records": total,
        "allowed_connections": stats["allowed_connections"],
        "blocked_connections": stats["blocked_connections"],
        "unrecognized_action_count": stats["unrecognized_action_count"],
        "unique_source_ips": len(stats["unique_source_ips"]),
        "unique_destination_ips": len(stats["unique_destination_ips"]),
        "countries": len(stats["countries"]),
        "protocols": len(stats["protocols"]),
        "unique_destination_ports": len(stats["destination_ports"]),
        "total_traffic_bytes": stats["total_traffic_bytes"],
        "average_bytes_per_record": round(avg_bytes, 2),
        "min_timestamp": min(timestamps).isoformat() if timestamps else None,
        "max_timestamp": max(timestamps).isoformat() if timestamps else None,
        "country_distribution": dict(country_dist),
        "protocol_distribution": dict(protocol_dist),
        "protocol_bytes": dict(protocol_bytes),
        "top_destination_ports": dict(sorted(dest_port_counts.items(), key=lambda kv: -kv[1])[:10]),
        "top_source_ips": dict(sorted(source_ip_counts.items(), key=lambda kv: -kv[1])[:10]),
        "top_destination_ips": dict(sorted(dest_ip_counts.items(), key=lambda kv: -kv[1])[:10]),
        "top_blocked_source_ips": dict(sorted(blocked_source_ip_counts.items(), key=lambda kv: -kv[1])[:10]),
        "hourly_traffic_bytes": hourly_bytes,
        "has_timestamps": len(timestamps) > 0,
        "source_to_ports": {ip: sorted(ports) for ip, ports in source_to_ports.items()},
        "dest_hit_counts": dict(dest_hit_counts),
        "blocked_source_ip_counts": dict(blocked_source_ip_counts),

        # --- Full (uncapped) aggregates for detection use ---
        "destination_port_counts": dict(dest_port_counts),
        "destination_port_action_counts": {
            port: dict(counts) for port, counts in dest_port_action_counts.items()
        },
        "blocked_source_to_ports": {
            ip: sorted(ports) for ip, ports in blocked_source_to_ports.items()
        },
        "source_ip_timestamps": {
            ip: sorted(ts_list) for ip, ts_list in source_ip_timestamps.items()
        },
    }
    return result
