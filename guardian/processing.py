"""
Processing module: generates CSV timelines from Fennec JSONL artifacts.
Converts raw JSONL files into structured, sortable CSV timelines.
"""

import os
import csv
import json
import logging
from datetime import datetime

from . import config

logger = logging.getLogger("guardian.processing")


class ProcessingError(Exception):
    """Raised when CSV generation fails."""
    pass


# Priority fields for timeline ordering
TIMESTAMP_FIELDS = ["@timestamp", "timestamp", "time", "start_time", "SystemTime"]


def find_timestamp(record: dict) -> str:
    """
    Extract the best timestamp from a record.
    Fennec typically uses '@timestamp'.
    """
    for field in TIMESTAMP_FIELDS:
        if field in record and record[field]:
            return str(record[field])
    return ""


def parse_jsonl_file(filepath: str) -> list:
    """
    Parse a JSONL file and return list of dicts.
    Skips empty lines and malformed JSON.
    """
    records = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        records.append(record)
                except json.JSONDecodeError:
                    logger.debug(f"Skipping malformed JSON at {filepath}:{line_num}")
    except Exception as e:
        logger.warning(f"Error reading {filepath}: {e}")
    return records


def flatten_record(record: dict, prefix: str = "") -> dict:
    """
    Flatten a nested dict into a single-level dict with dot-notation keys.
    """
    flat = {}
    for key, value in record.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(flatten_record(value, full_key))
        elif isinstance(value, list):
            flat[full_key] = str(value)
        else:
            flat[full_key] = value
    return flat


def generate_unified_timeline(case_dir: str, artifacts: dict) -> str:
    """
    Generate a unified timeline CSV from all JSONL artifacts.
    Each row has: timestamp, source_file, category, key_data, full_json
    
    Returns path to the generated CSV.
    """
    csv_dir = os.path.join(case_dir, "csv")
    os.makedirs(csv_dir, exist_ok=True)
    output_path = os.path.join(csv_dir, "unified_timeline.csv")

    timeline_rows = []

    for category, files in artifacts.items():
        if category == "system_logs":
            continue  # Log files are not JSONL, skip for timeline

        for file_info in files:
            filepath = file_info.get("path", "")
            filename = file_info.get("filename", "")

            if not filepath or not os.path.isfile(filepath):
                continue
            if not filename.endswith(".jsonl"):
                continue

            records = parse_jsonl_file(filepath)

            for record in records:
                timestamp = find_timestamp(record)
                
                # Build a human-readable summary from key fields
                summary_parts = []
                for key in ["name", "cmdline", "path", "address", "hostname",
                            "username", "command", "source", "destination",
                            "local_address", "remote_address", "description"]:
                    if key in record and record[key]:
                        val = str(record[key])
                        if len(val) > 120:
                            val = val[:120] + "..."
                        summary_parts.append(f"{key}={val}")

                summary = "; ".join(summary_parts[:5]) if summary_parts else str(record)[:200]

                timeline_rows.append({
                    "timestamp": timestamp,
                    "source": filename,
                    "category": category,
                    "summary": summary,
                    "raw_json": json.dumps(record, default=str),
                })

    # Sort by timestamp
    timeline_rows.sort(key=lambda r: r["timestamp"] if r["timestamp"] else "0")

    # Write CSV
    if timeline_rows:
        fieldnames = ["timestamp", "source", "category", "summary", "raw_json"]
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(timeline_rows)
        logger.info(f"Generated unified timeline: {len(timeline_rows)} rows → {output_path}")
    else:
        # Write empty CSV with headers
        fieldnames = ["timestamp", "source", "category", "summary", "raw_json"]
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
        logger.warning("No timeline data found in artifacts")

    return output_path


def generate_per_artifact_csvs(case_dir: str, artifacts: dict) -> list:
    """
    Generate individual CSV files for each artifact type.
    Each JSONL file gets its own CSV with flattened columns.
    
    Returns list of generated CSV paths.
    """
    csv_dir = os.path.join(case_dir, "csv")
    os.makedirs(csv_dir, exist_ok=True)
    generated = []

    for category, files in artifacts.items():
        if category == "system_logs":
            continue

        for file_info in files:
            filepath = file_info.get("path", "")
            filename = file_info.get("filename", "")

            if not filepath or not os.path.isfile(filepath):
                continue
            if not filename.endswith(".jsonl"):
                continue

            records = parse_jsonl_file(filepath)
            if not records:
                continue

            # Flatten all records and collect all keys
            flat_records = [flatten_record(r) for r in records]
            all_keys = set()
            for fr in flat_records:
                all_keys.update(fr.keys())

            # Sort keys for consistent output, put timestamp first
            sorted_keys = sorted(all_keys)
            for ts_field in reversed(TIMESTAMP_FIELDS):
                if ts_field in sorted_keys:
                    sorted_keys.remove(ts_field)
                    sorted_keys.insert(0, ts_field)

            # Write CSV
            csv_filename = filename.replace(".jsonl", ".csv")
            csv_path = os.path.join(csv_dir, csv_filename)

            with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=sorted_keys, extrasaction="ignore")
                writer.writeheader()
                for fr in flat_records:
                    writer.writerow(fr)

            generated.append({
                "filename": csv_filename,
                "path": csv_path,
                "source": filename,
                "category": category,
                "row_count": len(flat_records),
            })
            logger.info(f"Generated {csv_filename}: {len(flat_records)} rows")

    return generated


def generate_all_csvs(case_dir: str, artifacts: dict) -> dict:
    """
    Run full CSV generation: unified timeline + per-artifact CSVs.
    Returns results dict with paths and stats.
    """
    try:
        timeline_path = generate_unified_timeline(case_dir, artifacts)
        per_artifact = generate_per_artifact_csvs(case_dir, artifacts)

        # Count total rows in timeline
        timeline_rows = 0
        if os.path.isfile(timeline_path):
            with open(timeline_path, "r") as f:
                timeline_rows = sum(1 for _ in f) - 1  # subtract header

        return {
            "success": True,
            "timeline_path": timeline_path,
            "timeline_rows": timeline_rows,
            "per_artifact_csvs": per_artifact,
            "total_csvs": len(per_artifact) + 1,
        }
    except Exception as e:
        logger.error(f"CSV generation failed: {e}")
        raise ProcessingError(f"CSV generation failed: {e}")
