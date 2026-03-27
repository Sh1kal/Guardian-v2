"""
Investigation module: handles Kuiper integration and case data export.
"""

import os
import json
import zipfile
import logging
import requests

from . import config

logger = logging.getLogger("guardian.investigation")


def check_kuiper_status() -> dict:
    """
    Check if Kuiper is reachable.
    Returns status dict.
    """
    kuiper_url = config.KUIPER_URL
    try:
        resp = requests.get(kuiper_url, timeout=5)
        return {
            "available": True,
            "url": kuiper_url,
            "status_code": resp.status_code,
        }
    except requests.ConnectionError:
        return {
            "available": False,
            "url": kuiper_url,
            "error": "Connection refused",
        }
    except requests.Timeout:
        return {
            "available": False,
            "url": kuiper_url,
            "error": "Connection timed out",
        }
    except Exception as e:
        return {
            "available": False,
            "url": kuiper_url,
            "error": str(e),
        }


def export_case_for_kuiper(case_dir: str, case_id: str) -> str:
    """
    Package case data (CSVs + analysis results) into a ZIP for Kuiper import.
    Returns path to the export ZIP.
    """
    export_dir = os.path.join(case_dir, "export")
    os.makedirs(export_dir, exist_ok=True)
    export_path = os.path.join(export_dir, f"case_{case_id}_export.zip")

    with zipfile.ZipFile(export_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add CSV files
        csv_dir = os.path.join(case_dir, "csv")
        if os.path.isdir(csv_dir):
            for fname in os.listdir(csv_dir):
                fpath = os.path.join(csv_dir, fname)
                if os.path.isfile(fpath):
                    zf.write(fpath, f"csv/{fname}")

        # Add analysis results
        analysis_dir = os.path.join(case_dir, "analysis")
        if os.path.isdir(analysis_dir):
            for fname in os.listdir(analysis_dir):
                fpath = os.path.join(analysis_dir, fname)
                if os.path.isfile(fpath) and fname.endswith((".json", ".log")):
                    zf.write(fpath, f"analysis/{fname}")

        # Add raw JSONL artifacts (excludes huge file_list.jsonl)
        extract_dir = os.path.join(case_dir, "extracted")
        if os.path.isdir(extract_dir):
            for fname in os.listdir(extract_dir):
                fpath = os.path.join(extract_dir, fname)
                if (os.path.isfile(fpath) and fname.endswith(".jsonl")
                        and os.path.getsize(fpath) < 10 * 1024 * 1024):  # Skip files > 10MB
                    zf.write(fpath, f"artifacts/{fname}")

    logger.info(f"Case export created: {export_path}")
    return export_path


def get_kuiper_url() -> str:
    """Return the configured Kuiper URL."""
    return config.KUIPER_URL
