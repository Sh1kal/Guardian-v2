"""
Investigation module: handles Kuiper integration and case data export.

Kuiper integration supports two modes:
  1. Export ZIP  – packages CSVs + analysis results into a ZIP the analyst
                   can manually import into Kuiper.
  2. Push to Kuiper – directly creates a case in Kuiper via its REST API
                      and uploads the CSV timelines so they are immediately
                      available for investigation.

Kuiper REST API flow (dfirkuiper/kuiper v2):
  POST /api/v1/cases               → create case, returns case_id
  POST /api/v1/cases/{id}/machines → create machine entry, returns machine_id
  POST /api/v1/cases/{id}/machines/{mid}/artifact/upload
                                   → multipart upload of a timeline CSV
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

        # Add raw JSONL artifacts.
        # Fennec extracts into a nested subdirectory
        # (e.g. extracted/hostname_20231001/process_list.jsonl), so we must
        # walk the tree rather than just listing the top-level directory.
        extract_dir = os.path.join(case_dir, "extracted")
        if os.path.isdir(extract_dir):
            for root, _dirs, files in os.walk(extract_dir):
                for fname in files:
                    if not fname.endswith(".jsonl"):
                        continue
                    fpath = os.path.join(root, fname)
                    # Skip very large files (e.g. file_list.jsonl)
                    if os.path.getsize(fpath) >= 10 * 1024 * 1024:
                        continue
                    zf.write(fpath, f"artifacts/{fname}")

    logger.info(f"Case export created: {export_path}")
    return export_path


def push_to_kuiper(case_dir: str, case_id: str, case_name: str) -> dict:
    """
    Push case data directly to Kuiper via its REST API.

    Creates a Kuiper case, registers the machine name, then uploads every
    CSV timeline file.  Returns a result dict with keys:
      success     – bool
      kuiper_case_id – str (Kuiper's internal case id, on success)
      uploaded    – list of uploaded filenames
      error       – str (on failure)
    """
    api_base = config.KUIPER_API_URL
    csv_dir = os.path.join(case_dir, "csv")

    if not os.path.isdir(csv_dir):
        return {"success": False, "error": "No CSV files found – run Generate CSV first"}

    csv_files = [
        os.path.join(csv_dir, f)
        for f in os.listdir(csv_dir)
        if f.endswith(".csv") and os.path.isfile(os.path.join(csv_dir, f))
    ]
    if not csv_files:
        return {"success": False, "error": "CSV directory is empty – run Generate CSV first"}

    # ── Step 1: Create Kuiper case ────────────────────────────────────
    try:
        resp = requests.post(
            f"{api_base}/cases",
            json={"case_name": case_name, "description": f"Imported from Guardian case {case_id}"},
            timeout=15,
        )
        resp.raise_for_status()
        resp_json = resp.json()
    except requests.ConnectionError:
        return {"success": False, "error": f"Cannot connect to Kuiper at {api_base}"}
    except requests.Timeout:
        return {"success": False, "error": "Kuiper request timed out while creating case"}
    except Exception as e:
        return {"success": False, "error": f"Failed to create Kuiper case: {e}"}

    # Kuiper API returns the new case id under various key names depending on version
    kuiper_case_id = (
        resp_json.get("case_id")
        or resp_json.get("id")
        or resp_json.get("_id")
        or resp_json.get("data", {}).get("case_id")
    )
    if not kuiper_case_id:
        return {
            "success": False,
            "error": f"Kuiper did not return a case id. Response: {resp_json}",
        }

    logger.info(f"Kuiper case created: {kuiper_case_id} for Guardian case {case_id}")

    # ── Step 2: Register machine ──────────────────────────────────────
    machine_name = case_name or case_id
    try:
        resp = requests.post(
            f"{api_base}/cases/{kuiper_case_id}/machines",
            json={"machine_name": machine_name, "tags": ["guardian", "fennec"]},
            timeout=15,
        )
        resp.raise_for_status()
        machine_json = resp.json()
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to register machine in Kuiper: {e}",
            "kuiper_case_id": kuiper_case_id,
        }

    machine_id = (
        machine_json.get("machine_id")
        or machine_json.get("id")
        or machine_json.get("_id")
        or machine_json.get("data", {}).get("machine_id")
    )
    if not machine_id:
        return {
            "success": False,
            "error": f"Kuiper did not return a machine id. Response: {machine_json}",
            "kuiper_case_id": kuiper_case_id,
        }

    logger.info(f"Kuiper machine registered: {machine_id}")

    # ── Step 3: Upload CSV timelines ──────────────────────────────────
    uploaded = []
    errors = []
    for csv_path in csv_files:
        fname = os.path.basename(csv_path)
        try:
            with open(csv_path, "rb") as fh:
                resp = requests.post(
                    f"{api_base}/cases/{kuiper_case_id}/machines/{machine_id}/artifact/upload",
                    files={"file": (fname, fh, "text/csv")},
                    timeout=120,
                )
            resp.raise_for_status()
            uploaded.append(fname)
            logger.info(f"Uploaded {fname} to Kuiper")
        except Exception as e:
            errors.append(f"{fname}: {e}")
            logger.warning(f"Failed to upload {fname} to Kuiper: {e}")

    if errors and not uploaded:
        return {
            "success": False,
            "error": f"All uploads failed: {'; '.join(errors)}",
            "kuiper_case_id": kuiper_case_id,
        }

    return {
        "success": True,
        "kuiper_case_id": kuiper_case_id,
        "machine_id": machine_id,
        "uploaded": uploaded,
        "errors": errors,
        "kuiper_url": f"{config.KUIPER_URL}",
    }


def get_kuiper_url() -> str:
    """Return the configured Kuiper URL."""
    return config.KUIPER_URL
