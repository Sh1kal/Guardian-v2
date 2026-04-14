"""
Ingestion module: handles ZIP upload, validation, safe extraction, and Fennec artifact detection.
"""

import os
import uuid
import zipfile
import shutil
import subprocess
import logging
from datetime import datetime

from . import config

logger = logging.getLogger("guardian.ingest")


class IngestError(Exception):
    """Raised when ingestion fails."""
    pass


def validate_zip(file_path: str) -> dict:
    """
    Validate that a file is a valid ZIP and check for safety.
    Returns metadata dict with info about the ZIP contents.
    """
    if not os.path.isfile(file_path):
        raise IngestError(f"File not found: {file_path}")

    if not zipfile.is_zipfile(file_path):
        raise IngestError("Uploaded file is not a valid ZIP archive")

    # Check for path traversal attacks
    with zipfile.ZipFile(file_path, "r") as zf:
        for member in zf.namelist():
            # Reject absolute paths or parent directory references
            if member.startswith("/") or ".." in member:
                raise IngestError(
                    f"ZIP contains unsafe path: {member}"
                )

        # Gather metadata
        jsonl_files = [n for n in zf.namelist() if n.endswith(".jsonl")]
        log_files = [n for n in zf.namelist() if "logs/" in n and not n.endswith("/")]
        total_files = len(zf.namelist())

    return {
        "total_files": total_files,
        "jsonl_count": len(jsonl_files),
        "log_count": len(log_files),
        "jsonl_files": jsonl_files,
        "is_fennec": len(jsonl_files) > 0,
    }


def create_case(original_filename: str) -> dict:
    """
    Create a new case with a unique ID and directory structure.
    Returns case metadata dict.
    """
    case_id = str(uuid.uuid4())[:8]
    timestamp = datetime.utcnow().isoformat()
    case_name = os.path.splitext(original_filename)[0]

    case_dir = os.path.join(config.CASES_DIR, case_id)
    os.makedirs(os.path.join(case_dir, "upload"), exist_ok=True)
    os.makedirs(os.path.join(case_dir, "extracted"), exist_ok=True)
    os.makedirs(os.path.join(case_dir, "csv"), exist_ok=True)
    os.makedirs(os.path.join(case_dir, "analysis"), exist_ok=True)

    case_meta = {
        "case_id": case_id,
        "case_name": case_name,
        "original_filename": original_filename,
        "created_at": timestamp,
        "status": "uploaded",
        "case_dir": case_dir,
        "csv_ready": False,
        "analysis_ready": False,
        "artifacts": {},
    }

    return case_meta


def _extract_with_system_tool(zip_path: str, extract_dir: str) -> bool:
    """
    Fall back to system ``unzip`` or ``7z`` when Python's zipfile module cannot
    handle the compression method (e.g. deflate64, method 9).

    Returns True on success, False if no suitable tool is available or all fail.
    """
    os.makedirs(extract_dir, exist_ok=True)

    # Try unzip first (widely available on Linux)
    if shutil.which("unzip"):
        try:
            result = subprocess.run(
                ["unzip", "-o", zip_path, "-d", extract_dir],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                logger.info("Extracted ZIP using system unzip")
                return True
            logger.warning(f"unzip exited with code {result.returncode}: {result.stderr[:200]}")
        except Exception as e:
            logger.warning(f"unzip failed: {e}")

    # Try 7z / 7za as a second option
    for tool in ("7z", "7za"):
        if shutil.which(tool):
            try:
                result = subprocess.run(
                    [tool, "x", zip_path, f"-o{extract_dir}", "-y"],
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode == 0:
                    logger.info(f"Extracted ZIP using {tool}")
                    return True
                logger.warning(f"{tool} exited with code {result.returncode}: {result.stderr[:200]}")
            except Exception as e:
                logger.warning(f"{tool} failed: {e}")

    return False


def extract_zip(zip_path: str, case_dir: str) -> dict:
    """
    Safely extract a ZIP file into the case's extracted/ directory.
    Returns extraction metadata.
    """
    extract_dir = os.path.join(case_dir, "extracted")

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)
    except zipfile.BadZipFile as e:
        raise IngestError(f"Failed to extract ZIP: {e}")
    except NotImplementedError:
        # Python's zipfile doesn't support all compression methods (e.g. deflate64).
        # Fall back to a system tool that can handle them.
        logger.warning(
            "Python zipfile cannot handle the compression method in this archive "
            "(possibly deflate64). Trying system extraction tools."
        )
        if not _extract_with_system_tool(zip_path, extract_dir):
            raise IngestError(
                "ZIP uses an unsupported compression method (e.g. deflate64) and no "
                "compatible extraction tool (unzip, 7z) is available on the system."
            )
    except Exception as e:
        raise IngestError(f"Extraction error: {e}")

    # Catalog what was extracted
    artifacts = catalog_artifacts(extract_dir)

    return {
        "extract_dir": extract_dir,
        "artifacts": artifacts,
    }


def catalog_artifacts(extract_dir: str) -> dict:
    """
    Walk the extracted directory and catalog all artifacts by category.
    Returns a dict: {category: [{filename, path, size_bytes}]}
    """
    catalog = {}
    all_jsonl = []
    all_logs = []

    for root, dirs, files in os.walk(extract_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, extract_dir)
            size = os.path.getsize(fpath)

            if fname.endswith(".jsonl"):
                all_jsonl.append({
                    "filename": fname,
                    "path": fpath,
                    "rel_path": rel_path,
                    "size_bytes": size,
                })
            elif "logs/" in rel_path or fname.endswith((".log", ".journal", ".journal~")):
                all_logs.append({
                    "filename": fname,
                    "path": fpath,
                    "rel_path": rel_path,
                    "size_bytes": size,
                })

    # Categorize JSONL files using Fennec categories
    for category, known_files in config.FENNEC_ARTIFACT_CATEGORIES.items():
        matched = [
            j for j in all_jsonl
            if j["filename"] in known_files and j["size_bytes"] > 0
        ]
        if matched:
            catalog[category] = matched

    # Add uncategorized JSONL files
    categorized_names = set()
    for cat_files in config.FENNEC_ARTIFACT_CATEGORIES.values():
        categorized_names.update(cat_files)

    uncategorized = [
        j for j in all_jsonl
        if j["filename"] not in categorized_names and j["size_bytes"] > 0
    ]
    if uncategorized:
        catalog["other"] = uncategorized

    # Add log files
    non_empty_logs = [l for l in all_logs if l["size_bytes"] > 0]
    if non_empty_logs:
        catalog["system_logs"] = non_empty_logs

    return catalog


def ingest_zip(file_storage, original_filename: str, mongo_fs=None) -> dict:
    """
    Full ingestion pipeline: create case → save ZIP → validate → extract → catalog.
    
    Args:
        file_storage: werkzeug FileStorage object or file path string
        original_filename: original filename from upload
        mongo_fs: GridFS instance for backup storage (optional)
    
    Returns:
        Complete case metadata dict
    """
    # Create case
    case_meta = create_case(original_filename)
    case_dir = case_meta["case_dir"]

    # Save ZIP to case upload directory
    zip_path = os.path.join(case_dir, "upload", original_filename)
    try:
        if isinstance(file_storage, str):
            # It's a file path - copy it
            shutil.copy2(file_storage, zip_path)
        else:
            # It's a FileStorage object - save it
            file_storage.save(zip_path)
    except Exception as e:
        # Clean up on failure
        shutil.rmtree(case_dir, ignore_errors=True)
        raise IngestError(f"Failed to save uploaded file: {e}")

    # Validate
    try:
        validation = validate_zip(zip_path)
        case_meta["validation"] = validation
    except IngestError:
        shutil.rmtree(case_dir, ignore_errors=True)
        raise

    if not validation["is_fennec"]:
        logger.warning(
            f"Case {case_meta['case_id']}: ZIP does not appear to contain Fennec artifacts "
            f"(no .jsonl files found). Proceeding anyway."
        )

    # Extract
    try:
        extraction = extract_zip(zip_path, case_dir)
        case_meta["artifacts"] = extraction["artifacts"]
        case_meta["status"] = "extracted"
    except IngestError:
        shutil.rmtree(case_dir, ignore_errors=True)
        raise

    # Store in GridFS as backup (optional)
    if mongo_fs:
        try:
            with open(zip_path, "rb") as f:
                mongo_fs.put(f, filename=original_filename, case_id=case_meta["case_id"])
        except Exception as e:
            logger.warning(f"Failed to store ZIP in GridFS: {e}")

    logger.info(
        f"Case {case_meta['case_id']} ingested: "
        f"{validation['jsonl_count']} JSONL files, "
        f"{validation['log_count']} log files"
    )

    return case_meta
