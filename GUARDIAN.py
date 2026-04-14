"""
GUARDIAN - Global Unified Analysis and Response for Detecting Intrusions and Neutralizing threats.

Main Flask application: handles web UI, REST API for the threat hunting pipeline.
Pipeline: Fennec ZIP → Upload → CSV → Zircolite/Heuristic Analysis → Kuiper
"""

import os
import json
import logging
import threading
from datetime import datetime
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, send_file, send_from_directory, abort
)
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from gridfs import GridFS

from guardian import config
from guardian.ingest import ingest_zip, IngestError
from guardian.processing import generate_all_csvs, ProcessingError
from guardian.analysis import run_zircolite, run_heuristic_analysis, AnalysisError
from guardian.investigation import check_kuiper_status, export_case_for_kuiper, push_to_kuiper, get_kuiper_url

# ─── App Setup ────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder='templates', static_folder='templates/static')
app.secret_key = config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = config.MAX_UPLOAD_SIZE_MB * 1024 * 1024

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("guardian")

# ─── MongoDB Setup ────────────────────────────────────────────────────────────

try:
    mongo_client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
    mongo_client.server_info()  # Force connection check
    db = mongo_client[config.MONGO_DB_NAME]
    fs = GridFS(db)
    cases_collection = db["cases"]
    logger.info("Connected to MongoDB")
except Exception as e:
    logger.warning(f"MongoDB not available: {e}. Running without database persistence.")
    db = None
    fs = None
    cases_collection = None

# ─── In-Memory Case Store (backed by MongoDB when available) ──────────────────

_cases = {}  # case_id -> case_meta dict


def save_case(case_meta: dict):
    """Save case metadata to memory and MongoDB."""
    case_id = case_meta["case_id"]
    _cases[case_id] = case_meta
    if cases_collection is not None:
        try:
            cases_collection.update_one(
                {"case_id": case_id},
                {"$set": case_meta},
                upsert=True
            )
        except Exception as e:
            logger.warning(f"Failed to save case to MongoDB: {e}")


def load_cases():
    """Load cases from MongoDB on startup, and from filesystem."""
    if cases_collection is not None:
        try:
            for doc in cases_collection.find():
                case_id = doc.get("case_id")
                if case_id:
                    doc.pop("_id", None)
                    _cases[case_id] = doc
        except Exception as e:
            logger.warning(f"Failed to load cases from MongoDB: {e}")

    # Also scan filesystem for cases not in DB
    if os.path.isdir(config.CASES_DIR):
        for case_id in os.listdir(config.CASES_DIR):
            case_dir = os.path.join(config.CASES_DIR, case_id)
            if os.path.isdir(case_dir) and case_id not in _cases:
                # Reconstruct minimal metadata from filesystem
                meta_path = os.path.join(case_dir, "case_meta.json")
                if os.path.isfile(meta_path):
                    try:
                        with open(meta_path, "r") as f:
                            _cases[case_id] = json.load(f)
                    except Exception:
                        pass
                else:
                    _cases[case_id] = {
                        "case_id": case_id,
                        "case_name": case_id,
                        "status": "unknown",
                        "case_dir": case_dir,
                        "csv_ready": os.path.isdir(os.path.join(case_dir, "csv")),
                        "analysis_ready": os.path.isdir(os.path.join(case_dir, "analysis")),
                    }

    # Reconstruct full artifact paths from rel_path + extracted directory.
    # persist_case_meta stores rel_path; without this step CSV generation
    # silently produces empty output after a server restart.
    for case_id, case in _cases.items():
        case_dir = case.get("case_dir", "")
        if not case_dir:
            continue
        extract_dir = os.path.join(case_dir, "extracted")
        artifacts = case.get("artifacts", {})
        for cat, files in artifacts.items():
            for file_info in files:
                # Already has a valid path from this session (e.g. just ingested)
                if file_info.get("path") and os.path.isfile(file_info["path"]):
                    continue
                rel_path = file_info.get("rel_path", "")
                filename = file_info.get("filename", "")
                if rel_path:
                    full_path = os.path.join(extract_dir, rel_path)
                    if os.path.isfile(full_path):
                        file_info["path"] = full_path
                        continue
                # Fallback: search the extracted tree for the filename
                if filename and os.path.isdir(extract_dir):
                    for root, _dirs, fnames in os.walk(extract_dir):
                        if filename in fnames:
                            file_info["path"] = os.path.join(root, filename)
                            file_info["rel_path"] = os.path.relpath(
                                file_info["path"], extract_dir
                            )
                            break


def persist_case_meta(case_meta: dict):
    """Write case metadata to a JSON file for filesystem persistence."""
    case_dir = case_meta.get("case_dir", "")
    if case_dir and os.path.isdir(case_dir):
        meta_path = os.path.join(case_dir, "case_meta.json")
        # Make a serializable copy
        safe_meta = {}
        for k, v in case_meta.items():
            if k == "artifacts":
                # Preserve filename, rel_path, size_bytes so paths can be
                # reconstructed after a server restart.
                safe_artifacts = {}
                for cat, files in v.items():
                    safe_artifacts[cat] = [
                        {
                            "filename": f.get("filename", ""),
                            "rel_path": f.get("rel_path", ""),
                            "size_bytes": f.get("size_bytes", 0),
                        }
                        for f in files
                    ]
                safe_meta[k] = safe_artifacts
            else:
                safe_meta[k] = v
        try:
            with open(meta_path, "w") as f:
                json.dump(safe_meta, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"Failed to persist case meta: {e}")


def _run_pipeline_background(case_id: str):
    """
    Background thread: automatically run CSV generation then threat analysis
    after a successful upload so the full pipeline fires without manual steps.
    Updates case status at each stage so the UI reflects progress.
    """
    case = get_case(case_id)
    if not case:
        return

    case_dir = case.get("case_dir", "")
    artifacts = case.get("artifacts", {})

    if not artifacts:
        logger.warning(f"Case {case_id}: no artifacts found, skipping auto-pipeline")
        case["status"] = "extracted"
        case["processing_step"] = "No artifacts found"
        save_case(case)
        return

    # ── Step 1: CSV generation ──────────────────────────────────────
    try:
        case["status"] = "processing"
        case["processing_step"] = "Generating CSV timeline"
        save_case(case)

        results = generate_all_csvs(case_dir, artifacts)

        case["csv_ready"] = True
        case["csv_results"] = {
            "timeline_rows": results["timeline_rows"],
            "total_csvs": results["total_csvs"],
            "generated_at": datetime.utcnow().isoformat(),
        }
        case["status"] = "csv_ready"
        case["processing_step"] = "CSV ready"
        save_case(case)
        persist_case_meta(case)
        logger.info(
            f"Case {case_id}: CSV generation complete "
            f"({results['timeline_rows']} rows, {results['total_csvs']} files)"
        )
    except Exception as e:
        logger.error(f"Case {case_id}: CSV generation failed: {e}", exc_info=True)
        case["status"] = "error"
        case["processing_step"] = f"CSV generation failed: {e}"
        save_case(case)
        return

    # ── Step 2: Threat analysis ─────────────────────────────────────
    try:
        case["status"] = "analyzing"
        case["processing_step"] = "Running threat analysis"
        save_case(case)

        results = run_zircolite(case_dir, artifacts)

        case["analysis_ready"] = True
        case["analysis_results"] = {
            "engine": results["engine"],
            "detected_count": results["detected_count"],
            "analyzed_at": datetime.utcnow().isoformat(),
        }
        case["status"] = "analyzed"
        case["processing_step"] = "Complete"
        save_case(case)
        persist_case_meta(case)
        logger.info(
            f"Case {case_id}: analysis complete "
            f"({results['detected_count']} findings via {results['engine']})"
        )
    except Exception as e:
        logger.error(f"Case {case_id}: analysis failed: {e}", exc_info=True)
        # CSV is still good — downgrade status rather than marking as error
        case["status"] = "csv_ready"
        case["processing_step"] = f"Analysis failed: {e}"
        save_case(case)


def get_case(case_id: str) -> dict:
    """Get case by ID."""
    return _cases.get(case_id)


def get_all_cases() -> list:
    """Get all cases sorted by creation date."""
    cases = list(_cases.values())
    cases.sort(key=lambda c: c.get("created_at", ""), reverse=True)
    return cases


# ─── Routes: Auth (simplified - bypass for now) ──────────────────────────────

@app.route('/', methods=['GET'])
def root():
    """Redirect to dashboard."""
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    """Main dashboard - shows all cases and pipeline controls."""
    cases = get_all_cases()
    kuiper_url = get_kuiper_url()
    kuiper_status = check_kuiper_status()
    return render_template(
        'index.html',
        cases=cases,
        kuiper_url=kuiper_url,
        kuiper_available=kuiper_status["available"],
    )


# ─── Routes: Upload ──────────────────────────────────────────────────────────

@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handle ZIP file upload via drag-and-drop or form.
    Validates, extracts, and catalogues the Fennec artifacts.
    Returns JSON response.
    """
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected"}), 400

    filename = secure_filename(file.filename)

    # Check extension
    ext = os.path.splitext(filename)[1].lower()
    if ext not in config.ALLOWED_EXTENSIONS:
        return jsonify({"success": False, "error": f"Invalid file type: {ext}. Only ZIP files are allowed."}), 400

    try:
        case_meta = ingest_zip(file, filename, mongo_fs=fs)
        save_case(case_meta)
        persist_case_meta(case_meta)

        # Auto-trigger full pipeline in background so the user doesn't need
        # to manually click "Generate CSV" and "Run Analysis".
        pipeline_thread = threading.Thread(
            target=_run_pipeline_background,
            args=(case_meta["case_id"],),
            daemon=True,
        )
        pipeline_thread.start()

        return jsonify({
            "success": True,
            "case_id": case_meta["case_id"],
            "case_name": case_meta["case_name"],
            "status": case_meta["status"],
            "artifact_count": sum(len(v) for v in case_meta.get("artifacts", {}).values()),
            "message": f"Case '{case_meta['case_name']}' created successfully",
        })

    except IngestError as e:
        logger.error(f"Upload failed: {e}")
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Upload error: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal server error during upload"}), 500


# ─── Routes: CSV Generation ──────────────────────────────────────────────────

@app.route('/api/cases/<case_id>/csv', methods=['POST'])
def generate_csv(case_id):
    """Generate CSV timeline from case artifacts."""
    case = get_case(case_id)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    case_dir = case.get("case_dir", "")
    artifacts = case.get("artifacts", {})

    if not artifacts:
        return jsonify({"success": False, "error": "No artifacts found in case"}), 400

    try:
        results = generate_all_csvs(case_dir, artifacts)

        # Update case metadata
        case["csv_ready"] = True
        case["csv_results"] = {
            "timeline_rows": results["timeline_rows"],
            "total_csvs": results["total_csvs"],
            "generated_at": datetime.utcnow().isoformat(),
        }
        case["status"] = "csv_ready"
        save_case(case)
        persist_case_meta(case)

        return jsonify({
            "success": True,
            "timeline_rows": results["timeline_rows"],
            "total_csvs": results["total_csvs"],
            "per_artifact_csvs": [
                {"filename": c["filename"], "rows": c["row_count"], "category": c["category"]}
                for c in results["per_artifact_csvs"]
            ],
        })

    except ProcessingError as e:
        return jsonify({"success": False, "error": str(e)}), 500
    except Exception as e:
        logger.error(f"CSV generation error: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal error during CSV generation"}), 500


@app.route('/api/cases/<case_id>/csv/download')
def download_csv(case_id):
    """Download the unified timeline CSV."""
    case = get_case(case_id)
    if not case:
        abort(404)

    csv_path = os.path.join(case.get("case_dir", ""), "csv", "unified_timeline.csv")
    if not os.path.isfile(csv_path):
        abort(404)

    return send_file(csv_path, as_attachment=True, download_name=f"timeline_{case_id}.csv")


@app.route('/api/cases/<case_id>/csv/download/<filename>')
def download_artifact_csv(case_id, filename):
    """Download a specific per-artifact CSV."""
    case = get_case(case_id)
    if not case:
        abort(404)

    csv_dir = os.path.join(case.get("case_dir", ""), "csv")
    safe_filename = secure_filename(filename)
    csv_path = os.path.join(csv_dir, safe_filename)

    if not os.path.isfile(csv_path):
        abort(404)

    return send_file(csv_path, as_attachment=True, download_name=safe_filename)


# ─── Routes: Analysis ────────────────────────────────────────────────────────

@app.route('/api/cases/<case_id>/analyze', methods=['POST'])
def analyze_case(case_id):
    """Run Zircolite/heuristic analysis on case artifacts."""
    case = get_case(case_id)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    case_dir = case.get("case_dir", "")
    artifacts = case.get("artifacts", {})

    if not artifacts:
        return jsonify({"success": False, "error": "No artifacts found in case"}), 400

    try:
        results = run_zircolite(case_dir, artifacts)

        # Update case metadata
        case["analysis_ready"] = True
        case["analysis_results"] = {
            "engine": results["engine"],
            "detected_count": results["detected_count"],
            "analyzed_at": datetime.utcnow().isoformat(),
        }
        case["status"] = "analyzed"
        save_case(case)
        persist_case_meta(case)

        return jsonify({
            "success": True,
            "engine": results["engine"],
            "detected_count": results["detected_count"],
            "detected_events": results["detected_events"],
            "gui_url": results.get("gui_url"),
        })

    except AnalysisError as e:
        return jsonify({"success": False, "error": str(e)}), 500
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal error during analysis"}), 500


@app.route('/api/cases/<case_id>/analysis/results')
def get_analysis_results(case_id):
    """Get analysis results for a case."""
    case = get_case(case_id)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    analysis_file = os.path.join(case.get("case_dir", ""), "analysis", "detected_events.json")
    if not os.path.isfile(analysis_file):
        return jsonify({"success": False, "error": "No analysis results available"}), 404

    try:
        with open(analysis_file, "r") as f:
            events = json.load(f)
        return jsonify({
            "success": True,
            "detected_count": len(events),
            "detected_events": events[:200],
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Routes: Investigation (Kuiper) ──────────────────────────────────────────

@app.route('/api/cases/<case_id>/export', methods=['POST'])
def export_case(case_id):
    """Export case data as ZIP for Kuiper import."""
    case = get_case(case_id)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    case_dir = case.get("case_dir", "")
    try:
        export_path = export_case_for_kuiper(case_dir, case_id)
        return send_file(export_path, as_attachment=True,
                         download_name=f"case_{case_id}_export.zip")
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/kuiper/status')
def kuiper_status():
    """Check Kuiper availability."""
    status = check_kuiper_status()
    return jsonify(status)


@app.route('/api/cases/<case_id>/push-to-kuiper', methods=['POST'])
def push_case_to_kuiper(case_id):
    """Push case CSV timelines directly to Kuiper via its REST API."""
    case = get_case(case_id)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    case_dir = case.get("case_dir", "")
    case_name = case.get("case_name", case_id)

    if not case.get("csv_ready"):
        return jsonify({
            "success": False,
            "error": "CSV timeline is not ready yet. Generate CSV first.",
        }), 400

    try:
        result = push_to_kuiper(case_dir, case_id, case_name)
        if result["success"]:
            # Record the Kuiper case id for reference
            case["kuiper_case_id"] = result.get("kuiper_case_id")
            save_case(case)
            persist_case_meta(case)
        return jsonify(result), 200 if result["success"] else 502
    except Exception as e:
        logger.error(f"Push-to-Kuiper error: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500




@app.route('/api/cases/<case_id>', methods=['GET'])
def get_case_info(case_id):
    """Get case metadata."""
    case = get_case(case_id)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    # Build a safe serializable copy
    safe_case = {}
    for k, v in case.items():
        if k == "artifacts":
            safe_artifacts = {}
            for cat, files in v.items():
                safe_artifacts[cat] = [
                    {"filename": f.get("filename", ""), "size_bytes": f.get("size_bytes", 0)}
                    for f in files
                ]
            safe_case[k] = safe_artifacts
        else:
            safe_case[k] = v
    return jsonify({"success": True, "case": safe_case})


@app.route('/api/cases/<case_id>', methods=['DELETE'])
def delete_case(case_id):
    """Delete a case and its data."""
    case = get_case(case_id)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    case_dir = case.get("case_dir", "")

    # Remove from memory
    _cases.pop(case_id, None)

    # Remove from MongoDB
    if cases_collection is not None:
        try:
            cases_collection.delete_one({"case_id": case_id})
        except Exception:
            pass

    # Remove from GridFS
    if fs is not None:
        try:
            grid_file = fs.find_one({"case_id": case_id})
            if grid_file:
                fs.delete(grid_file._id)
        except Exception:
            pass

    # Remove filesystem data
    import shutil
    if case_dir and os.path.isdir(case_dir):
        shutil.rmtree(case_dir, ignore_errors=True)

    return jsonify({"success": True, "message": f"Case {case_id} deleted"})


@app.route('/api/cases/<case_id>/status')
def case_status(case_id):
    """Get pipeline status for a case."""
    case = get_case(case_id)
    if not case:
        return jsonify({"success": False, "error": "Case not found"}), 404

    case_dir = case.get("case_dir", "")
    return jsonify({
        "success": True,
        "case_id": case_id,
        "status": case.get("status", "unknown"),
        "processing_step": case.get("processing_step", ""),
        "uploaded": case.get("status") in ["uploaded", "extracted", "processing", "csv_ready", "analyzing", "analyzed"],
        "extracted": case.get("status") in ["extracted", "processing", "csv_ready", "analyzing", "analyzed"],
        "csv_ready": case.get("csv_ready", False),
        "analysis_ready": case.get("analysis_ready", False),
        "csv_exists": os.path.isfile(os.path.join(case_dir, "csv", "unified_timeline.csv")),
        "analysis_exists": os.path.isfile(os.path.join(case_dir, "analysis", "detected_events.json")),
    })


# ─── Routes: Zircolite GUI ───────────────────────────────────────────────────

@app.route('/analysis/<case_id>/gui/<path:filename>')
def serve_analysis_gui(case_id, filename):
    """Serve Zircolite GUI static files."""
    case = get_case(case_id)
    if not case:
        abort(404)

    gui_dir = os.path.join(case.get("case_dir", ""), "analysis", "zircogui")
    # Check for nested directory
    if os.path.isdir(os.path.join(gui_dir, "zircogui")):
        gui_dir = os.path.join(gui_dir, "zircogui")

    return send_from_directory(gui_dir, filename)


# ─── Startup ──────────────────────────────────────────────────────────────────

load_cases()
logger.info(f"Loaded {len(_cases)} existing cases")


def main():
    """Start the Guardian application."""
    logger.info("=" * 60)
    logger.info("GUARDIAN - Threat Hunting Pipeline")
    logger.info(f"Data directory: {config.DATA_DIR}")
    logger.info(f"Cases directory: {config.CASES_DIR}")
    logger.info(f"Kuiper URL: {config.KUIPER_URL}")
    logger.info("=" * 60)

    app.run(host='0.0.0.0', port=5002, debug=False, threaded=True)


if __name__ == "__main__":
    main()
