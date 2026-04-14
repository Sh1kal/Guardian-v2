"""
Analysis module: runs Zircolite SIGMA-based detection on Fennec JSONL artifacts.
Also provides a fallback heuristic analysis when Zircolite rules are unavailable.
"""

import os
import json
import subprocess
import shutil
import logging
from datetime import datetime

from . import config

logger = logging.getLogger("guardian.analysis")


class AnalysisError(Exception):
    """Raised when analysis fails."""
    pass


def check_zircolite_available() -> bool:
    """Check if Zircolite script exists and is accessible."""
    return os.path.isfile(config.ZIRCOLITE_PATH)


def check_rules_available() -> bool:
    """Check if Linux SIGMA rules are present."""
    return os.path.isfile(config.ZIRCOLITE_LINUX_RULES)


def find_jsonl_files(extract_dir: str) -> list:
    """Find all non-empty JSONL files in the extraction directory."""
    jsonl_files = []
    for root, dirs, files in os.walk(extract_dir):
        for fname in files:
            if fname.endswith(".jsonl"):
                fpath = os.path.join(root, fname)
                if os.path.getsize(fpath) > 0:
                    jsonl_files.append(fpath)
    return jsonl_files


def run_zircolite(case_dir: str, artifacts: dict) -> dict:
    """
    Run Zircolite on JSONL artifacts using --jsononly mode.
    
    Zircolite supports:
    - --events <folder_or_file> : input events
    - --jsononly : for JSONL/NDJSON input
    - --ruleset <rules.json> : SIGMA rules
    - -o <output.json> : output file
    
    Returns analysis results dict.
    """
    extract_dir = os.path.join(case_dir, "extracted")
    analysis_dir = os.path.join(case_dir, "analysis")
    os.makedirs(analysis_dir, exist_ok=True)

    # Check prerequisites
    if not check_zircolite_available():
        logger.warning("Zircolite not found, falling back to heuristic analysis")
        return run_heuristic_analysis(case_dir, artifacts)

    # Find JSONL files
    jsonl_files = find_jsonl_files(extract_dir)
    if not jsonl_files:
        raise AnalysisError("No JSONL files found for analysis")

    output_file = os.path.join(analysis_dir, "detected_events.json")
    log_file = os.path.join(analysis_dir, "zircolite.log")

    # Build Zircolite command
    # Use --jsononly for JSONL files, point to the extract directory
    cmd = [
        "python3", config.ZIRCOLITE_PATH,
        "--events", extract_dir,
        "--jsononly",
        "-o", output_file,
        "-l", log_file,
    ]

    # Add ruleset if available
    if check_rules_available():
        cmd.extend(["--ruleset", config.ZIRCOLITE_LINUX_RULES])
    else:
        logger.warning("No Linux SIGMA ruleset found. Attempting without specific rules.")
        # Without rules, Zircolite won't detect much - do heuristic instead
        return run_heuristic_analysis(case_dir, artifacts)

    # Also generate Zircolite GUI output if template exists
    if os.path.isfile(config.ZIRCOLITE_TEMPLATE):
        gui_output = os.path.join(analysis_dir, "data.js")
        cmd.extend(["--template", config.ZIRCOLITE_TEMPLATE])
        cmd.extend(["--templateOutput", gui_output])

    logger.info(f"Running Zircolite: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
            cwd=config.BASE_DIR,
        )

        if result.returncode != 0:
            logger.error(f"Zircolite stderr: {result.stderr}")
            # Try heuristic as fallback
            logger.info("Zircolite failed, falling back to heuristic analysis")
            return run_heuristic_analysis(case_dir, artifacts)

    except subprocess.TimeoutExpired:
        raise AnalysisError("Zircolite timed out after 10 minutes")
    except FileNotFoundError:
        logger.warning("Python3 or Zircolite not found, falling back to heuristic")
        return run_heuristic_analysis(case_dir, artifacts)

    # Parse results
    detected_events = []
    if os.path.isfile(output_file):
        try:
            with open(output_file, "r") as f:
                detected_events = json.load(f)
        except json.JSONDecodeError:
            logger.warning("Failed to parse Zircolite output")

    # Set up Zircolite GUI if data.js was generated
    gui_url = None
    gui_output = os.path.join(analysis_dir, "data.js")
    if os.path.isfile(gui_output) and os.path.isfile(config.ZIRCOLITE_GUI_ZIP):
        gui_url = setup_zircolite_gui(analysis_dir, gui_output)

    return {
        "success": True,
        "engine": "zircolite",
        "detected_count": len(detected_events),
        "detected_events": detected_events[:100],  # Limit for UI
        "output_file": output_file,
        "gui_url": gui_url,
        "log_file": log_file,
    }


def setup_zircolite_gui(analysis_dir: str, data_js_path: str) -> str:
    """
    Extract Zircolite GUI and copy data.js into it.
    Returns the relative URL path to the GUI.
    """
    gui_dir = os.path.join(analysis_dir, "zircogui")
    try:
        # Extract GUI zip
        subprocess.run(
            ["7z", "x", config.ZIRCOLITE_GUI_ZIP, f"-o{gui_dir}", "-y"],
            capture_output=True,
            timeout=30,
        )
        # Move data.js into GUI directory
        # The 7z might extract into a subdirectory
        if os.path.isdir(os.path.join(gui_dir, "zircogui")):
            actual_gui = os.path.join(gui_dir, "zircogui")
        else:
            actual_gui = gui_dir

        shutil.copy2(data_js_path, os.path.join(actual_gui, "data.js"))
        return actual_gui
    except Exception as e:
        logger.warning(f"Failed to set up Zircolite GUI: {e}")
        return None


def run_heuristic_analysis(case_dir: str, artifacts: dict) -> dict:
    """
    Heuristic threat analysis when Zircolite/SIGMA rules aren't available.
    Checks for common Linux threat indicators in Fennec artifacts.
    """
    extract_dir = os.path.join(case_dir, "extracted")
    analysis_dir = os.path.join(case_dir, "analysis")
    os.makedirs(analysis_dir, exist_ok=True)

    findings = []

    # 1. Check for suspicious SUID binaries
    findings.extend(_check_suid_bins(extract_dir))

    # 2. Check for suspicious processes
    findings.extend(_check_suspicious_processes(extract_dir))

    # 3. Check for suspicious crontabs
    findings.extend(_check_crontabs(extract_dir))

    # 4. Check for suspicious shell history
    findings.extend(_check_shell_history(extract_dir))

    # 5. Check for suspicious network connections
    findings.extend(_check_network(extract_dir))

    # 6. Check for shadow file anomalies
    findings.extend(_check_shadow(extract_dir))

    # 7. Check for SSH anomalies
    findings.extend(_check_ssh(extract_dir))

    # 8. Check for suspicious authorized_keys
    findings.extend(_check_authorized_keys(extract_dir))

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 4))

    # Save results
    output_file = os.path.join(analysis_dir, "detected_events.json")
    with open(output_file, "w") as f:
        json.dump(findings, f, indent=2, default=str)

    return {
        "success": True,
        "engine": "heuristic",
        "detected_count": len(findings),
        "detected_events": findings[:100],
        "output_file": output_file,
        "gui_url": None,
        "log_file": None,
    }


def _read_jsonl(extract_dir: str, filename: str) -> list:
    """Helper to read a JSONL file from the extract directory.

    Searches recursively so Fennec archives with a top-level subdirectory
    (e.g. ``hostname_20231001/process_list.jsonl``) are found correctly.
    """
    for root, _dirs, files in os.walk(extract_dir):
        if filename in files:
            fpath = os.path.join(root, filename)
            records = []
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
            except Exception:
                pass
            return records
    return []


def _check_suid_bins(extract_dir: str) -> list:
    """Check for unusual SUID binaries."""
    findings = []
    KNOWN_DANGEROUS_SUID = {
        "nmap", "python", "python3", "perl", "ruby", "gcc", "vim", "vi",
        "nano", "find", "bash", "sh", "dash", "zsh", "env", "awk", "gawk",
        "less", "more", "man", "ftp", "socat", "nc", "ncat", "wget", "curl",
        "php", "node", "lua", "tclsh", "wish", "expect", "strace", "ltrace",
        "gdb", "docker", "pkexec",
    }
    records = _read_jsonl(extract_dir, "suid_bin.jsonl")
    for r in records:
        path = r.get("path", "")
        name = os.path.basename(path).lower()
        if name in KNOWN_DANGEROUS_SUID:
            findings.append({
                "title": f"Dangerous SUID binary: {path}",
                "description": f"SUID bit set on {name}, which can be used for privilege escalation",
                "severity": "high",
                "category": "privilege_escalation",
                "source": "suid_bin.jsonl",
                "evidence": r,
            })
    return findings


def _check_suspicious_processes(extract_dir: str) -> list:
    """Check for suspicious processes."""
    findings = []
    SUSPICIOUS_NAMES = {
        "nc", "ncat", "netcat", "socat", "meterpreter", "reverse",
        "bind_shell", "xmrig", "cryptominer", "mimikatz", "lazagne",
        "linpeas", "linenum", "pspy",
    }
    SUSPICIOUS_CMDLINE = [
        "/dev/tcp/", "/dev/udp/", "bash -i", "mkfifo", "mknod",
        "base64 -d", "python -c", "perl -e", "ruby -e",
        "/tmp/", "wget http", "curl http", "nc -e", "ncat -e",
    ]
    records = _read_jsonl(extract_dir, "process_list.jsonl")
    for r in records:
        name = r.get("name", "").lower()
        cmdline = r.get("cmdline", "").lower()

        if name in SUSPICIOUS_NAMES:
            findings.append({
                "title": f"Suspicious process: {r.get('name', '')}",
                "description": f"Process '{name}' (PID {r.get('pid', '?')}) is commonly associated with attack tools",
                "severity": "high",
                "category": "execution",
                "source": "process_list.jsonl",
                "evidence": {k: r.get(k) for k in ["pid", "name", "cmdline", "path", "uid", "start_time"]},
            })

        for pattern in SUSPICIOUS_CMDLINE:
            if pattern in cmdline:
                findings.append({
                    "title": f"Suspicious command line: {pattern}",
                    "description": f"Process PID {r.get('pid', '?')} has suspicious command: {r.get('cmdline', '')[:200]}",
                    "severity": "high",
                    "category": "execution",
                    "source": "process_list.jsonl",
                    "evidence": {k: r.get(k) for k in ["pid", "name", "cmdline", "path", "uid", "start_time"]},
                })
                break  # One finding per process

    return findings


def _check_crontabs(extract_dir: str) -> list:
    """Check for suspicious crontab entries."""
    findings = []
    SUSPICIOUS_CRON = [
        "/tmp/", "/dev/shm/", "wget ", "curl ", "base64",
        "python -c", "perl -e", "bash -c", "/dev/tcp",
    ]
    records = _read_jsonl(extract_dir, "crontab.jsonl")
    for r in records:
        command = r.get("command", "").lower()
        for pattern in SUSPICIOUS_CRON:
            if pattern in command:
                findings.append({
                    "title": f"Suspicious crontab entry",
                    "description": f"Crontab contains suspicious pattern '{pattern}': {r.get('command', '')[:200]}",
                    "severity": "medium",
                    "category": "persistence",
                    "source": "crontab.jsonl",
                    "evidence": r,
                })
                break
    return findings


def _check_shell_history(extract_dir: str) -> list:
    """Check for suspicious commands in shell history."""
    findings = []
    SUSPICIOUS_COMMANDS = [
        "passwd", "shadow", "useradd", "usermod", "visudo",
        "iptables -F", "ufw disable", "setenforce 0",
        "chmod 777", "chmod +s", "chown root",
        "wget http", "curl http", "nc -", "ncat -",
        "base64 -d", "python -c", "perl -e",
        ".ssh/authorized_keys", "id_rsa",
        "/etc/cron", "systemctl disable",
    ]
    records = _read_jsonl(extract_dir, "shell_history.jsonl")
    for r in records:
        command = r.get("command", "").lower()
        for pattern in SUSPICIOUS_COMMANDS:
            if pattern.lower() in command:
                findings.append({
                    "title": f"Suspicious shell command: {pattern}",
                    "description": f"Shell history contains: {r.get('command', '')[:200]}",
                    "severity": "medium",
                    "category": "execution",
                    "source": "shell_history.jsonl",
                    "evidence": r,
                })
                break
    return findings


def _check_network(extract_dir: str) -> list:
    """Check for suspicious network connections."""
    findings = []
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 1234, 31337, 12345, 9001, 8888, 9999}
    records = _read_jsonl(extract_dir, "netstat.jsonl")
    for r in records:
        remote_port = r.get("remote_port", 0)
        state = r.get("state", "").upper()

        try:
            remote_port = int(remote_port)
        except (ValueError, TypeError):
            remote_port = 0

        if remote_port in SUSPICIOUS_PORTS and state == "ESTABLISHED":
            findings.append({
                "title": f"Suspicious outbound connection to port {remote_port}",
                "description": f"Active connection to {r.get('remote_address', '?')}:{remote_port}",
                "severity": "high",
                "category": "command_and_control",
                "source": "netstat.jsonl",
                "evidence": {k: r.get(k) for k in ["pid", "name", "local_address", "local_port", "remote_address", "remote_port", "state"]},
            })
    return findings


def _check_shadow(extract_dir: str) -> list:
    """Check for shadow file anomalies."""
    findings = []
    records = _read_jsonl(extract_dir, "shadow.jsonl")
    for r in records:
        username = r.get("username", "")
        password_status = r.get("password_status", "")

        # Check for accounts with no password
        if password_status in ["", "NP"]:
            findings.append({
                "title": f"Account without password: {username}",
                "description": f"User '{username}' has no password set",
                "severity": "medium",
                "category": "credential_access",
                "source": "shadow.jsonl",
                "evidence": {"username": username, "password_status": password_status},
            })
    return findings


def _check_ssh(extract_dir: str) -> list:
    """Check SSH configuration for security issues."""
    findings = []
    records = _read_jsonl(extract_dir, "ssh_configs.jsonl")
    for r in records:
        if r.get("PermitRootLogin", "").lower() in ["yes", "without-password"]:
            findings.append({
                "title": "SSH PermitRootLogin enabled",
                "description": "SSH is configured to allow root login",
                "severity": "medium",
                "category": "initial_access",
                "source": "ssh_configs.jsonl",
                "evidence": r,
            })
        if r.get("PasswordAuthentication", "").lower() == "yes":
            findings.append({
                "title": "SSH Password Authentication enabled",
                "description": "SSH allows password-based authentication",
                "severity": "low",
                "category": "initial_access",
                "source": "ssh_configs.jsonl",
                "evidence": r,
            })
    return findings


def _check_authorized_keys(extract_dir: str) -> list:
    """Check for suspicious authorized_keys entries."""
    findings = []
    records = _read_jsonl(extract_dir, "authorized_keys.jsonl")
    for r in records:
        key = r.get("key", "")
        options = r.get("options", "")
        if "command=" in options.lower():
            findings.append({
                "title": "Authorized key with forced command",
                "description": f"An SSH authorized key has a forced command: {options[:200]}",
                "severity": "high",
                "category": "persistence",
                "source": "authorized_keys.jsonl",
                "evidence": r,
            })
    return findings
