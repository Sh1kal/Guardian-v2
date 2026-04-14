"""
Centralized configuration for GUARDIAN pipeline.
All paths, URLs, and settings are defined here. Override via environment variables.
"""

import os

# Base paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("GUARDIAN_DATA_DIR", os.path.join(BASE_DIR, "data"))
CASES_DIR = os.path.join(DATA_DIR, "cases")
RULES_DIR = os.environ.get("GUARDIAN_RULES_DIR", os.path.join(BASE_DIR, "rules"))

# Zircolite
ZIRCOLITE_PATH = os.environ.get(
    "GUARDIAN_ZIRCOLITE_PATH", os.path.join(BASE_DIR, "zircolite.py")
)
ZIRCOLITE_LINUX_RULES = os.path.join(RULES_DIR, "rules_linux.json")
ZIRCOLITE_FIELD_MAPPINGS = os.path.join(BASE_DIR, "config", "fieldMappings.json")
ZIRCOLITE_GUI_ZIP = os.path.join(BASE_DIR, "gui", "zircogui.zip")
ZIRCOLITE_TEMPLATE = os.path.join(BASE_DIR, "templates", "exportForZircoGui.tmpl")

# MongoDB
MONGO_URI = os.environ.get("GUARDIAN_MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.environ.get("GUARDIAN_MONGO_DB", "guardian")

# Kuiper
KUIPER_URL = os.environ.get("GUARDIAN_KUIPER_URL", "http://localhost:9000")
# Kuiper REST API base URL – defaults to the standard v1 path on the same host
KUIPER_API_URL = os.environ.get(
    "GUARDIAN_KUIPER_API_URL",
    os.environ.get("GUARDIAN_KUIPER_URL", "http://localhost:9000").rstrip("/") + "/api/v1",
)

# Flask
SECRET_KEY = os.environ.get("GUARDIAN_SECRET_KEY", "guardian-secret-change-me")
MAX_UPLOAD_SIZE_MB = int(os.environ.get("GUARDIAN_MAX_UPLOAD_MB", "500"))
ALLOWED_EXTENSIONS = {".zip"}

# Fennec artifact categories (known JSONL file types from Fennec)
FENNEC_ARTIFACT_CATEGORIES = {
    "system": [
        "system_info.jsonl", "os_version.jsonl", "uptime.jsonl",
        "mounts.jsonl", "deb_packages.jsonl", "rpm_packages.jsonl",
    ],
    "users": [
        "users.jsonl", "groups.jsonl", "shadow.jsonl",
        "logged_in_users.jsonl", "last.jsonl", "bad_logins.jsonl",
        "sudoers.jsonl", "authorized_keys.jsonl",
    ],
    "network": [
        "netstat.jsonl", "interface_addresses.jsonl", "routes.jsonl",
        "arp_cache.jsonl", "iptables.jsonl", "etc_hosts.jsonl",
    ],
    "processes": [
        "process_list.jsonl", "process_envs.jsonl",
        "process_open_files.jsonl", "startup_items.jsonl",
    ],
    "security": [
        "suid_bin.jsonl", "selinux_settings.jsonl",
        "shell_history.jsonl", "ssh_configs.jsonl",
        "crontab.jsonl", "auth_log.jsonl", "audit_log.jsonl",
        "secure_log.jsonl",
    ],
    "services": [
        "docker_containers.jsonl", "nginx_access.jsonl",
        "apt_sources.jsonl", "yum_sources.jsonl",
    ],
    "files": [
        "file_list.jsonl",
    ],
    "logs": [
        "syslog_log.jsonl", "messages_log.jsonl",
        "fennec.log",
    ],
}

# Ensure directories exist
os.makedirs(CASES_DIR, exist_ok=True)
os.makedirs(RULES_DIR, exist_ok=True)
