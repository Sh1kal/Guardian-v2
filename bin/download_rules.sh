#!/usr/bin/env bash
# download_rules.sh
#
# Downloads the pre-compiled Zircolite Linux SIGMA ruleset from the official
# Zircolite repository and places it where Guardian expects it.
#
# Usage:
#   ./bin/download_rules.sh [<rules_dir>]
#
# If <rules_dir> is not given the script uses the GUARDIAN_RULES_DIR
# environment variable, falling back to a "rules/" directory in the project
# root.

set -euo pipefail

RULES_DIR="${1:-${GUARDIAN_RULES_DIR:-$(dirname "$0")/../rules}}"
RULES_FILE="${RULES_DIR}/rules_linux.json"

# Zircolite ships several pre-built rulesets in its GitHub releases.
# We fetch the latest Linux one from the main branch (stable enough for
# forensic work).  You can pin a specific tag by changing the URL.
RULES_URL="${ZIRCOLITE_RULES_URL:-https://raw.githubusercontent.com/wagga40/Zircolite/master/rules/rules_linux.json}"

mkdir -p "${RULES_DIR}"

echo "[*] Downloading Linux SIGMA ruleset to ${RULES_FILE} …"
if command -v curl &>/dev/null; then
    curl -fsSL "${RULES_URL}" -o "${RULES_FILE}"
elif command -v wget &>/dev/null; then
    wget -q "${RULES_URL}" -O "${RULES_FILE}"
else
    echo "[!] Neither curl nor wget found – cannot download rules." >&2
    exit 1
fi

if [ -s "${RULES_FILE}" ]; then
    echo "[+] Rules downloaded successfully: ${RULES_FILE}"
else
    echo "[!] Downloaded file is empty – check the URL or network connectivity." >&2
    rm -f "${RULES_FILE}"
    exit 1
fi
