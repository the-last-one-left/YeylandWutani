#!/usr/bin/env bash
# =============================================================================
# Yeyland Wutani - Network Discovery Pi
# self-update.sh - Pull latest code from GitHub
#
# Usage:
#   bash /opt/network-discovery/bin/self-update.sh
#
# Can be run manually OR is called automatically by initial-checkin.py
# before the first check-in email is sent.
#
# Design principles:
#   - Non-fatal: any failure logs a warning and exits 0 so callers continue
#   - Uses --ff-only pull: never creates merge commits
#   - Uses --depth=1 fetch: keeps the Pi's shallow clone lean
#   - Checks requirements.txt for changes and re-runs pip if needed
#   - Outputs "UPDATED" to stdout ONLY when an actual update was applied
#     (used by Python callers to detect whether an update occurred)
# =============================================================================

INSTALL_DIR="/opt/network-discovery"
LOG_FILE="${INSTALL_DIR}/logs/update.log"
LOCK_FILE="${INSTALL_DIR}/data/.update_running"
VENV_PIP="${INSTALL_DIR}/venv/bin/pip"

# ── Colour helpers ────────────────────────────────────────────────────────────
COLOR_ORANGE='\033[0;33m'
COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_RESET='\033[0m'

log() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${ts}] $*" | tee -a "${LOG_FILE}"
}

log_warn() { echo -e "${COLOR_ORANGE}[WARN]${COLOR_RESET} $*" >&2; log "WARN: $*"; }
log_err()  { echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2; log "ERROR: $*"; }
log_ok()   { echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $*"; log "OK: $*"; }

# ── Ensure log dir exists ─────────────────────────────────────────────────────
mkdir -p "${INSTALL_DIR}/logs" "${INSTALL_DIR}/data"

# ── Lock file: prevent concurrent update runs ─────────────────────────────────
if [[ -f "${LOCK_FILE}" ]]; then
    # Check if the lock is stale (older than 5 minutes)
    if [[ $(( $(date +%s) - $(stat -c %Y "${LOCK_FILE}" 2>/dev/null || echo 0) )) -gt 300 ]]; then
        log_warn "Stale lock file found, removing and continuing."
        rm -f "${LOCK_FILE}"
    else
        log "Update already in progress (lock file exists), skipping."
        exit 0
    fi
fi

touch "${LOCK_FILE}"
trap 'rm -f "${LOCK_FILE}"' EXIT

# ── Verify install dir is a git repo ─────────────────────────────────────────
if [[ ! -d "${INSTALL_DIR}/.git" ]]; then
    log_warn "Install directory is not a git repository: ${INSTALL_DIR}"
    log_warn "Self-update requires a git clone. Skipping."
    exit 0
fi

# ── Check git is available ────────────────────────────────────────────────────
if ! command -v git &>/dev/null; then
    log_warn "git not found. Cannot self-update."
    exit 0
fi

log "Starting self-update check (install dir: ${INSTALL_DIR})..."

# ── Get current commit hash ───────────────────────────────────────────────────
BEFORE=$(git -C "${INSTALL_DIR}" rev-parse HEAD 2>/dev/null || echo "unknown")
log "Current commit: ${BEFORE:0:8}"

# ── Fetch latest from origin (no merge yet) ───────────────────────────────────
log "Fetching from origin/main..."
if ! git -C "${INSTALL_DIR}" fetch --depth=1 origin main 2>>"${LOG_FILE}"; then
    log_warn "git fetch failed — no internet access or repo unreachable. Continuing without update."
    exit 0
fi

# ── Check if there is anything new ───────────────────────────────────────────
REMOTE=$(git -C "${INSTALL_DIR}" rev-parse origin/main 2>/dev/null || echo "unknown")

if [[ "${BEFORE}" == "${REMOTE}" ]]; then
    log "Already up to date (commit: ${BEFORE:0:8}). No update needed."
    exit 0
fi

log "Update available: ${BEFORE:0:8} -> ${REMOTE:0:8}"

# ── Pull with fast-forward only ───────────────────────────────────────────────
# --ff-only ensures we never create a merge commit.
# If local files have been modified and diverged, this will fail safely.
if ! git -C "${INSTALL_DIR}" pull --ff-only origin main 2>>"${LOG_FILE}"; then
    log_warn "git pull --ff-only failed."
    log_warn "This usually means the local repo has been manually modified."
    log_warn "Run 'git status' in ${INSTALL_DIR} to investigate."
    log_warn "Continuing without update."
    exit 0
fi

AFTER=$(git -C "${INSTALL_DIR}" rev-parse HEAD 2>/dev/null || echo "unknown")
log_ok "Update applied: ${BEFORE:0:8} -> ${AFTER:0:8}"

# ── Reinstall pip packages if requirements.txt changed ───────────────────────
if git -C "${INSTALL_DIR}" diff "${BEFORE}" "${AFTER}" --name-only 2>/dev/null | grep -q "requirements.txt"; then
    log "requirements.txt changed — updating Python packages..."
    if [[ -x "${VENV_PIP}" ]]; then
        "${VENV_PIP}" install -r "${INSTALL_DIR}/requirements.txt" --quiet 2>>"${LOG_FILE}" && \
            log_ok "Python packages updated." || \
            log_warn "pip install failed. Check ${LOG_FILE} for details."
    else
        log_warn "venv pip not found at ${VENV_PIP}. Skipping package update."
    fi
fi

# ── Fix permissions on scripts (new files may have been added) ────────────────
chmod +x "${INSTALL_DIR}/bin/"*.py 2>/dev/null || true
chmod +x "${INSTALL_DIR}/bin/"*.sh 2>/dev/null || true

# ── Signal to callers that an actual update was applied ───────────────────────
echo "UPDATED"

log "Self-update complete."
exit 0
