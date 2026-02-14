#!/usr/bin/env bash
# Yeyland Wutani - Network Discovery Pi
# reset-checkin.sh - Reset the initial check-in flag for re-testing
#
# Usage: sudo /opt/network-discovery/bin/reset-checkin.sh

FLAG_FILE="/opt/network-discovery/data/.checkin_complete"

echo "Yeyland Wutani - Network Discovery Pi"
echo "======================================"

if [[ -f "${FLAG_FILE}" ]]; then
    rm -f "${FLAG_FILE}"
    echo "Check-in flag removed. The initial check-in will run again on next boot"
    echo "(or when the initial-checkin.service is started)."
else
    echo "No check-in flag found. Initial check-in has not run yet."
fi

echo ""
echo "To trigger check-in now:"
echo "  sudo systemctl start initial-checkin.service"
