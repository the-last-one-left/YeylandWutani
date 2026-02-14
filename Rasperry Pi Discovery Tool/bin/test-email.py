#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
test-email.py - Test Graph API email sending

Usage:
  /opt/network-discovery/venv/bin/python3 /opt/network-discovery/bin/test-email.py
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from graph_auth import GraphAuthError
from graph_mailer import GraphMailerError, load_mailer_from_config

CONFIG_PATH = "/opt/network-discovery/config/config.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

parser = argparse.ArgumentParser(description="Test Graph API email delivery")
parser.add_argument("--config", default=CONFIG_PATH)
args = parser.parse_args()

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif; max-width:500px; margin:auto; padding:20px;">
  <div style="background:#00A0D9; color:#fff; padding:20px; border-radius:4px 4px 0 0;">
    <h2 style="margin:0;">Yeyland Wutani - Network Discovery Pi</h2>
    <p style="margin:5px 0 0 0; opacity:0.85;">Email Delivery Test</p>
  </div>
  <div style="border:1px solid #d0e8f5; border-top:none; padding:20px; border-radius:0 0 4px 4px;">
    <p>&#10003; <strong>Graph API email delivery is working correctly.</strong></p>
    <p>Test sent at: <code>{timestamp}</code></p>
    <hr style="border:none; border-top:1px solid #eee;">
    <p style="color:#888; font-size:11px;">Yeyland Wutani &bull; Building Better Systems</p>
  </div>
</body>
</html>"""

try:
    mailer = load_mailer_from_config(args.config)
    mailer.send_email(
        subject=f"[Network Discovery Pi] Email Test - {timestamp}",
        body_html=html_body,
    )
    print("SUCCESS: Test email sent. Check your inbox.")
    sys.exit(0)
except (GraphMailerError, GraphAuthError) as e:
    print(f"FAILED: {e}", file=sys.stderr)
    sys.exit(1)
