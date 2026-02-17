#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
graph-mailer.py - CLI entry point for sending emails via Microsoft Graph API.

The reusable module lives at lib/graph_mailer.py (importable as `graph_mailer`).
This script is a thin CLI wrapper around it for quick manual email tests.

Usage:
    python3 graph-mailer.py [--subject TEXT] [--body HTML] [--config PATH]
                            [--attachment FILE ...]
"""

import logging
import sys
from pathlib import Path

# Resolve lib/ relative to this script so it works from any working directory
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graph_auth import GraphAuthError
from graph_mailer import GraphMailer, GraphMailerError, load_mailer_from_config  # noqa: F401

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="Send a test email via Graph API")
    parser.add_argument("--subject", default="Graph API Test - Yeyland Wutani Network Discovery Pi")
    parser.add_argument("--body", default="<h1>Test Email</h1><p>Graph API email delivery is working.</p>")
    parser.add_argument("--config", default="/opt/network-discovery/config/config.json")
    parser.add_argument("--attachment", action="append", dest="attachments", help="File path to attach")
    args = parser.parse_args()

    try:
        mailer = load_mailer_from_config(args.config)
        mailer.send_email(
            subject=args.subject,
            body_html=args.body,
            attachment_paths=args.attachments,
        )
        logger.info("CLI test email sent successfully.")
    except (GraphMailerError, GraphAuthError) as e:
        logger.error(f"CLI test email failed: {e}", exc_info=True)
        sys.exit(1)
