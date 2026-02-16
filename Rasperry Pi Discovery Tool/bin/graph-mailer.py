#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
graph-mailer.py - Microsoft Graph API Email Sender

Sends HTML emails with optional attachments via the Microsoft Graph API.
Includes retry logic, exponential backoff, and throttling handling.

For messages under 4 MB, uses the fast sendMail endpoint.
For larger messages (up to 150 MB), uses createUploadSession to upload
attachments in 320 KB chunks, then sends the draft.
"""

import base64
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

import requests

# Allow running from bin/ or as a module
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from graph_auth import GraphAuth, GraphAuthError, load_credentials_from_config

logger = logging.getLogger(__name__)

GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
MAX_RETRIES = 4
RETRY_BASE_DELAY = 2  # seconds

# ── Large attachment constants ────────────────────────────────────────────
# Graph API sendMail has a 4 MB limit (including JSON envelope + base64
# expansion). We switch to the upload-session flow above 3 MB to leave
# headroom for envelope overhead and base64 ~33 % bloat.
LARGE_ATTACHMENT_THRESHOLD = 3 * 1024 * 1024  # 3 MB
# Graph API requires upload chunks to be multiples of 320 KB (327,680 bytes).
UPLOAD_CHUNK_SIZE = 327680  # 320 KB

# Inline attachment limit per the sendMail docs (base64-encoded).
MIME_TYPES = {
    ".json": "application/json",
    ".csv": "text/csv",
    ".txt": "text/plain",
    ".gz": "application/gzip",
    ".zip": "application/zip",
    ".html": "text/html",
    ".pdf": "application/pdf",
}


class GraphMailerError(Exception):
    """Raised when email sending fails."""
    pass


class GraphMailer:
    """
    Sends email via Microsoft Graph API.
    Supports HTML body, file attachments, retry with exponential backoff,
    and handling of 429 throttling responses.

    Small messages (< 3 MB) use the single-call ``sendMail`` endpoint.
    Larger messages use draft + ``createUploadSession`` chunked upload + send.
    """

    def __init__(self, auth: GraphAuth, from_email: str, to_email: str):
        self.auth = auth
        self.from_email = from_email
        self.to_email = to_email

    def _get_headers(self, content_type: str = "application/json") -> dict:
        logger.debug("Acquiring Graph API token for request...")
        token_start = time.time()
        token = self.auth.get_token()
        logger.debug(f"Token acquired in {time.time() - token_start:.2f}s")
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type,
        }

    @staticmethod
    def _mime_type(file_path: Path) -> str:
        return MIME_TYPES.get(file_path.suffix.lower(), "application/octet-stream")

    # ── Inline attachment (base64, for small messages) ────────────────────

    def _build_attachment(self, file_path: str) -> dict:
        """Build a base64-encoded file attachment payload for Graph API."""
        path = Path(file_path)
        if not path.exists():
            raise GraphMailerError(f"Attachment file not found: {file_path}")

        content_bytes = path.read_bytes()
        content_b64 = base64.b64encode(content_bytes).decode("utf-8")

        return {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": path.name,
            "contentType": self._mime_type(path),
            "contentBytes": content_b64,
        }

    # ── Message payload builders ──────────────────────────────────────────

    def _build_sendmail_payload(
        self,
        subject: str,
        body_html: str,
        attachment_paths: Optional[list] = None,
        cc_emails: Optional[list] = None,
    ) -> dict:
        """Build the Graph API sendMail message payload."""
        to_recipients = [{"emailAddress": {"address": self.to_email}}]
        cc_recipients = []
        if cc_emails:
            cc_recipients = [{"emailAddress": {"address": addr}} for addr in cc_emails]

        message = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "HTML",
                    "content": body_html,
                },
                "toRecipients": to_recipients,
                "ccRecipients": cc_recipients,
            },
            "saveToSentItems": False,
        }

        if attachment_paths:
            attachments = []
            for path in attachment_paths:
                try:
                    attachments.append(self._build_attachment(path))
                    logger.debug(f"Attachment prepared: {path}")
                except GraphMailerError as e:
                    logger.warning(f"Skipping attachment: {e}")
            if attachments:
                message["message"]["attachments"] = attachments

        return message

    def _build_draft_message(
        self,
        subject: str,
        body_html: str,
        cc_emails: Optional[list] = None,
    ) -> dict:
        """Build a draft message payload (no attachments — those are uploaded separately)."""
        to_recipients = [{"emailAddress": {"address": self.to_email}}]
        cc_recipients = []
        if cc_emails:
            cc_recipients = [{"emailAddress": {"address": addr}} for addr in cc_emails]

        return {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": body_html,
            },
            "toRecipients": to_recipients,
            "ccRecipients": cc_recipients,
        }

    # ── Sending strategies ────────────────────────────────────────────────

    def _send_with_sendmail(
        self,
        subject: str,
        body_html: str,
        attachment_paths: Optional[list] = None,
        cc_emails: Optional[list] = None,
    ) -> bool:
        """Send via the single-call sendMail endpoint (< 4 MB total)."""
        url = f"{GRAPH_API_BASE}/users/{self.from_email}/sendMail"
        payload = self._build_sendmail_payload(subject, body_html, attachment_paths, cc_emails)

        last_error = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                headers = self._get_headers()
                payload_size = len(json.dumps(payload).encode("utf-8"))
                logger.info(
                    f"Sending email via sendMail (attempt {attempt}/{MAX_RETRIES}): "
                    f"'{subject}' -> {self.to_email} "
                    f"[payload: {payload_size / 1024:.0f} KB]"
                )
                req_start = time.time()
                response = requests.post(url, headers=headers, json=payload, timeout=30)
                req_duration = time.time() - req_start

                if response.status_code == 202:
                    logger.info(
                        f"Email sent successfully in {req_duration:.1f}s: '{subject}'"
                    )
                    return True

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", RETRY_BASE_DELAY * attempt))
                    logger.warning(f"Graph API throttled (429). Waiting {retry_after}s before retry...")
                    time.sleep(retry_after)
                    continue

                if response.status_code in (401, 403):
                    error_body = response.text[:500]
                    raise GraphMailerError(
                        f"Authentication/authorization error ({response.status_code}): {error_body}"
                    )

                if response.status_code >= 500:
                    logger.warning(f"Server error {response.status_code} on attempt {attempt}. Retrying...")
                    last_error = f"Server error: {response.status_code}"
                    time.sleep(RETRY_BASE_DELAY ** attempt)
                    continue

                error_body = response.text[:500]
                raise GraphMailerError(
                    f"Unexpected Graph API error ({response.status_code}): {error_body}"
                )

            except (requests.ConnectionError, requests.Timeout) as e:
                logger.warning(f"Network error on attempt {attempt}: {e}")
                last_error = str(e)
                if attempt < MAX_RETRIES:
                    delay = RETRY_BASE_DELAY ** attempt
                    logger.info(f"Retrying in {delay}s...")
                    time.sleep(delay)

            except GraphAuthError as e:
                raise GraphMailerError(f"Authentication failed during email send: {e}") from e

        raise GraphMailerError(
            f"Failed to send email after {MAX_RETRIES} attempts. Last error: {last_error}"
        )

    def _send_with_upload_session(
        self,
        subject: str,
        body_html: str,
        attachment_paths: list,
        cc_emails: Optional[list] = None,
    ) -> bool:
        """Send via draft + createUploadSession for large attachments (up to 150 MB).

        Flow:
          1. Create a draft message (no attachments)
          2. For each attachment, create an upload session and upload in chunks
          3. Send the draft
        """
        draft_id = None
        try:
            # Step 1: Create draft message
            draft_url = f"{GRAPH_API_BASE}/users/{self.from_email}/messages"
            draft_payload = self._build_draft_message(subject, body_html, cc_emails)
            headers = self._get_headers()

            logger.info(f"Creating draft message for large email: '{subject}'")
            draft_start = time.time()
            resp = requests.post(draft_url, headers=headers, json=draft_payload, timeout=30)
            if resp.status_code not in (200, 201):
                logger.error(
                    f"Draft creation failed ({resp.status_code}): {resp.text[:500]}"
                )
                raise GraphMailerError(
                    f"Failed to create draft message ({resp.status_code}): {resp.text[:500]}"
                )
            draft_id = resp.json().get("id")
            if not draft_id:
                raise GraphMailerError("Draft message created but no ID returned.")
            logger.info(
                f"Draft message created in {time.time() - draft_start:.1f}s: {draft_id[:20]}..."
            )

            # Step 2: Upload each attachment via upload session
            for file_path in attachment_paths:
                path = Path(file_path)
                if not path.exists():
                    logger.warning(f"Skipping missing attachment: {file_path}")
                    continue
                self._upload_large_attachment(draft_id, path)

            # Step 3: Send the draft
            send_url = f"{GRAPH_API_BASE}/users/{self.from_email}/messages/{draft_id}/send"
            headers = self._get_headers()
            logger.info(f"Sending draft message: '{subject}' -> {self.to_email}")
            send_start = time.time()
            resp = requests.post(send_url, headers=headers, timeout=30)
            if resp.status_code == 202:
                total_upload_time = time.time() - draft_start
                logger.info(
                    f"Large email sent successfully in {total_upload_time:.1f}s "
                    f"(draft + upload + send): '{subject}'"
                )
                return True
            logger.error(
                f"Draft send failed ({resp.status_code}) after {time.time() - send_start:.1f}s: "
                f"{resp.text[:500]}"
            )
            raise GraphMailerError(
                f"Failed to send draft ({resp.status_code}): {resp.text[:500]}"
            )

        except GraphMailerError:
            # Clean up draft on failure
            self._delete_draft(draft_id)
            raise
        except GraphAuthError as e:
            self._delete_draft(draft_id)
            raise GraphMailerError(f"Authentication failed during upload send: {e}") from e
        except (requests.ConnectionError, requests.Timeout) as e:
            self._delete_draft(draft_id)
            raise GraphMailerError(f"Network error during upload send: {e}") from e

    def _upload_large_attachment(self, draft_id: str, path: Path) -> None:
        """Create an upload session and upload file in 320 KB chunks."""
        file_size = path.stat().st_size
        content_type = self._mime_type(path)

        # Create upload session
        session_url = (
            f"{GRAPH_API_BASE}/users/{self.from_email}/messages/{draft_id}"
            f"/attachments/createUploadSession"
        )
        session_payload = {
            "AttachmentItem": {
                "@odata.type": "#microsoft.graph.attachmentItem",
                "attachmentType": "file",
                "name": path.name,
                "size": file_size,
                "contentType": content_type,
            }
        }
        headers = self._get_headers()
        resp = requests.post(session_url, headers=headers, json=session_payload, timeout=30)
        if resp.status_code not in (200, 201):
            raise GraphMailerError(
                f"Failed to create upload session for '{path.name}' "
                f"({resp.status_code}): {resp.text[:500]}"
            )
        upload_url = resp.json().get("uploadUrl")
        if not upload_url:
            raise GraphMailerError(f"Upload session created but no uploadUrl for '{path.name}'.")

        total_chunks = (file_size + UPLOAD_CHUNK_SIZE - 1) // UPLOAD_CHUNK_SIZE
        logger.info(
            f"Uploading attachment '{path.name}' ({file_size / 1024 / 1024:.1f} MB) "
            f"in {total_chunks} x {UPLOAD_CHUNK_SIZE // 1024} KB chunks..."
        )

        # Upload in chunks
        upload_start = time.time()
        with open(path, "rb") as f:
            offset = 0
            chunk_num = 0
            while offset < file_size:
                chunk = f.read(UPLOAD_CHUNK_SIZE)
                chunk_len = len(chunk)
                end = offset + chunk_len - 1
                chunk_num += 1

                chunk_headers = {
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(chunk_len),
                    "Content-Range": f"bytes {offset}-{end}/{file_size}",
                }

                for retry in range(3):
                    try:
                        chunk_start = time.time()
                        resp = requests.put(
                            upload_url, headers=chunk_headers, data=chunk, timeout=60,
                        )
                        chunk_duration = time.time() - chunk_start
                        if resp.status_code in (200, 201, 202):
                            logger.debug(
                                f"  Chunk {chunk_num}/{total_chunks} uploaded in "
                                f"{chunk_duration:.1f}s ({chunk_len / 1024:.0f} KB)"
                            )
                            break
                        if resp.status_code == 416:
                            # Range not satisfiable — server already has this chunk
                            logger.debug(f"  Chunk {offset}-{end} already uploaded, skipping.")
                            break
                        if retry < 2:
                            logger.warning(
                                f"Chunk {chunk_num}/{total_chunks} upload failed "
                                f"({resp.status_code}), retry {retry + 1}/3: "
                                f"{resp.text[:300]}"
                            )
                            time.sleep(RETRY_BASE_DELAY * (retry + 1))
                        else:
                            raise GraphMailerError(
                                f"Chunk upload failed for '{path.name}' at offset {offset}: "
                                f"({resp.status_code}) {resp.text[:300]}"
                            )
                    except (requests.ConnectionError, requests.Timeout) as e:
                        if retry < 2:
                            logger.warning(
                                f"Network error on chunk {chunk_num}/{total_chunks}, "
                                f"retry {retry + 1}/3: {e}"
                            )
                            time.sleep(RETRY_BASE_DELAY * (retry + 1))
                        else:
                            raise GraphMailerError(
                                f"Network error uploading '{path.name}' at offset {offset}: {e}"
                            ) from e

                offset += chunk_len
                pct = min(100, int(offset / file_size * 100))
                if pct % 25 == 0 or offset >= file_size:
                    elapsed = time.time() - upload_start
                    logger.info(
                        f"  Upload progress '{path.name}': {pct}% "
                        f"({offset / 1024 / 1024:.1f}/{file_size / 1024 / 1024:.1f} MB, "
                        f"{elapsed:.0f}s elapsed)"
                    )

        upload_duration = time.time() - upload_start
        speed_kbps = (file_size / 1024) / max(upload_duration, 0.001)
        logger.info(
            f"Attachment uploaded successfully: '{path.name}' "
            f"in {upload_duration:.1f}s ({speed_kbps:.0f} KB/s)"
        )

    def _delete_draft(self, draft_id: Optional[str]) -> None:
        """Best-effort cleanup of a draft message on failure."""
        if not draft_id:
            return
        try:
            url = f"{GRAPH_API_BASE}/users/{self.from_email}/messages/{draft_id}"
            headers = self._get_headers()
            requests.delete(url, headers=headers, timeout=10)
            logger.debug(f"Cleaned up draft message: {draft_id[:20]}...")
        except Exception:
            logger.debug(f"Could not clean up draft {draft_id[:20]}... (non-critical)")

    # ── Public send API ───────────────────────────────────────────────────

    def send_email(
        self,
        subject: str,
        body_html: str,
        attachment_paths: Optional[list] = None,
        cc_emails: Optional[list] = None,
    ) -> bool:
        """
        Send an HTML email via Graph API.

        Automatically selects the appropriate strategy:
          - Small messages (< 3 MB total): single sendMail call
          - Large messages: draft + chunked upload session + send

        Returns True on success, raises GraphMailerError on failure.
        """
        # Calculate approximate total size
        html_size = len(body_html.encode("utf-8"))
        attach_size = 0
        if attachment_paths:
            for p in attachment_paths:
                path = Path(p)
                if path.exists():
                    fsize = path.stat().st_size
                    attach_size += fsize
                    logger.debug(f"Attachment: {path.name} ({fsize / 1024:.0f} KB)")
                else:
                    logger.warning(f"Attachment file not found (will skip): {p}")
        total_size = html_size + attach_size
        logger.info(
            f"Email size estimate: HTML {html_size / 1024:.0f} KB + "
            f"attachments {attach_size / 1024:.0f} KB = {total_size / 1024:.0f} KB total"
        )

        if total_size > LARGE_ATTACHMENT_THRESHOLD and attachment_paths:
            logger.info(
                f"Total message size ~{total_size / 1024 / 1024:.1f} MB "
                f"exceeds {LARGE_ATTACHMENT_THRESHOLD // 1024 // 1024} MB threshold. "
                f"Using upload session strategy."
            )
            return self._send_with_upload_session(subject, body_html, attachment_paths, cc_emails)
        else:
            return self._send_with_sendmail(subject, body_html, attachment_paths, cc_emails)


def load_mailer_from_config(
    config_path: str = "/opt/network-discovery/config/config.json",
) -> GraphMailer:
    """
    Build a GraphMailer from config.json / environment variables.
    Reads config.json exactly once and passes it down to avoid redundant I/O.
    """
    logger.debug(f"Loading mailer config from: {config_path}")

    # Load config once up front
    file_config: dict = {}
    try:
        with open(config_path, "r") as f:
            file_config = json.load(f)
    except Exception as e:
        logger.debug(f"Could not load config file {config_path}: {e}")

    auth = load_credentials_from_config(config_path, _preloaded_config=file_config)

    graph_cfg = file_config.get("graph_api", {})

    # Email addresses - env vars take precedence
    from_email = os.environ.get("GRAPH_FROM_EMAIL")
    if from_email:
        logger.debug("From email loaded from GRAPH_FROM_EMAIL env var")
    else:
        from_email = graph_cfg.get("from_email")

    to_email = os.environ.get("GRAPH_TO_EMAIL")
    if to_email:
        logger.debug("To email loaded from GRAPH_TO_EMAIL env var")
    else:
        to_email = graph_cfg.get("to_email")

    if not from_email or not to_email:
        raise GraphMailerError(
            "Missing email addresses. Set GRAPH_FROM_EMAIL and GRAPH_TO_EMAIL "
            "or configure graph_api.from_email / to_email in config.json."
        )

    logger.info(f"Mailer configured: {from_email} -> {to_email}")
    return GraphMailer(auth=auth, from_email=from_email, to_email=to_email)


# ── CLI entrypoint for quick email tests ───────────────────────────────────
if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

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
