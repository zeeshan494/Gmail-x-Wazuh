#!/usr/bin/env python3
"""
gmail_collector.py — Production Gmail API → Wazuh log collector
================================================================
Fetches new emails from Gmail API and writes Wazuh-safe syslog-format
lines to /var/ossec/logs/gmail.log.

LOG FORMAT (one line per email, no newlines):
  integration=gmail from="sender@domain.com" subject="Clean subject" timestamp="2024-01-15T09:30:00Z"

WAZUH SAFETY RULES ENFORCED:
  1. No newlines inside field values (would break syslog line parsing)
  2. No double-quotes inside field values (would break decoder regex)
  3. No null bytes or control characters
  4. Subject truncated at 200 chars to prevent "Too many fields" on long tokens
  5. All fields always present, never empty (malformed log detection)
  6. Log rotation awareness via append mode + size check

SETUP:
  1. pip3 install google-auth google-auth-oauthlib google-api-python-client
  2. Create OAuth2 credentials in Google Cloud Console
  3. Download credentials.json to same directory as this script
  4. First run: python3 gmail_collector.py --auth  (opens browser for OAuth)
  5. Subsequent runs: python3 gmail_collector.py (or via cron)

CRON EXAMPLE (every 5 minutes):
  */5 * * * * /usr/bin/python3 /opt/gmail-wazuh/gmail_collector.py >> /var/log/gmail_collector_errors.log 2>&1
"""

import os
import re
import sys
import json
import logging
import argparse
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

# ─── Google API imports ───────────────────────────────────────────────────────
try:
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("ERROR: Missing Google API libraries. Run: pip3 install google-auth google-auth-oauthlib google-api-python-client", file=sys.stderr)
    sys.exit(1)


# ─── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR        = Path(__file__).parent.resolve()
CREDENTIALS_FILE  = SCRIPT_DIR / "credentials.json"
TOKEN_FILE        = SCRIPT_DIR / "token.json"
STATE_FILE        = SCRIPT_DIR / "last_history_id.txt"

WAZUH_LOG_FILE    = Path("/var/ossec/logs/gmail.log")
MAX_LOG_SIZE_MB   = 100          # Rotate if log exceeds this size
SUBJECT_MAX_LEN   = 200          # Truncate subjects longer than this
MAX_EMAILS_PER_RUN = 500         # Safety cap: never write more than this per run

# Gmail API scopes — readonly is sufficient
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# ─── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
log = logging.getLogger("gmail_collector")


# ─── Wazuh-safe string sanitisation ──────────────────────────────────────────
def sanitise_field(value: str, max_len: int = 500) -> str:
    """
    Make a string safe to embed in a Wazuh syslog key="value" field.

    Rules:
      - Replace double-quotes with single-quotes (protects decoder regex)
      - Strip all control characters (newlines, tabs, nulls, ESC, etc.)
      - Normalise unicode to NFC (avoids multi-codepoint surprises)
      - Truncate to max_len (prevents "Too many fields" on huge subjects)
      - Replace empty result with a safe sentinel

    Args:
        value:   Raw string from Gmail API
        max_len: Maximum allowed length after cleaning

    Returns:
        Cleaned string, guaranteed safe for key="value" embedding
    """
    if not value:
        return "(empty)"

    # Normalise unicode (NFC) — prevents confusable character attacks
    value = unicodedata.normalize("NFC", value)

    # Strip control characters (newlines, tabs, carriage returns, nulls, etc.)
    # Keep only printable characters and safe whitespace (regular space only)
    value = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", value)

    # Replace double-quotes with typographic quotes so decoder regex is not broken
    # Using standard apostrophe/single-quote is more readable in SIEM dashboards
    value = value.replace('"', "'")

    # Collapse multiple consecutive spaces into one
    value = re.sub(r" {2,}", " ", value).strip()

    # Truncate
    if len(value) > max_len:
        value = value[:max_len] + "...[TRUNCATED]"

    # Final safety: if nothing useful remains, return sentinel
    return value if value.strip() else "(empty)"


def build_log_line(sender: str, subject: str, timestamp: str) -> str:
    """
    Build a single Wazuh syslog log line.

    Output format (EXACTLY):
      integration=gmail from="sender" subject="subject" timestamp="ISO_TIME"

    All fields are sanitised before embedding.
    """
    clean_sender    = sanitise_field(sender,    max_len=254)   # max email length
    clean_subject   = sanitise_field(subject,   max_len=SUBJECT_MAX_LEN)
    clean_timestamp = sanitise_field(timestamp, max_len=35)

    return (
        f'integration=gmail '
        f'from="{clean_sender}" '
        f'subject="{clean_subject}" '
        f'timestamp="{clean_timestamp}"'
    )


# ─── Log file management ──────────────────────────────────────────────────────
def ensure_log_dir() -> None:
    """Create /var/ossec/logs/ if missing (shouldn't happen but be safe)."""
    WAZUH_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def check_log_rotation() -> None:
    """
    Warn if the log file is getting large.
    Wazuh handles log rotation via its own mechanism, but we warn early.
    This does NOT delete the file — let Wazuh's logrotate handle that.
    """
    if WAZUH_LOG_FILE.exists():
        size_mb = WAZUH_LOG_FILE.stat().st_size / (1024 * 1024)
        if size_mb > MAX_LOG_SIZE_MB:
            log.warning(
                f"Log file {WAZUH_LOG_FILE} is {size_mb:.1f}MB — "
                f"consider checking Wazuh log rotation config."
            )


def write_log_lines(lines: list[str]) -> int:
    """
    Append log lines to Wazuh log file.
    Each line gets a trailing newline. Lines are written atomically per batch.

    Returns: number of lines written
    """
    if not lines:
        return 0

    ensure_log_dir()
    check_log_rotation()

    with open(WAZUH_LOG_FILE, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")

    return len(lines)


# ─── State management (incremental fetch) ────────────────────────────────────
def load_last_history_id() -> str | None:
    """Load the Gmail historyId from the last run (for incremental fetch)."""
    if STATE_FILE.exists():
        raw = STATE_FILE.read_text().strip()
        return raw if raw else None
    return None


def save_history_id(history_id: str) -> None:
    """Persist the latest Gmail historyId so next run fetches only new messages."""
    STATE_FILE.write_text(str(history_id))


# ─── Gmail API authentication ─────────────────────────────────────────────────
def get_credentials() -> Credentials:
    """
    Load or refresh OAuth2 credentials.
    On first run (no token.json), opens browser for user authorisation.
    """
    creds = None

    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                log.info("OAuth2 token refreshed successfully.")
            except Exception as e:
                log.error(f"Token refresh failed: {e}. Re-authorisation required.")
                creds = None

        if not creds:
            if not CREDENTIALS_FILE.exists():
                log.error(f"credentials.json not found at {CREDENTIALS_FILE}")
                sys.exit(1)
            flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), SCOPES)
            creds = flow.run_local_server(port=0)
            log.info("OAuth2 authorisation completed.")

        # Save for next run
        TOKEN_FILE.write_text(creds.to_json())

    return creds


# ─── Email extraction helpers ─────────────────────────────────────────────────
def extract_header(headers: list[dict], name: str) -> str:
    """Extract a header value by name from Gmail message headers list."""
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""


def get_message_details(service, msg_id: str) -> dict | None:
    """
    Fetch a single message's From/Subject/Date headers.
    Returns a dict or None on error.
    """
    try:
        msg = service.users().messages().get(
            userId="me",
            id=msg_id,
            format="metadata",
            metadataHeaders=["From", "Subject", "Date"]
        ).execute()

        headers = msg.get("payload", {}).get("headers", [])
        internal_date_ms = int(msg.get("internalDate", 0))
        # Use internalDate (milliseconds epoch) for reliable timestamp
        ts = datetime.fromtimestamp(internal_date_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return {
            "from":      extract_header(headers, "From") or "(unknown sender)",
            "subject":   extract_header(headers, "Subject") or "(no subject)",
            "timestamp": ts,
        }
    except HttpError as e:
        log.warning(f"Failed to fetch message {msg_id}: {e}")
        return None


# ─── Core fetch logic ─────────────────────────────────────────────────────────
def fetch_new_emails(service) -> list[dict]:
    """
    Fetch new emails using Gmail History API (incremental) or
    fall back to listing recent messages on first run.

    Returns list of dicts: [{from, subject, timestamp}, ...]
    """
    last_history_id = load_last_history_id()
    emails = []

    try:
        # Get current profile to have latest historyId
        profile = service.users().getProfile(userId="me").execute()
        current_history_id = profile["historyId"]

        if last_history_id:
            # ── Incremental fetch via History API ──────────────────────────
            log.info(f"Fetching history since historyId={last_history_id}")
            try:
                history_response = service.users().history().list(
                    userId="me",
                    startHistoryId=last_history_id,
                    historyTypes=["messageAdded"]
                ).execute()

                message_ids = []
                for record in history_response.get("history", []):
                    for added in record.get("messagesAdded", []):
                        message_ids.append(added["message"]["id"])

                log.info(f"Found {len(message_ids)} new messages via history API.")

                # Cap at MAX_EMAILS_PER_RUN
                for msg_id in message_ids[:MAX_EMAILS_PER_RUN]:
                    details = get_message_details(service, msg_id)
                    if details:
                        emails.append(details)

            except HttpError as e:
                if e.resp.status == 404:
                    # historyId expired (>30 days) — fall back to recent list
                    log.warning("historyId expired, falling back to recent message list.")
                    last_history_id = None
                else:
                    raise

        if not last_history_id:
            # ── First run or fallback: list recent messages ────────────────
            log.info("First run: fetching last 50 messages.")
            results = service.users().messages().list(
                userId="me",
                maxResults=50,
                labelIds=["INBOX"]
            ).execute()

            messages = results.get("messages", [])
            log.info(f"Found {len(messages)} recent messages.")

            for msg in messages[:MAX_EMAILS_PER_RUN]:
                details = get_message_details(service, msg["id"])
                if details:
                    emails.append(details)

        # Save new historyId for next run
        save_history_id(current_history_id)
        log.info(f"Saved historyId={current_history_id}")

    except HttpError as e:
        log.error(f"Gmail API error: {e}")
        raise

    return emails


# ─── Main entry point ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Gmail API → Wazuh log collector")
    parser.add_argument("--auth", action="store_true", help="Force re-authorisation (opens browser)")
    parser.add_argument("--dry-run", action="store_true", help="Print log lines to stdout, do not write to file")
    parser.add_argument("--test-line", action="store_true", help="Write a single test line and exit")
    args = parser.parse_args()

    # ── Test mode: write one known-good line ──────────────────────────────────
    if args.test_line:
        test_line = build_log_line(
            sender="test@gmail.com",
            subject="Wazuh integration test",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        if args.dry_run:
            print(test_line)
        else:
            written = write_log_lines([test_line])
            print(f"Wrote {written} test line(s) to {WAZUH_LOG_FILE}")
        return

    # ── Force re-auth ─────────────────────────────────────────────────────────
    if args.auth and TOKEN_FILE.exists():
        TOKEN_FILE.unlink()
        log.info("Removed existing token.json — will re-authorise.")

    # ── Get Gmail service ─────────────────────────────────────────────────────
    try:
        creds   = get_credentials()
        service = build("gmail", "v1", credentials=creds)
    except Exception as e:
        log.error(f"Failed to initialise Gmail service: {e}")
        sys.exit(1)

    # ── Fetch and write ───────────────────────────────────────────────────────
    try:
        emails = fetch_new_emails(service)
        log.info(f"Processing {len(emails)} email(s).")

        log_lines = []
        for email in emails:
            line = build_log_line(
                sender=email["from"],
                subject=email["subject"],
                timestamp=email["timestamp"]
            )
            log_lines.append(line)

        if args.dry_run:
            for line in log_lines:
                print(line)
            print(f"\n[DRY RUN] Would have written {len(log_lines)} line(s).")
        else:
            written = write_log_lines(log_lines)
            log.info(f"Wrote {written} log line(s) to {WAZUH_LOG_FILE}")

    except Exception as e:
        log.error(f"Fatal error during email fetch/write: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
