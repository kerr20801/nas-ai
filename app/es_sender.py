"""
POST analysis events to Logstash HTTP input (nas-ai-events pipeline).
Fire-and-forget: never blocks or fails the upload if Logstash is down.
"""

import json
import logging
import subprocess
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def send_event(logstash_url: str, payload: dict) -> None:
    payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    try:
        subprocess.run(
            [
                "curl", "-4", "-s", "--max-time", "3",
                "-X", "POST", logstash_url,
                "-H", "Content-Type: application/json",
                "-d", json.dumps(payload),
            ],
            capture_output=True,
            timeout=5,
        )
    except Exception as e:
        log.warning("ES send failed (non-fatal): %s", e)
