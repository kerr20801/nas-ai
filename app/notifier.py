import subprocess
import json
import logging

log = logging.getLogger(__name__)


def _escape(text: str) -> str:
    for ch in "&<>":
        text = text.replace(ch, f"&amp;" if ch == "&" else f"&lt;" if ch == "<" else "&gt;")
    return text


def send_telegram(bot_token: str, chat_id: str, result: dict, target: str):
    verdict = result["verdict"]
    emoji = {"clean": "✅", "suspicious": "⚠️", "malicious": "🚨"}.get(verdict, "❓")
    filename = _escape(result["filename"])
    reasons_html = "\n".join(f"  • {_escape(r)}" for r in result["reasons"]) or "  (none)"

    text = (
        f"{emoji} <b>NAS AI — {verdict.upper()}</b>\n"
        f"File: <code>{filename}</code>\n"
        f"Target: <code>{_escape(target)}</code>\n"
        f"Size: {result['size']:,} bytes\n"
        f"Entropy: {result['entropy']}\n"
        f"MIME: <code>{_escape(result['detected_mime'] or '?')}</code>\n"
        f"IF score: {result['if_score']}\n"
        f"Reasons:\n{reasons_html}"
    )

    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    })

    cmd = [
        "curl", "-4", "-s",
        "-X", "POST",
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        "-H", "Content-Type: application/json",
        "-d", payload,
    ]
    try:
        subprocess.run(cmd, timeout=10, capture_output=True, check=True)
    except Exception as e:
        log.error("TG send failed: %s", e)
