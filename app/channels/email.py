"""Email channel using Postmark inbound + outbound (free developer tier).

The person forwards a suspicious email to e.g. verifier@your-domain.fr.
Postmark posts it to /webhooks/email as JSON; we analyse the body (which
contains the original "De : / From:" lines) and reply by email.
Any other inbound provider (Cloudflare Email Workers, SendGrid, Mailgun)
works the same way: map its payload to `handle_inbound`.
"""

from __future__ import annotations

import base64
import html
import logging
import os
import re

from ..analyzer import WELCOME, analyze, format_reply, llm
from .http import request_json

log = logging.getLogger(__name__)


def _html_to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style).*?</\1>", " ", markup)
    markup = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", markup)
    markup = re.sub(r'(?i)<a [^>]*href="([^"]+)"[^>]*>', r" \1 ", markup)  # keep real link targets
    return html.unescape(re.sub(r"<[^>]+>", " ", markup))


def _is_auto_message(payload: dict) -> bool:
    for h in payload.get("Headers", []):
        name, value = h.get("Name", "").lower(), h.get("Value", "").lower()
        if name == "auto-submitted" and value != "no":
            return True
        if name in {"x-autoreply", "x-autorespond"} or (name == "precedence" and value in {"bulk", "auto_reply", "list"}):
            return True
    return False


def build_reply(payload: dict) -> str | None:
    """Return the reply text, or None when we must not answer (loops, robots)."""
    sender = (payload.get("FromFull") or {}).get("Email", payload.get("From", "")).lower()
    own = os.getenv("REPLY_FROM_EMAIL", "").lower()
    if not sender or (own and own in sender) or _is_auto_message(payload):
        return None

    text = payload.get("TextBody") or _html_to_text(payload.get("HtmlBody", ""))
    # Links hidden behind "Cliquez ici" are only visible in the HTML version
    if payload.get("HtmlBody"):
        hrefs = re.findall(r'href="(https?://[^"]+)"', payload["HtmlBody"], re.I)
        text += "\n" + "\n".join(dict.fromkeys(hrefs))
    text = f"{payload.get('Subject', '')}\n{text}".strip()

    # A screenshot of an SMS sent as an attachment
    for att in payload.get("Attachments", []):
        if att.get("ContentType", "").startswith("image/") and llm.enabled():
            transcript = llm.transcribe_image(base64.b64decode(att["Content"]), att["ContentType"])
            if transcript:
                return format_reply(analyze(transcript), "unknown")

    if len(text) < 40:
        return WELCOME
    return format_reply(analyze(text), "email")


def send_reply(payload: dict, body: str) -> None:
    sender = (payload.get("FromFull") or {}).get("Email", payload.get("From"))
    subject = payload.get("Subject", "")
    request_json("POST", "https://api.postmarkapp.com/email", headers={
        "X-Postmark-Server-Token": os.environ["POSTMARK_SERVER_TOKEN"],
        "Accept": "application/json",
    }, payload={
        "From": os.environ["REPLY_FROM_EMAIL"],
        "To": sender,
        "Subject": f"Vérif'Arnaque : {subject}"[:200],
        "TextBody": body,
        "MessageStream": "outbound",
        "Headers": [{"Name": "Auto-Submitted", "Value": "auto-replied"}],
    })


def sender_of(payload: dict) -> str:
    return (payload.get("FromFull") or {}).get("Email", payload.get("From", "")).lower()
