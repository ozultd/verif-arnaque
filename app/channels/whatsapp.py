"""WhatsApp Business Cloud API (Meta) channel.

Flow: the person forwards a message or sends a screenshot to the service's
WhatsApp number -> Meta calls our webhook -> we analyse -> we reply.
Replies to conversations the user starts are free within Meta's
"service conversation" window (check current pricing on Meta's site).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os

from ..analyzer import WELCOME, analyze, format_reply, llm
from .http import request_bytes, request_json

log = logging.getLogger(__name__)

GRAPH = "https://graph.facebook.com"


def _ver() -> str:
    return os.getenv("WHATSAPP_API_VERSION", "v23.0")


def _auth() -> dict:
    return {"Authorization": f"Bearer {os.environ['WHATSAPP_TOKEN']}"}


def verify_signature(raw_body: bytes, header: str | None) -> bool:
    secret = os.getenv("WHATSAPP_APP_SECRET")
    if not secret:
        log.warning("WHATSAPP_APP_SECRET not set: signature check skipped (dev only!)")
        return True
    if not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def send_text(to: str, body: str) -> None:
    phone_id = os.environ["WHATSAPP_PHONE_NUMBER_ID"]
    request_json("POST", f"{GRAPH}/{_ver()}/{phone_id}/messages", headers=_auth(), payload={
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": body[:4000], "preview_url": False},
    })


def download_media(media_id: str) -> tuple[bytes, str]:
    meta = request_json("GET", f"{GRAPH}/{_ver()}/{media_id}", headers=_auth())
    return request_bytes(meta["url"], headers=_auth()), meta.get("mime_type", "image/jpeg")


def _looks_like_greeting(text: str) -> bool:
    t = text.strip().lower()
    return len(t) < 25 and "http" not in t and "." not in t.strip(".!?")


def handle_message(msg: dict) -> str:
    """Build the reply for one incoming WhatsApp message."""
    kind = msg.get("type")
    if kind == "text":
        text = msg["text"]["body"]
        if _looks_like_greeting(text):
            return WELCOME
        return format_reply(analyze(text), "unknown")

    if kind == "image":
        if not llm.enabled():
            return ("Je ne peux pas encore lire les captures d'écran. "
                    "Transférez-moi plutôt le message lui-même (appui long > Transférer).")
        image, mime = download_media(msg["image"]["id"])
        text = llm.transcribe_image(image, mime.split(";")[0])
        if not text:
            return "Je n'arrive pas à lire de message sur cette image. Pouvez-vous m'envoyer une capture plus nette ?"
        caption = msg["image"].get("caption", "")
        return format_reply(analyze(f"{caption}\n{text}".strip()), "unknown")

    return WELCOME


def process_webhook(payload: dict, allow) -> None:
    """Handle a webhook payload. `allow(sender)` is the rate-limiter."""
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            for msg in change.get("value", {}).get("messages", []):
                sender = msg.get("from")
                if not sender:
                    continue
                try:
                    if not allow(sender):
                        send_text(sender, "Vous avez atteint la limite de vérifications pour aujourd'hui. "
                                          "Réessayez demain. En attendant : ne cliquez sur aucun lien.")
                        continue
                    send_text(sender, handle_message(msg))
                except Exception:
                    log.exception("whatsapp message failed")  # never log message content
