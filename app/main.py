"""Vérif'Arnaque web service: web page, WhatsApp webhook, email webhook.

Run locally:  uvicorn app.main:app --reload
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os
import time
from collections import defaultdict
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .analyzer import analyze, format_reply, llm
from .channels import email as email_channel
from .channels import whatsapp

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("verif-arnaque")

app = FastAPI(title="Vérif'Arnaque", version="0.1.0")
STATIC = Path(__file__).parent / "static"

# --- Privacy-friendly rate limit: hashed sender ids, in memory, per day ---
DAILY_LIMIT = int(os.getenv("DAILY_LIMIT_PER_USER", "30"))
_usage: dict[str, list[float]] = defaultdict(list)


def allow(sender: str) -> bool:
    key = hashlib.sha256(sender.encode()).hexdigest()[:16]
    now = time.time()
    _usage[key] = [t for t in _usage[key] if now - t < 86400]
    if len(_usage[key]) >= DAILY_LIMIT:
        return False
    _usage[key].append(now)
    return True


# --------------------------------- Web ------------------------------------

class CheckText(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)
    channel: str = Field("unknown", pattern="^(sms|email|unknown)$")


class CheckImage(BaseModel):
    image_base64: str = Field(..., max_length=8_000_000)
    media_type: str = "image/png"


@app.get("/")
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    return {"ok": True, "llm": llm.enabled()}


@app.post("/api/check")
def check_text(body: CheckText, request: Request):
    if not allow(request.client.host if request.client else "web"):
        raise HTTPException(429, "Limite atteinte pour aujourd'hui.")
    result = analyze(body.text)
    return {**result.to_dict(), "reply": format_reply(result, body.channel)}


@app.post("/api/check-image")
def check_image(body: CheckImage, request: Request):
    if not llm.enabled():
        raise HTTPException(503, "La lecture des captures d'écran n'est pas activée.")
    if not allow(request.client.host if request.client else "web"):
        raise HTTPException(429, "Limite atteinte pour aujourd'hui.")
    try:
        image = base64.b64decode(body.image_base64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, "Image illisible.")
    text = llm.transcribe_image(image, body.media_type)
    if not text:
        return {"level": None, "reply": "Je n'arrive pas à lire de message sur cette image."}
    result = analyze(text)
    return {**result.to_dict(), "reply": format_reply(result, "unknown"), "transcript": text}


# ------------------------------- WhatsApp ---------------------------------

@app.get("/webhooks/whatsapp")
def whatsapp_verify(request: Request):
    p = request.query_params
    if p.get("hub.mode") == "subscribe" and p.get("hub.verify_token") == os.getenv("WHATSAPP_VERIFY_TOKEN"):
        return PlainTextResponse(p.get("hub.challenge", ""))
    raise HTTPException(403)


@app.post("/webhooks/whatsapp")
async def whatsapp_incoming(request: Request, tasks: BackgroundTasks):
    raw = await request.body()
    if not whatsapp.verify_signature(raw, request.headers.get("X-Hub-Signature-256")):
        raise HTTPException(401)
    payload = await request.json()
    tasks.add_task(whatsapp.process_webhook, payload, allow)  # answer Meta fast, work after
    return {"ok": True}


# -------------------------------- Email -----------------------------------

@app.post("/webhooks/email")
async def email_incoming(request: Request, tasks: BackgroundTasks):
    token = os.getenv("INBOUND_EMAIL_TOKEN")
    if not token or not hmac.compare_digest(request.query_params.get("token", ""), token):
        raise HTTPException(401)
    payload = await request.json()
    tasks.add_task(_process_email, payload)
    return {"ok": True}


def _process_email(payload: dict) -> None:
    try:
        sender = email_channel.sender_of(payload)
        if not sender or not allow(sender):
            return
        reply = email_channel.build_reply(payload)
        if reply:
            email_channel.send_reply(payload, reply)
    except Exception:
        log.exception("email processing failed")  # never log message content
