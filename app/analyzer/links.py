"""Link and sender extraction, plus optional online reputation checks."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .patterns import BRANDS, FREE_WEBMAILS, SUSPICIOUS_TLDS, URL_SHORTENERS

log = logging.getLogger(__name__)

_TLDS = (
    "fr|com|net|org|info|xyz|top|online|site|click|icu|live|shop|app|io|me|ly|co|cc|biz|"
    "link|vip|eu|be|ch|ru|cn|tk|ml|ga|cf|gq|pw|ws|buzz|cyou|sbs|bond|support|services|help|"
    "rest|store|fun|monster|lol|today|gd|at|asia|id|in|de"
)
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'()]+"
    r"|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + _TLDS + r")\b(?:/[^\s<>\"'()]*)?",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
SENDER_LINE_RE = re.compile(
    r"^\s*(?:from|de|expediteur|exp[ée]diteur|envoy[ée] par)\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)


def extract_urls(text: str) -> list[str]:
    urls = []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?»)]'\"")
        if url and url not in urls:
            urls.append(url)
    return urls


def host_of(url: str) -> str:
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    host = (urlsplit(url).hostname or "").lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def registered_domain(host: str) -> str:
    """Rough eTLD+1 without a public-suffix list (good enough for FR use)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"gouv", "co", "com", "org", "net", "ac", "asso"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_official(host: str, domains: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def find_sender_domain(text: str) -> str | None:
    """Original sender of a forwarded email ("De : ..." / "From: ..." lines)."""
    for m in SENDER_LINE_RE.finditer(text):
        e = EMAIL_RE.search(m.group(1))
        if e:
            return e.group(1).lower()
    return None


def link_signals(urls: list[str]) -> list[tuple[str, int, str]]:
    """Return (id, weight, explanation) tuples for suspicious links."""
    signals = []
    for url in urls:
        host = host_of(url)
        if not host:
            continue
        if host in URL_SHORTENERS:
            signals.append(("shortener", 2, f"Le lien est raccourci ({host}) pour cacher sa vraie destination."))
        if is_ip(host):
            signals.append(("ip_link", 3, "Le lien pointe vers une adresse technique (chiffres) au lieu d'un vrai site."))
        if "xn--" in host:
            signals.append(("punycode", 3, f"Le lien ({host}) utilise des lettres déguisées pour imiter un vrai site."))
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            signals.append(("suspicious_tld", 2, f"Le lien se termine par une extension souvent utilisée par les escrocs ({host})."))
        if "gouv" in host and not host.endswith(".gouv.fr"):
            signals.append(("fake_gov", 4, f"Le lien ({host}) imite un site du gouvernement, mais les vrais finissent par « .gouv.fr »."))
        for brand, info in BRANDS.items():
            if any(k in host for k in info["keywords"]) and not is_official(host, info["domains"]):
                signals.append(("lookalike", 4, f"Le lien ({host}) imite {brand} mais n'est PAS son site officiel."))
                break
        if host.count("-") >= 3 or sum(c.isdigit() for c in host) >= 5:
            signals.append(("weird_host", 1, f"L'adresse du site ({host}) a une forme inhabituelle."))
    return signals


# ---------------------------------------------------------------------------
# Optional online checks (enabled only when configured; failures are ignored)
# ---------------------------------------------------------------------------

def _get_json(url: str, timeout: float = 6.0, data: dict | None = None) -> dict | None:
    try:
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as exc:  # network errors must never break a verdict
        log.info("online check failed: %s", type(exc).__name__)
        return None


def domain_age_days(domain: str) -> int | None:
    """Age of a domain via RDAP (free, no key). None if unknown."""
    data = _get_json(f"https://rdap.org/domain/{domain}")
    if not data:
        return None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            try:
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - created).days
            except (KeyError, ValueError):
                return None
    return None


def safe_browsing_hits(urls: list[str]) -> list[str]:
    """Google Safe Browsing Lookup API v4. Needs GOOGLE_SAFE_BROWSING_KEY."""
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key or not urls:
        return []
    payload = {
        "client": {"clientId": "verif-arnaque", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u if "://" in u else "http://" + u} for u in urls[:10]],
        },
    }
    data = _get_json(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", data=payload)
    return [m["threat"]["url"] for m in (data or {}).get("matches", [])]


def online_signals(urls: list[str]) -> list[tuple[str, int, str]]:
    signals = []
    for hit in safe_browsing_hits(urls):
        signals.append(("blocklisted", 6, f"Ce lien est déjà connu comme dangereux ({host_of(hit)})."))
    if os.getenv("CHECK_DOMAIN_AGE", "1") == "1":
        seen = set()
        for url in urls[:3]:
            host = host_of(url)
            if not host or is_ip(host) or host in URL_SHORTENERS:
                continue
            domain = registered_domain(host)
            if domain in seen:
                continue
            seen.add(domain)
            age = domain_age_days(domain)
            if age is not None and age < 60:
                signals.append(("new_domain", 4, f"Le site {domain} a été créé il y a seulement {age} jours."))
    return signals


def sender_signals(sender_domain: str | None, brands: list[str]) -> list[tuple[str, int, str]]:
    if not sender_domain or not brands:
        return []
    for brand in brands:
        if is_official(sender_domain, BRANDS[brand]["domains"]):
            return []
    if sender_domain in FREE_WEBMAILS:
        return [("free_webmail_sender", 3,
                 f"L'email dit venir de {brands[0]} mais a été envoyé depuis une adresse personnelle ({sender_domain}).")]
    return [("sender_mismatch", 2,
             f"L'email dit venir de {brands[0]} mais l'adresse d'envoi ({sender_domain}) n'est pas la sienne.")]
