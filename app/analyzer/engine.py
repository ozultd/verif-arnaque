"""Combine all signals into one verdict and a plain-French reply."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from . import links, llm
from .patterns import BRANDS, FAMILY_WORDS, TEXT_SIGNALS

DANGER, SUSPECT, NO_SIGNS = "danger", "suspect", "no_signs"
_RANK = {NO_SIGNS: 0, SUSPECT: 1, DANGER: 2}
DANGER_SCORE = 6
SUSPECT_SCORE = 3

_COMPILED = [(sid, w, [re.compile(p) for p in pats], why) for sid, w, pats, why in TEXT_SIGNALS]


@dataclass
class Signal:
    id: str
    weight: int
    reason: str


@dataclass
class Result:
    level: str
    score: int
    signals: list[Signal] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    llm_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "score": self.score,
            "signals": [s.__dict__ for s in self.signals],
            "brands": self.brands,
            "urls": self.urls,
            "llm_reasons": self.llm_reasons,
        }


def normalize(text: str) -> str:
    text = text.replace("’", "'").replace(" ", " ")
    text = unicodedata.normalize("NFKD", text)
    return "".join(c for c in text if not unicodedata.combining(c)).lower()


def detect_brands(norm: str) -> list[str]:
    found = []
    for brand, info in BRANDS.items():
        if any(re.search(r"\b" + re.escape(n) + r"\b", norm) for n in info["names"]):
            found.append(brand)
    return found


def analyze(text: str, *, use_llm: bool = True, use_network: bool = True) -> Result:
    text = (text or "").strip()
    norm = normalize(text)
    signals: list[Signal] = []

    # 1. Wording
    for sid, weight, patterns, why in _COMPILED:
        if any(p.search(norm) for p in patterns):
            signals.append(Signal(sid, weight, why))
    ids = {s.id for s in signals}
    if re.search(FAMILY_WORDS, norm) and ids & {"new_number", "broken_phone", "move_to_whatsapp"}:
        signals.append(Signal("family_impersonation", 2,
                              "Le message se fait passer pour un proche. Appelez-le sur son numéro habituel."))

    # 2. Links
    urls = links.extract_urls(text)
    brands = detect_brands(norm)
    for sid, weight, why in links.link_signals(urls):
        signals.append(Signal(sid, weight, why))
    if urls and brands:
        hosts = [links.host_of(u) for u in urls]
        official = any(links.is_official(h, BRANDS[b]["domains"]) for h in hosts for b in brands)
        if not official and "lookalike" not in {s.id for s in signals}:
            signals.append(Signal("not_official_link", 3,
                                  f"Le message parle de {brands[0]} mais le lien ne mène pas à son site officiel."))
    if urls and "credentials" in ids:
        signals.append(Signal("credentials_with_link", 2,
                              "On vous demande des informations personnelles via un lien : c'est le piège classique."))

    # 3. Sender of a forwarded email
    for sid, weight, why in links.sender_signals(links.find_sender_domain(text), brands):
        signals.append(Signal(sid, weight, why))

    # 4. Optional online checks
    if use_network and urls:
        for sid, weight, why in links.online_signals(urls):
            signals.append(Signal(sid, weight, why))

    # Deduplicate (keep the strongest of each id)
    best: dict[str, Signal] = {}
    for s in signals:
        if s.id not in best or s.weight > best[s.id].weight:
            best[s.id] = s
    signals = sorted(best.values(), key=lambda s: -s.weight)
    score = sum(s.weight for s in signals)
    level = DANGER if score >= DANGER_SCORE else SUSPECT if score >= SUSPECT_SCORE else NO_SIGNS
    result = Result(level=level, score=score, signals=signals, brands=brands, urls=urls)

    # 5. Optional LLM second opinion: may only ESCALATE the verdict
    if use_llm and text and llm.enabled():
        opinion = llm.second_opinion(text)
        if opinion and _RANK[opinion["verdict"]] > _RANK[result.level]:
            result.level = opinion["verdict"]
            result.llm_reasons = opinion["reasons"]

    return result


# ---------------------------------------------------------------------------
# Replies
# ---------------------------------------------------------------------------

def _report_line(channel: str) -> str:
    if channel == "sms":
        return "• Transférez le SMS au 33700 (gratuit), puis supprimez-le."
    if channel == "email":
        return "• Signalez-le sur signal-spam.fr, puis supprimez-le."
    return ("• Si c'est un SMS : transférez-le au 33700 (gratuit). "
            "Si c'est un email : signalez-le sur signal-spam.fr. Puis supprimez-le.")


def format_reply(result: Result, channel: str = "unknown") -> str:
    reasons = [s.reason for s in result.signals][:3] + result.llm_reasons[:2]
    reasons = list(dict.fromkeys(reasons))[:3]
    ids = {s.id for s in result.signals}
    lines: list[str] = []

    if result.level == DANGER:
        lines.append("🔴 ATTENTION : c'est très probablement une ARNAQUE.")
    elif result.level == SUSPECT:
        lines.append("🟠 MÉFIANCE : ce message présente des signes inquiétants.")
    else:
        lines.append("🟢 Je n'ai pas trouvé de signe d'arnaque.")

    if reasons:
        lines += ["", "Pourquoi :"] + [f"• {r}" for r in reasons]

    lines += ["", "Que faire :"]
    if result.level in (DANGER, SUSPECT):
        lines.append("• Ne cliquez sur aucun lien et ne répondez pas.")
        lines.append("• Ne donnez jamais de code, mot de passe ou numéro de carte.")
        if "family_impersonation" in ids or "new_number" in ids:
            lines.append("• Appelez votre proche sur son numéro HABITUEL avant de faire quoi que ce soit.")
        if "remote_access" in ids:
            lines.append("• Raccrochez et n'installez aucune application demandée.")
        if result.brands:
            lines.append(f"• En cas de doute, contactez {result.brands[0]} vous-même, "
                         "avec le numéro ou le site que vous connaissez déjà.")
        lines.append(_report_line(channel))
        lines.append("• Déjà cliqué ou payé ? Appelez votre banque tout de suite, "
                     "puis allez sur cybermalveillance.gouv.fr.")
    else:
        lines.append("• Cela ne garantit pas que le message est fiable.")
        lines.append("• Règle d'or : un organisme sérieux ne demande jamais un code, un mot de passe "
                     "ou un paiement urgent par SMS ou email.")
        lines.append("• En cas de doute, appelez l'organisme avec le numéro que vous connaissez.")

    lines += ["", "Vérif'Arnaque est une aide, pas une garantie."]
    return "\n".join(lines)


WELCOME = """👋 Bonjour ! Je suis Vérif'Arnaque, un service gratuit.

Vous avez reçu un SMS ou un email bizarre ?
1. Transférez-le-moi, ou envoyez une capture d'écran.
2. Je vous réponds en quelques secondes : 🔴 arnaque, 🟠 méfiance ou 🟢 pas de signe d'arnaque.

Ne cliquez sur aucun lien en attendant ma réponse."""
