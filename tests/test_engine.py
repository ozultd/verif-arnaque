import pytest

from app.analyzer import DANGER, NO_SIGNS, SUSPECT, analyze, format_reply
from app.analyzer.links import extract_urls, find_sender_domain, host_of

from .samples import LEGIT, SCAMS

RANK = {NO_SIGNS: 0, SUSPECT: 1, DANGER: 2}


def run(text):
    return analyze(text, use_llm=False, use_network=False)


@pytest.mark.parametrize("label,text,minimum", SCAMS, ids=[s[0] for s in SCAMS])
def test_scams_are_flagged(label, text, minimum):
    result = run(text)
    assert RANK[result.level] >= RANK[minimum], (label, result.to_dict())


@pytest.mark.parametrize("label,text", LEGIT, ids=[s[0] for s in LEGIT])
def test_legit_messages_are_not_flagged_as_danger(label, text):
    assert run(text).level != DANGER, label


def test_official_domain_is_not_a_lookalike():
    ids = {s.id for s in run("Connectez-vous sur https://www.ameli.fr/assure").signals}
    assert "lookalike" not in ids


def test_lookalike_domain_detected():
    ids = {s.id for s in run("Payez ici : https://ameli-remboursement.com/x").signals}
    assert "lookalike" in ids


def test_url_extraction_ignores_email_addresses():
    assert extract_urls("Ecrivez a jean@gmail.com ou allez sur exemple.fr/page.") == ["exemple.fr/page"]
    assert host_of("https://www.Exemple.FR/x") == "exemple.fr"


def test_forwarded_sender_found():
    text = "-------- Message transféré --------\nDe : Ameli <contact@ameli-info.net>\nObjet : remboursement"
    assert find_sender_domain(text) == "ameli-info.net"


def test_green_reply_never_promises_safety():
    reply = format_reply(run("Bonjour, a demain pour le cafe."), "sms")
    assert reply.startswith("🟢")
    assert "ne garantit pas" in reply
    assert "sûr" not in reply


def test_red_reply_gives_reporting_advice():
    reply = format_reply(run(SCAMS[0][1]), "sms")
    assert "33700" in reply and "cybermalveillance" in reply


def test_llm_cannot_downgrade(monkeypatch):
    from app.analyzer import engine
    monkeypatch.setattr(engine.llm, "enabled", lambda: True)
    monkeypatch.setattr(engine.llm, "second_opinion", lambda t: {"verdict": "no_signs", "reasons": ["Tout va bien"]})
    assert analyze(SCAMS[0][1], use_network=False).level == DANGER


def test_llm_can_escalate(monkeypatch):
    from app.analyzer import engine
    monkeypatch.setattr(engine.llm, "enabled", lambda: True)
    monkeypatch.setattr(engine.llm, "second_opinion",
                        lambda t: {"verdict": "danger", "reasons": ["Arnaque au faux héritage"]})
    result = analyze("Bonjour, je suis notaire, vous heritez de 2 millions.", use_network=False)
    assert result.level == DANGER and result.llm_reasons


def test_disguised_letters_are_flagged_alone():
    ids = {s.id for s in run("Неllо, уоur ассоunt іѕ rеаdу. Тһаnk уоu fоr уоur оrdеr tоdау.").signals}
    assert "disguised_letters" in ids


def test_real_foreign_alphabets_are_not_disguised():
    for text in ["Привет, мама! Как дела?", "Καλημέρα! Τι κάνεις;", "Barev, ինչպե՞ս ես։"]:
        assert "disguised_letters" not in {s.id for s in run(text).signals}, text


def test_callback_reply_says_not_to_call():
    text = "Si vous n'etes pas a l'origine, appelez immediatement le 01 86 76 54 32."
    reply = format_reply(run(text), "sms")
    assert "N'appelez PAS" in reply
