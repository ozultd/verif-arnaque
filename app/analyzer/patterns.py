"""Scam patterns, brands and domain lists for the French market.

All text patterns are written WITHOUT accents and in lowercase, because the
engine normalises messages (accents stripped, lowercased) before matching.
Contributions welcome: new scam waves usually mean adding a pattern here.
"""

# --- Text signals: (id, weight, regex list, explanation shown to the user) ---
TEXT_SIGNALS = [
    (
        "urgency", 2,
        [r"\burgent", r"\bimmediat", r"dernier (rappel|avis|delai)", r"sous 24 ?h",
         r"sous 48 ?h", r"avant (minuit|ce soir|demain)", r"sans delai",
         r"\bexpir", r"\bsuspendu", r"\bbloque", r"\bdesactive", r"\bclotur"],
        "Le message vous presse d'agir vite. C'est la technique n°1 des escrocs.",
    ),
    (
        "payment", 2,
        [r"frais (de |d')?(livraison|reexpedition|douane|port|dossier)", r"\bpayer\b",
         r"\breglez\b|\bregler\b", r"\bpaiement", r"\d+[,.]\d{2} ?(€|eur)", r"€ ?\d+[,.]\d{2}"],
        "On vous demande de payer une somme, souvent petite, pour vous mettre en confiance.",
    ),
    (
        "credentials", 3,
        [r"mot de passe", r"\bidentifiant", r"code (de |a \d+ chiffres|recu|sms)?(confirmation|securite|validation|verification)",
         r"coordonnees bancaires", r"numero de (votre )?carte", r"cryptogramme",
         r"mettre a jour (vos|votre) (informations|coordonnees|donnees|dossier|compte)",
         r"confirm(er|ez) (votre|vos) (identite|informations|coordonnees)",
         r"verifi(er|ez) (votre|vos) (identite|informations|compte)"],
        "On vous demande des informations personnelles ou bancaires. Un organisme serieux ne le fait jamais par SMS ou email.",
    ),
    (
        "new_number", 2,
        [r"nouveau (numero|num|portable)", r"(c'?est|voici) mon (nouveau )?(numero|num)"],
        "Quelqu'un dit avoir changé de numéro : c'est l'arnaque « Coucou maman ».",
    ),
    (
        "broken_phone", 2,
        [r"(casse|perdu|tombe|vole)[^.\n]{0,25}(telephone|portable|tel\b)",
         r"(telephone|portable)[^.\n]{0,25}(casse|perdu|tombe|en panne|vole)"],
        "La personne dit avoir perdu ou cassé son téléphone. C'est un scénario d'arnaque très courant.",
    ),
    (
        "move_to_whatsapp", 2,
        [r"(ecri|envoie|contacte|reponds?)[a-z-]*[^.\n]{0,20}whatsapp"],
        "On vous demande de continuer la conversation sur WhatsApp, loin des contrôles habituels.",
    ),
    (
        "parcel_or_prize", 2,
        [r"felicitations", r"vous avez (gagne|ete selectionne)", r"\bremboursement",
         r"colis[^.\n]{0,30}(en attente|bloque|retenu|instance|non livre)",
         r"livraison[^.\n]{0,20}(echouee|impossible|en attente|reportee)",
         r"(pas pu|n'a pu) etre livre", r"(programmez|planifiez|reprogrammez) (une )?(nouvelle )?livraison",
         r"carte vitale[^.\n]{0,40}(expire|renouvel|commander|mise a jour)",
         r"\bcadeau\b", r"\blot\b gagnant"],
        "Le message parle d'un colis bloqué, d'un remboursement ou d'un gain : des appâts classiques.",
    ),
    (
        "threat", 2,
        [r"\bmajoration", r"\bpoursuites", r"\bhuissier", r"\bgendarmerie",
         r"\bpolice\b", r"\bamende", r"\bcontravention", r"\bsaisie", r"\bplainte"],
        "Le message fait peur (amende, poursuites, police) pour vous empêcher de réfléchir.",
    ),
    (
        "investment", 2,
        [r"\bbitcoin", r"\bcrypto", r"investissement (garanti|sans risque)",
         r"rendement (garanti|de \d+)", r"gagner de l'argent"],
        "On vous promet de l'argent facile ou un placement « garanti ». Ça n'existe pas.",
    ),
    (
        "remote_access", 4,
        [r"\banydesk", r"\bteamviewer", r"quick ?support", r"support technique",
         r"virus (detecte|trouve)", r"ordinateur (est )?(infecte|bloque|pirate)"],
        "On veut prendre le contrôle de votre ordinateur ou téléphone à distance.",
    ),
    (
        "premium_number", 2,
        [r"\b0\s?8\s?9\s?\d"],
        "Le message vous fait appeler un numéro surtaxé (commençant par 089).",
    ),
]

FAMILY_WORDS = r"\b(maman|papa|mamie|mamy|papi|papy|mamounette|daron|daronne)\b"

# --- Brands commonly impersonated in France ---
# names: how the brand appears in a message (accent-free, lowercase)
# domains: official domains (a host equal to or ending with ".domain" is official)
# keywords: strings that, found in a link's host, suggest it imitates the brand
BRANDS = {
    "Assurance Maladie (Ameli)": {
        "names": ["ameli", "assurance maladie", "carte vitale", "cpam"],
        "domains": ["ameli.fr", "assurance-maladie.fr"],
        "keywords": ["ameli", "vitale", "cpam"],
    },
    "Chronopost": {"names": ["chronopost"], "domains": ["chronopost.fr", "chronopost.com"], "keywords": ["chronopost"]},
    "Colissimo / La Poste": {
        "names": ["colissimo", "la poste", "laposte"],
        "domains": ["laposte.fr", "colissimo.fr", "laposte.net", "labanquepostale.fr"],
        "keywords": ["colissimo", "laposte", "la-poste"],
    },
    "Mondial Relay": {"names": ["mondial relay"], "domains": ["mondialrelay.fr", "mondialrelay.com"], "keywords": ["mondialrelay", "mondial-relay"]},
    "DHL": {"names": ["dhl"], "domains": ["dhl.com", "dhl.fr", "dhl.de"], "keywords": ["dhl"]},
    "UPS": {"names": ["ups"], "domains": ["ups.com"], "keywords": ["ups-"]},
    "ANTAI (amendes)": {"names": ["antai"], "domains": ["antai.gouv.fr"], "keywords": ["antai", "amende"]},
    "Impôts (DGFiP)": {
        "names": ["impots", "dgfip", "tresor public", "finances publiques"],
        "domains": ["impots.gouv.fr", "economie.gouv.fr"],
        "keywords": ["impots", "impot", "dgfip", "tresor"],
    },
    "CAF": {"names": ["caf", "allocations familiales"], "domains": ["caf.fr"], "keywords": ["caf-", "-caf"]},
    "Mon Compte Formation (CPF)": {
        "names": ["cpf", "mon compte formation", "moncompteformation"],
        "domains": ["moncompteformation.gouv.fr"],
        "keywords": ["moncompteformation", "cpf"],
    },
    "ANTS (Crit'Air, carte grise)": {
        "names": ["ants", "crit'air", "critair", "crit air", "carte grise", "vignette crit"],
        "domains": ["ants.gouv.fr", "certificat-air.gouv.fr"],
        "keywords": ["ants-", "critair", "crit-air", "certificat-air", "carte-grise"],
    },
    "France Travail": {
        "names": ["france travail", "pole emploi"],
        "domains": ["francetravail.fr", "pole-emploi.fr"],
        "keywords": ["francetravail", "france-travail", "pole-emploi", "poleemploi"],
    },
    "EDF": {"names": ["edf"], "domains": ["edf.fr"], "keywords": ["edf-"]},
    "Engie": {"names": ["engie"], "domains": ["engie.fr", "engie.com"], "keywords": ["engie"]},
    "Orange": {"names": ["orange"], "domains": ["orange.fr", "orange.com", "sosh.fr"], "keywords": ["orange-"]},
    "SFR": {"names": ["sfr"], "domains": ["sfr.fr", "red-by-sfr.fr"], "keywords": ["sfr-"]},
    "Bouygues Telecom": {"names": ["bouygues"], "domains": ["bouyguestelecom.fr"], "keywords": ["bouygues"]},
    "Crédit Agricole": {"names": ["credit agricole"], "domains": ["credit-agricole.fr", "ca-paris.fr"], "keywords": ["credit-agricole", "creditagricole"]},
    "Société Générale": {"names": ["societe generale"], "domains": ["societegenerale.fr", "sg.fr"], "keywords": ["societegenerale", "societe-generale"]},
    "BNP Paribas": {"names": ["bnp"], "domains": ["bnpparibas", "bnpparibas.com", "bnpparibas.fr", "mabanque.bnpparibas"], "keywords": ["bnp-", "bnpparibas"]},
    "LCL": {"names": ["lcl"], "domains": ["lcl.fr"], "keywords": ["lcl-"]},
    "Caisse d'Epargne": {"names": ["caisse d'epargne", "caisse depargne"], "domains": ["caisse-epargne.fr"], "keywords": ["caisse-epargne", "caisseepargne"]},
    "La Banque Postale": {"names": ["banque postale"], "domains": ["labanquepostale.fr"], "keywords": ["banquepostale", "banque-postale"]},
    "Boursorama": {"names": ["boursorama", "boursobank"], "domains": ["boursorama.com", "boursobank.com"], "keywords": ["boursorama", "boursobank"]},
    "PayPal": {"names": ["paypal"], "domains": ["paypal.com", "paypal.fr"], "keywords": ["paypal"]},
    "Amazon": {"names": ["amazon"], "domains": ["amazon.fr", "amazon.com", "amazon.de"], "keywords": ["amazon"]},
    "Netflix": {"names": ["netflix"], "domains": ["netflix.com"], "keywords": ["netflix"]},
    "Vinted": {"names": ["vinted"], "domains": ["vinted.fr", "vinted.com"], "keywords": ["vinted"]},
    "Leboncoin": {"names": ["leboncoin", "le bon coin"], "domains": ["leboncoin.fr"], "keywords": ["leboncoin", "le-bon-coin"]},
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "ow.ly", "goo.gl",
    "shorturl.at", "tiny.cc", "s.id", "t.ly", "v.gd", "urlz.fr", "lnkd.in", "buff.ly",
    "rebrand.ly", "bl.ink", "shorturl.asia",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "online", "site", "click", "icu", "live", "shop", "info", "vip", "buzz",
    "cyou", "sbs", "bond", "tk", "ml", "ga", "cf", "gq", "pw", "ws", "link", "support",
    "services", "help", "cc", "biz", "rest", "store", "fun", "monster", "lol", "today",
}

FREE_WEBMAILS = {
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.fr", "outlook.com", "outlook.fr",
    "live.com", "live.fr", "msn.com", "yahoo.com", "yahoo.fr", "icloud.com", "me.com",
    "gmx.fr", "gmx.com", "gmx.net", "aol.com", "protonmail.com", "proton.me", "free.fr",
    "sfr.fr", "orange.fr", "wanadoo.fr", "neuf.fr", "bbox.fr", "mail.com", "yandex.com",
}
