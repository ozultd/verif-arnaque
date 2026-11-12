"""Test set of French scam and legitimate messages.

Scam examples are modelled on waves reported publicly (colis, Ameli, CPF,
ANTAI, Crit'Air, "coucou maman", faux conseiller bancaire...). Domains in
scam examples are invented. Add every new wave you see: it is the best way
to measure progress.
"""

# (label, text, minimum expected level)
SCAMS = [
    ("colis chronopost",
     "Chronopost: Votre colis est en attente, reglez 1,99€ de frais de livraison sous 24h: https://chrono-suivi-colis.top/fr",
     "danger"),
    ("colis la poste raccourci",
     "La Poste : votre colis n'a pas pu etre livre. Programmez une nouvelle livraison : bit.ly/3xQz9Lp",
     "danger"),
    ("ameli carte vitale",
     "Assurance Maladie: Votre carte Vitale expire. Commandez la nouvelle avant ce soir pour garder vos droits : ameli-renouvellement-vitale.com",
     "danger"),
    ("cpf",
     "Mon Compte Formation : il vous reste 1 840€ sur votre CPF. Ils expirent le 31/12, utilisez-les ici : www.cpf-droits-formation.info",
     "danger"),
    ("antai amende",
     "ANTAI: Vous avez une amende impayee de 35€. Sans paiement sous 48h une majoration sera appliquee. https://antai-paiement-amende.xyz",
     "danger"),
    ("crit'air",
     "Votre vignette Crit'Air doit etre commandee avant le 15. Commandez-la sur certificat-air-gouv.fr pour eviter une amende de 135€.",
     "danger"),
    ("coucou maman",
     "Coucou maman c'est moi, j'ai cassé mon téléphone, voici mon nouveau numéro. Écris-moi sur WhatsApp stp c'est urgent",
     "danger"),
    ("faux conseiller banque",
     "Credit Agricole: Une operation suspecte de 649€ a ete detectee. Si vous n'etes pas a l'origine, confirmez votre identite : https://ca-securite-client.online",
     "danger"),
    ("impots remboursement",
     "DGFiP : vous beneficiez d'un remboursement d'impot de 284,90€. Pour le recevoir, verifiez vos informations : impots-remboursement.site",
     "danger"),
    ("faux support microsoft",
     "ALERTE : votre ordinateur est infecte par un virus. Appelez immediatement le support technique au 09 70 19 23 45 et installez AnyDesk.",
     "danger"),
    ("email netflix gmail",
     "---------- Forwarded message ---------\nDe : Netflix <service.netflix.fr@gmail.com>\nObjet : Votre abonnement est suspendu\n\n"
     "Bonjour, votre paiement a echoue. Mettez a jour vos informations de paiement : https://netflix-renouvellement.shop/login",
     "danger"),
    ("crypto",
     "Félicitations ! Investissez 250€ en bitcoin avec un rendement garanti de 30% par mois.",
     "suspect"),
    ("numero surtaxe",
     "Vous avez un colis en attente. Rappelez le 0899 23 45 67 pour fixer un rendez-vous.",
     "suspect"),
]

LEGIT = [
    ("code ameli", "Votre code de connexion Ameli est 482913. Ne le communiquez a personne."),
    ("dentiste", "Bonjour, rappel de votre RDV chez le Dr Martin demain a 10h. Cabinet dentaire du Lac."),
    ("famille", "Coucou maman, on arrive vers 19h dimanche, je ramène le dessert !"),
    ("pharmacie", "Pharmacie des Alpes : votre commande est prete. Bonne journee."),
    ("vrai lien ameli", "Assurance Maladie : un nouveau document est disponible dans votre compte sur ameli.fr"),
]
