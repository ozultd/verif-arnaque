// Vérif'Arnaque — browser version of app/analyzer/engine.py (rules only).
// Runs entirely on the user's device: the message is never sent anywhere.
(function (root) {
  "use strict";
  const P = root.VA_PATTERNS;
  const DANGER = "danger", SUSPECT = "suspect", NO_SIGNS = "no_signs";
  const DANGER_SCORE = 6, SUSPECT_SCORE = 3;

  const TEXT = P.textSignals.map(s => ({ ...s, res: s.patterns.map(p => new RegExp(p)) }));
  const FAMILY = new RegExp(P.familyWords);
  const SHORT = new Set(P.shorteners), TLDS = new Set(P.suspiciousTlds), WEBMAIL = new Set(P.freeWebmails);

  const TLD_LIST = "fr|com|net|org|info|xyz|top|online|site|click|icu|live|shop|app|io|me|ly|co|cc|biz|" +
    "link|vip|eu|be|ch|ru|cn|tk|ml|ga|cf|gq|pw|ws|buzz|cyou|sbs|bond|support|services|help|" +
    "rest|store|fun|monster|lol|today|gd|at|asia|id|in|de";
  const URL_RE = new RegExp(
    "(?:https?://|www\\.)[^\\s<>\"'()]+" +
    "|(?<![@\\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:" + TLD_LIST + ")\\b(?:/[^\\s<>\"'()]*)?", "gi");
  const SENDER_RE = /^\s*(?:from|de|expediteur|exp[ée]diteur|envoy[ée] par)\s*:\s*(.+)$/gim;
  const EMAIL_RE = /[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/;

  const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const normalize = t => t.replace(/’/g, "'").replace(/ /g, " ")
    .normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase();

  function extractUrls(text) {
    const out = [];
    for (const m of text.matchAll(URL_RE)) {
      const u = m[0].replace(/[.,;:!?»)\]'"]+$/, "");
      if (u && !out.includes(u)) out.push(u);
    }
    return out;
  }
  function hostOf(url) {
    try {
      let h = new URL(/^https?:\/\//i.test(url) ? url : "http://" + url).hostname.toLowerCase().replace(/\.$/, "");
      return h.startsWith("www.") ? h.slice(4) : h;
    } catch (e) { return ""; }
  }
  const isOfficial = (host, domains) => domains.some(d => host === d || host.endsWith("." + d));
  const isIp = h => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith("[");

  function detectBrands(norm) {
    return Object.keys(P.brands).filter(b =>
      P.brands[b].names.some(n => new RegExp("\\b" + escapeRe(n) + "\\b").test(norm)));
  }

  function linkSignals(urls) {
    const s = [];
    for (const url of urls) {
      const host = hostOf(url);
      if (!host) continue;
      if (SHORT.has(host)) s.push(["shortener", 2, `Le lien est raccourci (${host}) pour cacher sa vraie destination.`]);
      if (isIp(host)) s.push(["ip_link", 3, "Le lien pointe vers une adresse technique (chiffres) au lieu d'un vrai site."]);
      if (host.includes("xn--")) s.push(["punycode", 3, `Le lien (${host}) utilise des lettres déguisées pour imiter un vrai site.`]);
      if (TLDS.has(host.split(".").pop())) s.push(["suspicious_tld", 2, `Le lien se termine par une extension souvent utilisée par les escrocs (${host}).`]);
      if (host.includes("gouv") && !host.endsWith(".gouv.fr")) s.push(["fake_gov", 4, `Le lien (${host}) imite un site du gouvernement, mais les vrais finissent par « .gouv.fr ».`]);
      for (const [brand, info] of Object.entries(P.brands)) {
        if (info.keywords.some(k => host.includes(k)) && !isOfficial(host, info.domains)) {
          s.push(["lookalike", 4, `Le lien (${host}) imite ${brand} mais n'est PAS son site officiel.`]);
          break;
        }
      }
      if ((host.match(/-/g) || []).length >= 3 || (host.match(/\d/g) || []).length >= 5)
        s.push(["weird_host", 1, `L'adresse du site (${host}) a une forme inhabituelle.`]);
    }
    return s;
  }

  function findSenderDomain(text) {
    for (const m of text.matchAll(SENDER_RE)) {
      const e = m[1].match(EMAIL_RE);
      if (e) return e[1].toLowerCase();
    }
    return null;
  }

  function senderSignals(domain, brands) {
    if (!domain || !brands.length) return [];
    if (brands.some(b => isOfficial(domain, P.brands[b].domains))) return [];
    if (WEBMAIL.has(domain)) return [["free_webmail_sender", 3, `L'email dit venir de ${brands[0]} mais a été envoyé depuis une adresse personnelle (${domain}).`]];
    return [["sender_mismatch", 2, `L'email dit venir de ${brands[0]} mais l'adresse d'envoi (${domain}) n'est pas la sienne.`]];
  }

  function analyze(text) {
    text = (text || "").trim();
    const norm = normalize(text);
    const raw = [];
    for (const t of TEXT) if (t.res.some(r => r.test(norm))) raw.push([t.id, t.weight, t.reason]);
    const ids = new Set(raw.map(s => s[0]));
    if (FAMILY.test(norm) && ["new_number", "broken_phone", "move_to_whatsapp"].some(i => ids.has(i)))
      raw.push(["family_impersonation", 2, "Le message se fait passer pour un proche. Appelez-le sur son numéro habituel."]);

    const urls = extractUrls(text), brands = detectBrands(norm);
    raw.push(...linkSignals(urls));
    if (urls.length && brands.length) {
      const hosts = urls.map(hostOf);
      const official = hosts.some(h => brands.some(b => isOfficial(h, P.brands[b].domains)));
      if (!official && !raw.some(s => s[0] === "lookalike"))
        raw.push(["not_official_link", 3, `Le message parle de ${brands[0]} mais le lien ne mène pas à son site officiel.`]);
    }
    if (urls.length && ids.has("credentials"))
      raw.push(["credentials_with_link", 2, "On vous demande des informations personnelles via un lien : c'est le piège classique."]);
    raw.push(...senderSignals(findSenderDomain(text), brands));

    const best = {};
    for (const [id, weight, reason] of raw) if (!best[id] || weight > best[id].weight) best[id] = { id, weight, reason };
    const signals = Object.values(best).sort((a, b) => b.weight - a.weight);
    const score = signals.reduce((n, s) => n + s.weight, 0);
    const level = score >= DANGER_SCORE ? DANGER : score >= SUSPECT_SCORE ? SUSPECT : NO_SIGNS;
    return { level, score, signals, brands, urls };
  }

  function reportLine(channel) {
    if (channel === "sms") return "• Transférez le SMS au 33700 (gratuit), puis supprimez-le.";
    if (channel === "email") return "• Signalez-le sur signal-spam.fr, puis supprimez-le.";
    return "• Si c'est un SMS : transférez-le au 33700 (gratuit). Si c'est un email : signalez-le sur signal-spam.fr. Puis supprimez-le.";
  }

  function formatReply(r, channel) {
    channel = channel || "unknown";
    const reasons = [...new Set(r.signals.map(s => s.reason))].slice(0, 3);
    const ids = new Set(r.signals.map(s => s.id));
    const L = [];
    L.push(r.level === DANGER ? "🔴 ATTENTION : c'est très probablement une ARNAQUE."
      : r.level === SUSPECT ? "🟠 MÉFIANCE : ce message présente des signes inquiétants."
      : "🟢 Je n'ai pas trouvé de signe d'arnaque.");
    if (reasons.length) L.push("", "Pourquoi :", ...reasons.map(x => "• " + x));
    L.push("", "Que faire :");
    if (r.level !== NO_SIGNS) {
      L.push("• Ne cliquez sur aucun lien et ne répondez pas.");
      L.push("• Ne donnez jamais de code, mot de passe ou numéro de carte.");
      if (ids.has("family_impersonation") || ids.has("new_number"))
        L.push("• Appelez votre proche sur son numéro HABITUEL avant de faire quoi que ce soit.");
      if (ids.has("remote_access")) L.push("• Raccrochez et n'installez aucune application demandée.");
      if (r.brands.length) L.push(`• En cas de doute, contactez ${r.brands[0]} vous-même, avec le numéro ou le site que vous connaissez déjà.`);
      L.push(reportLine(channel));
      L.push("• Déjà cliqué ou payé ? Appelez votre banque tout de suite, puis allez sur cybermalveillance.gouv.fr.");
    } else {
      L.push("• Cela ne garantit pas que le message est fiable.");
      L.push("• Règle d'or : un organisme sérieux ne demande jamais un code, un mot de passe ou un paiement urgent par SMS ou email.");
      L.push("• En cas de doute, appelez l'organisme avec le numéro que vous connaissez.");
    }
    L.push("", "Vérif'Arnaque est une aide, pas une garantie.");
    return L.join("\n");
  }

  root.VerifArnaque = { analyze, formatReply, DANGER, SUSPECT, NO_SIGNS };
})(typeof window !== "undefined" ? window : globalThis);
