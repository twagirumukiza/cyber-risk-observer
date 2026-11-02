#!/usr/bin/env python3
"""Veille éditoriale : flux RSS/Atom et catalogue CISA KEV -> data/veille.json

Ce fichier alimente l'onglet « Veille » de la rédaction : des SUJETS à traiter,
classés par rubrique et par pertinence. Rien n'est publié automatiquement et
data/items.json (les articles du journal) n'est jamais modifié ici.

Seuls le titre, l'adresse, la date et un court extrait (400 caractères) sont
conservés : l'article est à rédiger avec vos propres mots, source citée.
Bibliothèque standard uniquement (aucune dépendance à installer).
"""
import hashlib
import json
import re
import sys
import unicodedata
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

OUT = Path("data/veille.json")
MAX_ITEMS = 400
GARDER_JOURS = 30
HEADERS = {"User-Agent": "CyberRiskObserver-veille/2.0"}

# Rubriques (même numérotation que le journal et la rédaction)
ACTU, GEO, CYBER, ECO, SOCIETE, ANALYSES, CTF, NOTIONS = range(8)

# "actif": False = adresse à vérifier avant activation. Une source en panne
# n'arrête pas les autres. "poids" = bonus de pertinence de la source.
SOURCES = [
    {"nom": "CERT-FR alertes", "type": "rss", "rubrique": CYBER, "poids": 3,
     "url": "https://www.cert.ssi.gouv.fr/alerte/feed/"},
    {"nom": "CERT-FR avis", "type": "rss", "rubrique": CYBER, "poids": 1,
     "url": "https://www.cert.ssi.gouv.fr/avis/feed/"},
    {"nom": "CISA avis", "type": "rss", "rubrique": CYBER, "poids": 2,
     "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"nom": "CISA KEV", "type": "kev", "rubrique": CYBER, "poids": 2,
     "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    {"nom": "The Hacker News", "type": "rss", "rubrique": CYBER, "poids": 1,
     "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"nom": "BleepingComputer", "type": "rss", "rubrique": CYBER, "poids": 1,
     "url": "https://www.bleepingcomputer.com/feed/"},
    {"nom": "Krebs on Security", "type": "rss", "rubrique": CYBER, "poids": 1,
     "url": "https://krebsonsecurity.com/feed/"},
    {"nom": "ZATAZ", "type": "rss", "rubrique": ACTU, "poids": 1,
     "url": "https://www.zataz.com/feed/"},
    {"nom": "Le Monde International", "type": "rss", "rubrique": GEO, "poids": 0,
     "url": "https://www.lemonde.fr/international/rss_full.xml"},
    {"nom": "Le Monde Économie", "type": "rss", "rubrique": ECO, "poids": 0,
     "url": "https://www.lemonde.fr/economie/rss_full.xml"},
    {"nom": "Le Monde Pixels", "type": "rss", "rubrique": SOCIETE, "poids": 0,
     "url": "https://www.lemonde.fr/pixels/rss_full.xml"},
    {"nom": "CTFtime", "type": "rss", "rubrique": CTF, "poids": 2,
     "url": "https://ctftime.org/event/list/upcoming/rss/"},
    {"nom": "ANSSI", "type": "rss", "rubrique": ACTU, "poids": 3, "actif": False,
     "url": "https://www.ssi.gouv.fr/feed/actualite/"},
    {"nom": "CNIL", "type": "rss", "rubrique": ECO, "poids": 2, "actif": False,
     "url": "https://www.cnil.fr/fr/rss.xml"},
    {"nom": "ENISA", "type": "rss", "rubrique": ECO, "poids": 2, "actif": False,
     "url": "https://www.enisa.europa.eu/news/enisa-news/RSS"},
]

# Sujets qui intéressent le journal : (expression, étiquette, points)
INTERETS = [
    (r"\bnis ?2\b", "NIS2", 4), (r"\bdora\b", "DORA", 4), (r"\brgpd\b|\bgdpr\b", "RGPD", 4),
    (r"\bai act\b|reglement sur l.intelligence artificielle", "AI Act", 4),
    (r"cyber resilience act|\bcra\b", "CRA", 4), (r"\biso ?27001\b|\biso ?27005\b", "ISO 27001", 3),
    (r"conformite|compliance|gouvernance|\bgrc\b", "GRC", 3),
    (r"ransomware|rancongiciel", "Rançongiciel", 3),
    (r"zero.?day|0.?day|jour zero", "Zero-day", 3),
    (r"vulnerabilite|vulnerability|\bcve-\d{4}", "Vulnérabilité", 2),
    (r"supply chain|chaine d.approvisionnement|sous-traitan", "Chaîne d'approvisionnement", 3),
    (r"souverainete|sovereign", "Souveraineté", 3),
    (r"intelligence artificielle|\bia\b|\bai\b|llm|chatgpt", "IA", 2),
    (r"hamecon|phishing|usurpation", "Hameçonnage", 2),
    (r"zero trust|\bmfa\b|authentification", "Identité & accès", 2),
    (r"\bcloud\b|\bsaas\b", "Cloud", 1), (r"sauvegarde|backup", "Sauvegarde", 1),
    (r"anssi|cert-fr|\bcnil\b|\benisa\b|commission europeenne", "Institutions", 2),
    (r"cyberassurance|assurance", "Assurance", 1),
    (r"fuite de donnees|data breach|\bleak", "Fuite de données", 2),
    (r"\bctf\b|capture the flag", "CTF", 2),
]

# Rubrique suggérée d'après le contenu (le plus d'indices l'emporte)
REGLES = {
    GEO: r"guerre|conflit|otan|nato|ukrain|russ|chin|iran|israel|ingerence|diplomat|sanction|geopolit|nation.?state|state.?sponsored|\bapt ?\d+|espionnage",
    ECO: r"marche|entreprise|assurance|budget|rachat|acquisition|levee de fonds|bourse|\bpme\b|\bcout\b|investiss|regulation|amende|sanction financiere",
    SOCIETE: r"education|ecole|college|desinformation|vie privee|jeunes|citoyen|mineur|reseaux sociaux|harcelement",
    ANALYSES: r"etude|rapport|enquete|analyse|barometre|tendance|panorama",
    NOTIONS: r"bonnes pratiques|hygiene|sensibilisation|guide pratique|comment se proteger|conseils",
    CTF: r"\bctf\b|capture the flag|writeup",
}


def sans_accents(t):
    return unicodedata.normalize("NFKD", t or "").encode("ascii", "ignore").decode().lower()


def telecharger(url):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def en_date(texte):
    """Date au format AAAA-MM-JJ (UTC), ou None."""
    if not texte:
        return None
    try:
        d = parsedate_to_datetime(texte)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(texte.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%d")


def nettoyer(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html or "")).strip()


def creer(src, titre, url, date, resume="", criticite=""):
    cle = (url or titre).encode("utf-8")
    return {
        "id": hashlib.sha1(cle).hexdigest()[:12],
        "source": src["nom"], "rubrique": src["rubrique"],
        "titre": titre, "url": url,
        "date": date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "resume": resume[:400], "criticite": criticite, "poids": src.get("poids", 0),
    }


def lire_rss(src):
    racine = ET.fromstring(telecharger(src["url"]))
    for e in racine.iter():  # retire les espaces de noms (Atom, RSS, RDF)
        e.tag = e.tag.split("}")[-1]
    elements = list(racine.iter("item")) or list(racine.iter("entry"))

    def valeur(el, *noms):
        for n in noms:
            f = el.find(n)
            if f is not None:
                v = (f.text or f.get("href") or "").strip()
                if v:
                    return v
        return ""

    for el in elements:
        titre = nettoyer(valeur(el, "title"))
        url = valeur(el, "link", "id")
        if not titre or not url.startswith("http"):
            continue
        date = en_date(valeur(el, "pubDate", "published", "updated", "date"))
        resume = nettoyer(valeur(el, "description", "summary", "content"))
        yield creer(src, titre, url, date, resume)


def lire_kev(src):
    data = json.loads(telecharger(src["url"]))
    recentes = sorted(data.get("vulnerabilities", []),
                      key=lambda v: v.get("dateAdded", ""), reverse=True)[:30]
    for v in recentes:
        cve = v.get("cveID", "")
        titre = f"{cve} – {v.get('vendorProject', '')} {v.get('product', '')} : {v.get('vulnerabilityName', '')}"
        yield creer(src, titre.strip(), "https://nvd.nist.gov/vuln/detail/" + cve,
                    en_date(v.get("dateAdded")), v.get("shortDescription", ""), "Critique")


LECTEURS = {"rss": lire_rss, "kev": lire_kev}


def evaluer(it, aujourdhui):
    """Ajoute rubrique suggérée, étiquettes et score de pertinence."""
    texte = sans_accents(it["titre"] + " " + it.get("resume", ""))
    tags, pts = [], 0
    for motif, etiquette, p in INTERETS:
        if re.search(motif, texte):
            tags.append(etiquette)
            pts += p
    if it.get("criticite") == "Critique":
        pts += 3
    try:
        age = (aujourdhui - datetime.strptime(it["date"], "%Y-%m-%d").date()).days
    except ValueError:
        age = 30
    pts += 3 if age <= 1 else 2 if age <= 3 else 1 if age <= 7 else 0
    pts += it.get("poids", 0)
    meilleur, n_max = it["rubrique"], 0
    for rub, motif in REGLES.items():
        n = len(re.findall(motif, texte))
        if n > n_max:
            meilleur, n_max = rub, n
    it["rubrique"] = meilleur
    it["tags"] = tags[:5]
    it["score"] = min(pts, 20)
    return it


def main():
    aujourdhui = datetime.now(timezone.utc).date()
    limite = (aujourdhui - timedelta(days=GARDER_JOURS)).strftime("%Y-%m-%d")
    existants = {}
    if OUT.exists():
        try:
            existants = {i["id"]: i for i in json.loads(OUT.read_text(encoding="utf-8"))}
        except (ValueError, KeyError):
            existants = {}
    nouveaux, erreurs, tentees = 0, 0, 0
    for src in SOURCES:
        if src.get("actif", True) is False:
            continue
        tentees += 1
        try:
            for it in LECTEURS[src["type"]](src):
                if it["id"] not in existants:
                    existants[it["id"]] = it
                    nouveaux += 1
        except Exception as exc:  # une source en panne ne bloque pas les autres
            erreurs += 1
            print(f"[erreur] {src['nom']} : {exc}", file=sys.stderr)
    tous = [evaluer(i, aujourdhui) for i in existants.values() if i.get("date", "") >= limite]
    tous.sort(key=lambda i: (i["score"], i["date"]), reverse=True)
    items = tous[:MAX_ITEMS]
    items.sort(key=lambda i: i["date"], reverse=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{nouveaux} nouveaux sujets, {len(items)} au total, {erreurs}/{tentees} source(s) en erreur")
    if tentees and erreurs == tentees:
        sys.exit(1)


if __name__ == "__main__":
    main()
