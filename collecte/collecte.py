#!/usr/bin/env python3
"""Collecte de veille cyber : flux RSS/Atom et catalogue CISA KEV -> data/items.json

Chaque élément collecté arrive avec le statut "a_valider". Rien ne doit être
publié sans relecture humaine : le site n'affiche que les éléments "valide".
Bibliothèque standard uniquement (aucune dépendance à installer).
"""
import hashlib
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

OUT = Path("data/items.json")
MAX_ITEMS = 500
HEADERS = {"User-Agent": "CyberRiskObserver-veille/1.0"}

# "actif": False = adresse à vérifier avant activation (elle peut avoir changé).
SOURCES = [
    {"nom": "CERT-FR alertes", "type": "rss", "rubrique": "Alertes & Vulnérabilités",
     "url": "https://www.cert.ssi.gouv.fr/alerte/feed/"},
    {"nom": "CERT-FR avis", "type": "rss", "rubrique": "Alertes & Vulnérabilités",
     "url": "https://www.cert.ssi.gouv.fr/avis/feed/"},
    {"nom": "CISA avis", "type": "rss", "rubrique": "Alertes & Vulnérabilités",
     "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"nom": "CISA KEV", "type": "kev", "rubrique": "Alertes & Vulnérabilités",
     "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    {"nom": "ANSSI", "type": "rss", "rubrique": "Actualités Cyber", "actif": False,
     "url": "https://www.ssi.gouv.fr/feed/actualite/"},
    {"nom": "ENISA", "type": "rss", "rubrique": "GRC & Réglementation", "actif": False,
     "url": "https://www.enisa.europa.eu/news/enisa-news/RSS"},
    {"nom": "CNIL", "type": "rss", "rubrique": "GRC & Réglementation", "actif": False,
     "url": "https://www.cnil.fr/fr/rss.xml"},
]


def telecharger(url):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def en_iso(texte):
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
    return d.astimezone(timezone.utc).isoformat()


def nettoyer(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html or "")).strip()


def creer(src, titre, url, date, resume="", criticite="", action=""):
    cle = (src["nom"] + url + titre).encode("utf-8")
    return {
        "id": hashlib.sha1(cle).hexdigest()[:12],
        "source": src["nom"],
        "rubrique": src["rubrique"],
        "titre": titre,
        "url": url,
        "date": date,
        "resume": resume[:400],
        "criticite": criticite,
        "action": action[:300],
        "statut": "a_valider",
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
        if not titre or not url:
            continue
        date = en_iso(valeur(el, "pubDate", "published", "updated", "date"))
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
                    en_iso(v.get("dateAdded")), v.get("shortDescription", ""),
                    "Critique", v.get("requiredAction", ""))


LECTEURS = {"rss": lire_rss, "kev": lire_kev}


def main():
    existants = {}
    if OUT.exists():
        existants = {i["id"]: i for i in json.loads(OUT.read_text(encoding="utf-8"))}
    nouveaux, erreurs, tentees = 0, 0, 0
    for src in SOURCES:
        if src.get("actif", True) is False:
            continue
        tentees += 1
        try:
            for it in LECTEURS[src["type"]](src):
                if it["id"] not in existants:  # un élément déjà validé n'est jamais écrasé
                    existants[it["id"]] = it
                    nouveaux += 1
        except Exception as exc:  # une source en panne ne bloque pas les autres
            erreurs += 1
            print(f"[erreur] {src['nom']} : {exc}", file=sys.stderr)
    tous = sorted(existants.values(), key=lambda i: i.get("date") or "", reverse=True)
    valides = [i for i in tous if i.get("statut") == "valide"]  # jamais écartés
    autres = [i for i in tous if i.get("statut") != "valide"][:MAX_ITEMS]
    items = sorted(valides + autres, key=lambda i: i.get("date") or "", reverse=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{nouveaux} nouveaux éléments, {len(items)} au total, {erreurs} source(s) en erreur")
    if tentees and erreurs == tentees:
        sys.exit(1)


if __name__ == "__main__":
    main()
