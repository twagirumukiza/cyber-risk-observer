#!/usr/bin/env python3
"""Mise à jour automatique de l'observatoire (Threat Actors Observatory).

Lit data/acteurs.json (les acteurs de l'observatoire) et écrit data/acteurs-veille.json :
  - mitre    : pour chaque acteur reconnu dans la base MITRE ATT&CK (page des groupes),
               l'identifiant (Gxxxx), l'adresse de la fiche et les alias connus ;
  - actus    : les dernières mentions, titre, source, date et adresse :
               * sources de référence (CISA, ANSSI / CERT-FR, Europol, Mandiant / Google
                 Threat Intelligence, MITRE) : flux officiels + recherche limitée à ces sites,
                 repérées par "r": 1 ;
               * presse (Google Actualités) ;
  - nouveaux : des groupes MITRE absents du registre mais cités dans data/veille.json.

L'éditeur (onglet Observatoire > « Mettre à jour depuis internet ») applique ces
informations aux fiches. Rien n'est inventé : seuls l'identifiant MITRE, les alias MITRE
et la dernière mention dans la presse sont renseignés, les textes rédigés ne sont jamais écrasés.
Bibliothèque standard uniquement. Une source en panne n'arrête pas les autres.
"""
import json
import re
import sys
import time
import unicodedata
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path

ACT = Path("data/acteurs.json")
VEILLE = Path("data/veille.json")
OUT = Path("data/acteurs-veille.json")
HEAD = {"User-Agent": "Mozilla/5.0 (compatible; CyberRiskObserver-acteurs/1.0)"}
MITRE_URL = "https://attack.mitre.org/groups/"
JOURS = 60            # fenêtre de recherche presse
PAR_ACTEUR = 5        # mentions conservées par acteur
PAUSE = 0.8           # secondes entre deux requêtes presse
CONTEXTE = "(cyberattack OR hackers OR malware OR ransomware OR cyber OR cyberattaque)"
EDITIONS = [("en-US", "US", "US:en"), ("fr", "FR", "FR:fr")]
JOURS_REF = 365       # les sources officielles publient moins souvent : fenêtre plus large
REF_MAX = 3           # mentions de référence conservées par acteur (le reste : presse)
# Sites de référence : domaine -> nom affiché
REF_SITES = {
    "cisa.gov": "CISA", "cyber.gouv.fr": "ANSSI", "ssi.gouv.fr": "ANSSI", "cert.ssi.gouv.fr": "CERT-FR",
    "europol.europa.eu": "Europol", "mandiant.com": "Mandiant", "cloud.google.com": "Google Threat Intelligence",
    "cloudblog.withgoogle.com": "Google Threat Intelligence", "attack.mitre.org": "MITRE ATT&CK",
}
# Flux officiels lus directement (une adresse qui ne répond plus est ignorée et signalée dans "erreurs").
REF_FEEDS = [
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("CERT-FR", "https://www.cert.ssi.gouv.fr/cti/feed/"),
    ("CERT-FR", "https://www.cert.ssi.gouv.fr/alerte/feed/"),
    ("Mandiant / Google", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
    ("Europol", "https://www.europol.europa.eu/rss.xml"),
]


def get(url, timeout=40):
    req = urllib.request.Request(url, headers=HEAD)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def norm(s):
    s = unicodedata.normalize("NFD", str(s).lower())
    return re.sub(r"[^a-z0-9]+", "", "".join(c for c in s if unicodedata.category(c) != "Mn"))


def core(s):
    """Nom normalisé sans suffixe générique (« Sandworm Team » = « Sandworm »)."""
    s = re.sub(r"\b(team|group|gang|apt)\s*$", "", str(s).strip(), flags=re.I)
    return norm(s)


# --- MITRE ATT&CK -----------------------------------------------------------------
class _Rows(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows, self.cur, self.cell, self.td = [], None, None, False

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.cur = []
        elif tag == "td" and self.cur is not None:
            self.td, self.cell = True, []

    def handle_endtag(self, tag):
        if tag == "td" and self.cur is not None and self.cell is not None:
            self.cur.append(re.sub(r"\s+", " ", "".join(self.cell)).strip())
            self.td, self.cell = False, None
        elif tag == "tr" and self.cur is not None:
            self.rows.append(self.cur)
            self.cur = None

    def handle_data(self, d):
        if self.td and self.cell is not None:
            self.cell.append(d)


def parse_mitre(html):
    p = _Rows()
    p.feed(html)
    out = []
    for r in p.rows:
        if len(r) < 2:
            continue
        m = re.search(r"G\d{4}", r[0])
        if not m:
            continue
        alias = [a.strip() for a in (r[2] if len(r) > 2 else "").split(",") if a.strip()]
        out.append({"id": m.group(0), "nom": r[1], "alias": alias, "url": f"https://attack.mitre.org/groups/{m.group(0)}/"})
    return out


def termes(a):
    t = []
    for x in re.split(r"\s+/\s+", a.get("nom", "")):
        t.append(x.strip())
    for x in re.split(r"\s*[/,]\s*", a.get("alias", "") or ""):
        t.append(x.strip())
    return [x for x in dict.fromkeys(t) if len(x) >= 3]


def associer(acteurs, groupes):
    idx = {}
    for g in groupes:
        for n in [g["nom"]] + g["alias"]:
            idx.setdefault(core(n), g)
    res = {}
    for a in acteurs:
        for t in termes(a):
            g = idx.get(core(t))
            if g:
                res[a["id"]] = {"id": g["id"], "nom": g["nom"], "url": g["url"], "alias": g["alias"][:12]}
                break
    return res


# --- Presse (Google Actualités RSS) ----------------------------------------------------
def parse_news(xml, termes_, jours=None):
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    res = [re.compile(r"(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])", re.I) for t in termes_]
    lim = datetime.now(timezone.utc) - timedelta(days=jours or JOURS)
    out = []
    for it in root.iter("item"):
        titre = (it.findtext("title") or "").strip()
        lien = (it.findtext("link") or "").strip()
        src = (it.findtext("source") or "").strip()
        se = it.find("source")
        host = urllib.parse.urlparse(se.get("url", "")).netloc.lower().replace("www.", "") if se is not None else ""
        if not src and " - " in titre:
            src = titre.rsplit(" - ", 1)[1].strip()
        if " - " in titre and src and titre.endswith(" - " + src):
            titre = titre[: -len(src) - 3].strip()
        try:
            d = parsedate_to_datetime(it.findtext("pubDate") or "")
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if d < lim or not titre or not lien.startswith("http"):
            continue
        if not any(r.search(titre) for r in res):
            continue
        out.append({"t": titre[:220], "s": src[:80] or "Presse", "d": d.astimezone(timezone.utc).strftime("%Y-%m-%d"), "u": lien, "_h": host})
    return out


def label_ref(host):
    for dom, nom in REF_SITES.items():
        if host == dom or host.endswith("." + dom):
            return nom
    return None


def parse_feed(xml, nom, jours=JOURS_REF):
    """Flux RSS ou Atom officiel -> éléments {t, s, d, u, _x} (_x = titre + résumé pour la recherche)."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    lim = datetime.now(timezone.utc) - timedelta(days=jours)
    out = []
    for it in list(root.iter("item")) + list(root.iter("{http://www.w3.org/2005/Atom}entry")):
        def tx(*tags):
            for t in tags:
                e = it.find(t)
                if e is not None and (e.text or "").strip():
                    return e.text.strip()
            return ""
        A = "{http://www.w3.org/2005/Atom}"
        titre = tx("title", A + "title")
        lien = tx("link")
        if not lien:
            le = it.find(A + "link")
            lien = (le.get("href") if le is not None else "") or ""
        resume = re.sub(r"<[^>]+>", " ", tx("description", A + "summary", A + "content"))
        raw = tx("pubDate", A + "published", A + "updated", "{http://purl.org/dc/elements/1.1/}date")
        try:
            try:
                d = parsedate_to_datetime(raw)
            except Exception:
                d = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if d < lim or not titre or not lien.startswith("http"):
            continue
        out.append({"t": titre[:220], "s": nom, "d": d.astimezone(timezone.utc).strftime("%Y-%m-%d"), "u": lien, "_x": titre + " " + resume})
    return out


def charger_flux(erreurs):
    tout = []
    for nom, url in REF_FEEDS:
        try:
            l = parse_feed(get(url), nom)
            print(f"flux {nom} : {len(l)} éléments récents")
            tout += l
        except Exception as e:
            erreurs.append(f"flux {nom} ({url}) : {e}")
            print(erreurs[-1], file=sys.stderr)
    return tout


def depuis_flux(a, flux):
    res = [re.compile(r"(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])", re.I) for t in termes(a)[:4]]
    return [{k: v for k, v in x.items() if k != "_x"} for x in flux if any(r.search(x["_x"]) for r in res)]


def presse_ref(a):
    """Recherche limitée aux sites de référence (Google Actualités, opérateur site:)."""
    ts = termes(a)[:3]
    if not ts:
        return []
    sites = " OR ".join(f"site:{d}" for d in ("cisa.gov", "cyber.gouv.fr", "cert.ssi.gouv.fr", "europol.europa.eu", "mandiant.com", "cloud.google.com"))
    q = "(" + " OR ".join(f'"{t}"' for t in ts) + ") (" + sites + f") when:{JOURS_REF}d"
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode({"q": q, "hl": "en-US", "gl": "US", "ceid": "US:en"})
    try:
        items = parse_news(get(url), ts, JOURS_REF)
    except Exception as e:
        print(f"  réf. {a['nom']} : {e}", file=sys.stderr)
        return []
    time.sleep(PAUSE)
    out = []
    for x in items:
        nom = label_ref(x.get("_h", ""))
        if nom:
            x["s"] = nom
            out.append(x)
    return out


def presse(a):
    ts = termes(a)[:3]
    if not ts:
        return []
    q = "(" + " OR ".join(f'"{t}"' for t in ts) + ") " + CONTEXTE + f" when:{JOURS}d"
    vus, out = set(), []
    for hl, gl, ceid in EDITIONS:
        url = "https://news.google.com/rss/search?" + urllib.parse.urlencode({"q": q, "hl": hl, "gl": gl, "ceid": ceid})
        try:
            items = parse_news(get(url), ts)
        except Exception as e:
            print(f"  presse {a['nom']} ({hl}) : {e}", file=sys.stderr)
            items = []
        for x in items:
            k = norm(x["t"])[:80]
            if k not in vus:
                vus.add(k)
                out.append(x)
        time.sleep(PAUSE)
    out.sort(key=lambda x: x["d"], reverse=True)
    return out


# --- Groupes cités dans la veille mais absents du registre -----------------------------
def nouveaux(groupes, deja, veille):
    lim = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    titres = [str(x.get("titre", "")) for x in veille if str(x.get("date", "")) >= lim]
    out = []
    for g in groupes:
        if g["id"] in deja:
            continue
        noms = [n for n in [g["nom"]] + g["alias"] if len(n) >= 5 and not re.search(r"^(group|team)\b", n, re.I)]
        res = [re.compile(r"(?<![A-Za-z0-9])" + re.escape(n) + r"(?![A-Za-z0-9])", re.I) for n in noms]
        n = sum(1 for t in titres if any(r.search(t) for r in res))
        if n >= 2:
            out.append({"nom": g["nom"], "id": g["id"], "url": g["url"], "alias": g["alias"][:6], "n": n})
    out.sort(key=lambda x: -x["n"])
    return out[:8]


def charger(p, defaut):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return defaut


def main():
    base = charger(ACT, {})
    acteurs = [a for a in (base.get("acteurs") or []) if isinstance(a, dict) and a.get("nom") and a.get("id")]
    if not acteurs:
        print("data/acteurs.json absent ou vide : rien à mettre à jour.")
        return 0
    erreurs = []
    groupes = []
    try:
        groupes = parse_mitre(get(MITRE_URL).decode("utf-8", "replace"))
        print(f"MITRE : {len(groupes)} groupes")
    except Exception as e:
        erreurs.append(f"MITRE : {e}")
        print(erreurs[-1], file=sys.stderr)
    mitre = associer(acteurs, groupes) if groupes else {}
    actus = {}
    flux = charger_flux(erreurs)
    for a in acteurs:
        try:
            refs = depuis_flux(a, flux) + presse_ref(a)
            news = presse(a)
        except Exception as e:
            erreurs.append(f"recherche {a['nom']} : {e}")
            refs, news = [], []
        vus, r2 = set(), []
        for x in sorted(refs, key=lambda x: x["d"], reverse=True):
            k = norm(x["t"])[:80]
            if k not in vus:
                vus.add(k)
                x.pop("_h", None)
                x["r"] = 1
                r2.append(x)
        r2 = r2[:REF_MAX]
        n2 = []
        for x in news:
            k = norm(x["t"])[:80]
            if k not in vus:
                vus.add(k)
                x.pop("_h", None)
                n2.append(x)
        l = (r2 + n2)[:PAR_ACTEUR]
        if l:
            actus[a["id"]] = l
    nv = nouveaux(groupes, {m["id"] for m in mitre.values()}, charger(VEILLE, [])) if groupes else []
    old = charger(OUT, {})
    if not mitre and old.get("mitre"):
        mitre = old["mitre"]          # on garde les anciennes données si MITRE est injoignable
    out = {"maj": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "mitre": mitre, "actus": actus, "nouveaux": nv, "erreurs": erreurs[:10]}
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{len(mitre)} acteurs reconnus dans MITRE, {len(actus)} avec des mentions presse, {len(nv)} groupes suggérés")
    return 0


if __name__ == "__main__":
    sys.exit(main())
