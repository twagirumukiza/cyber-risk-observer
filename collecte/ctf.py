#!/usr/bin/env python3
"""Mise à jour automatique de la rubrique CTF -> data/ctf-veille.json

Sources : le web entier, pas seulement CTFtime.org :
  - calendrier : CTFtime (API publique) + les calendriers ICS ajoutés dans l'éditeur ;
  - classement : top 10 mondial CTFtime de l'année en cours ;
  - writeups   : (1) les flux RSS / Atom de la liste `sources` de data/ctf.json (modifiable dans
                 l'éditeur : blogs, CTFtime, Reddit, etc.), (2) une recherche dédiée à chaque
                 catégorie (Google Actualités, français et anglais), pour qu'aucune catégorie
                 ne reste vide. Les corriges sont rangés par catégorie, dédoublonnés, datés.

L'éditeur (onglet CTF > « Mettre à jour depuis internet ») applique ces données :
les éléments saisis à la main ne sont jamais modifiés, les éléments d'exemple sont remplacés.
Bibliothèque standard uniquement. Une source en panne n'arrête pas les autres.
"""
import hashlib
import json
import re
import sys
import time
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path("data/ctf-veille.json")
CFG = Path("data/ctf.json")
PAR_CAT = 10          # corriges conservés par catégorie
JOURS_WU = 120        # ancienneté maximale d'un corrigé
PAUSE = 0.8
FILTRE = r"ctf|capture the flag|write-?up|walkthrough|wargame|hack ?the ?box|\bhtb\b|picoctf|tryhackme|challenge"
MOTS = {"Web": "web XSS SQLi", "Crypto": "crypto RSA cipher", "Forensic": "forensic memory pcap", "Reverse": "reverse engineering binary", "Pwn": "pwn exploit overflow"}
HEAD = {"User-Agent": "Mozilla/5.0 (compatible; CyberRiskObserver-ctf/1.0; +https://github.com/twagirumukiza/cyber-risk-observer)"}
BASE = "https://ctftime.org"
CATS = [  # catégorie -> mots-clés cherchés dans le titre / le résumé
    ("Web", r"\bweb\b|xss|sqli|sql injection|csrf|ssrf|php|jwt|http|flask|node\.?js"),
    ("Crypto", r"crypto|rsa|aes|cipher|ecc|elliptic|lattice|hash|xor|prng"),
    ("Forensic", r"forensic|memory dump|pcap|wireshark|volatility|disk image|stego|osint"),
    ("Reverse", r"\brev(erse|ersing)?\b|decompil|ghidra|ida\b|obfusc|binary|apk|disassembl"),
    ("Pwn", r"\bpwn|exploit|buffer overflow|rop\b|heap|shellcode|kernel|format string|ret2"),
]


def get(url, timeout=40):
    req = urllib.request.Request(url, headers=HEAD)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def duree(d):
    j, h = int((d or {}).get("days") or 0), int((d or {}).get("hours") or 0)
    return " ".join(x for x in ((f"{j} j" if j else ""), (f"{h} h" if h else "")) if x)


def parse_events(txt):
    out = []
    for e in json.loads(txt):
        try:
            deb = datetime.fromisoformat(str(e["start"]).replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            continue
        fmt = {"jeopardy": "Jeopardy", "attack-defense": "attaque-défense", "hack quest": "hack quest"}.get(str(e.get("format", "")).lower(), e.get("format") or "")
        lieu = "sur site" + (f" ({e['location']})" if e.get("location") else "") if e.get("onsite") else "en ligne"
        w = float(e.get("weight") or 0)
        out.append({
            "ct": e.get("id"), "nom": str(e.get("title", "")).strip()[:140], "date": deb.strftime("%Y-%m-%d"),
            "duree": duree(e.get("duration")), "format": " · ".join(x for x in (fmt, lieu) if x),
            "niveau": f"poids CTFtime {w:g}" if w else "", "url": e.get("ctftime_url") or e.get("url") or "",
        })
    return [x for x in out if x["nom"]]


def parse_top(txt, annee):
    d = json.loads(txt)
    lst = d.get(str(annee)) if isinstance(d, dict) else d
    out = []
    for t in (lst or [])[:10]:
        nom = str(t.get("team_name", "")).strip()
        if nom:
            pts = t.get("points")
            out.append({"equipe": nom[:80], "points": (f"{float(pts):.2f}".rstrip("0").rstrip(".") if pts is not None else ""), "pays": ""})
    return out


def classer(texte):
    for cat, rx in CATS:
        if re.search(rx, texte, re.I):
            return cat
    return "Autre"


def parse_writeups(xml, max_n=25):
    root = ET.fromstring(xml)
    out = []
    for it in root.iter("item"):
        titre = re.sub(r"\s+", " ", (it.findtext("title") or "")).strip()
        lien = (it.findtext("link") or "").strip()
        if not titre or not lien.startswith("http"):
            continue
        res = re.sub(r"<[^>]+>", " ", it.findtext("description") or "")
        out.append({"id": "w" + hashlib.md5(lien.encode()).hexdigest()[:8], "cat": classer(titre + " " + res[:300]), "titre": titre[:160], "niveau": "", "url": lien})
        if len(out) >= max_n:
            break
    return out

def vers_date(raw):
    try:
        try:
            d = parsedate_to_datetime(raw)
        except Exception:
            d = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except Exception:
        return None


def parse_feed(xml, nom, jours=JOURS_WU):
    """Flux RSS ou Atom -> [{t, u, d, s, x}] (x = titre + résumé, pour le filtre et le classement)."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    A = "{http://www.w3.org/2005/Atom}"
    lim = datetime.now(timezone.utc) - timedelta(days=jours)
    out = []
    for it in list(root.iter("item")) + list(root.iter(A + "entry")):
        def tx(*tags):
            for t in tags:
                e = it.find(t)
                if e is not None and (e.text or "").strip():
                    return e.text.strip()
            return ""
        titre = re.sub(r"\s+", " ", tx("title", A + "title"))
        lien = tx("link")
        if not lien:
            le = it.find(A + "link")
            lien = (le.get("href") if le is not None else "") or ""
        d = vers_date(tx("pubDate", A + "published", A + "updated", "{http://purl.org/dc/elements/1.1/}date"))
        if not titre or not lien.startswith("http") or d is None or d < lim:
            continue
        res = re.sub(r"<[^>]+>", " ", tx("description", A + "summary", A + "content"))[:400]
        out.append({"t": titre[:160], "u": lien, "d": d.strftime("%Y-%m-%d"), "s": nom, "x": titre + " " + res})
    return out


def parse_ics(txt, nom, jours=120):
    """Calendrier iCalendar -> compétitions à venir."""
    lignes = re.sub(r"\r?\n[ \t]", "", txt).splitlines()
    now = datetime.now(timezone.utc)
    out, ev = [], None
    for l in lignes:
        if l.startswith("BEGIN:VEVENT"):
            ev = {}
        elif l.startswith("END:VEVENT") and ev is not None:
            d = ev.get("DTSTART")
            if d and ev.get("SUMMARY") and now - timedelta(days=1) <= d <= now + timedelta(days=jours):
                out.append({"ct": "ics" + hashlib.md5((ev["SUMMARY"] + d.strftime("%Y%m%d")).encode()).hexdigest()[:8], "nom": ev["SUMMARY"][:140], "date": d.strftime("%Y-%m-%d"),
                            "duree": "", "format": nom, "niveau": "", "url": ev.get("URL", "")})
            ev = None
        elif ev is not None and ":" in l:
            k, v = l.split(":", 1)
            k = k.split(";")[0].upper()
            if k == "DTSTART":
                m = re.match(r"(\d{4})(\d{2})(\d{2})", v)
                if m:
                    ev[k] = datetime(int(m[1]), int(m[2]), int(m[3]), tzinfo=timezone.utc)
            elif k in ("SUMMARY", "URL"):
                ev[k] = v.replace("\\,", ",").replace("\\n", " ").strip()
    return out


def news_cat(cat):
    """Recherche du web par catégorie (Google Actualités) : garantit du contenu pour chaque catégorie."""
    mots = MOTS.get(cat) or f'"{cat}"'
    q = '("CTF" OR "capture the flag") (writeup OR "write-up" OR walkthrough) (' + " OR ".join(mots.split()) + f") when:{JOURS_WU}d"
    out, vus = [], set()
    for hl, gl, ceid in (("en-US", "US", "US:en"), ("fr", "FR", "FR:fr")):
        url = "https://news.google.com/rss/search?" + urllib.parse.urlencode({"q": q, "hl": hl, "gl": gl, "ceid": ceid})
        try:
            root = ET.fromstring(get(url))
        except Exception as e:
            print(f"  web {cat} ({hl}) : {e}", file=sys.stderr)
            continue
        for it in root.iter("item"):
            titre = (it.findtext("title") or "").strip()
            lien = (it.findtext("link") or "").strip()
            src = (it.findtext("source") or "").strip()
            if src and titre.endswith(" - " + src):
                titre = titre[: -len(src) - 3].strip()
            d = vers_date(it.findtext("pubDate") or "")
            if not titre or not lien.startswith("http") or d is None or d < datetime.now(timezone.utc) - timedelta(days=JOURS_WU) or titre.lower() in vus:
                continue
            vus.add(titre.lower())
            out.append({"t": titre[:160], "u": lien, "d": d.strftime("%Y-%m-%d"), "s": src or "Web", "x": titre})
        time.sleep(PAUSE)
    return out


def corriges(sources, cats, erreurs, stats):
    tous = []
    for s in sources:
        nom, url = s.get("nom") or "Source", s.get("url") or ""
        if not url.startswith("http"):
            continue
        try:
            items = parse_feed(get(url), nom)
        except Exception as e:
            erreurs.append(f"{nom} : {e}")
            print(erreurs[-1], file=sys.stderr)
            continue
        if s.get("filtre"):
            items = [x for x in items if re.search(FILTRE, x["x"], re.I)]
        for x in items:
            x["cat"] = s.get("cat") or classer(x["x"])
        stats[nom] = len(items)
        tous += items
        time.sleep(0.3)
    for c in cats:
        items = news_cat(c)
        for x in items:
            x["cat"] = c
        stats[f"Web — {c}"] = len(items)
        tous += items
    vus_t, vus_u, out = set(), set(), []
    for x in sorted(tous, key=lambda x: x["d"], reverse=True):
        k = re.sub(r"[^a-z0-9]+", "", x["t"].lower())[:70]
        if k in vus_t or x["u"] in vus_u:
            continue
        vus_t.add(k)
        vus_u.add(x["u"])
        out.append({"id": "w" + hashlib.md5(x["u"].encode()).hexdigest()[:8], "cat": x["cat"], "titre": x["t"], "niveau": "", "url": x["u"], "d": x["d"], "s": x["s"]})
    res, n = [], {}
    for w in out:
        n[w["cat"]] = n.get(w["cat"], 0) + 1
        if n[w["cat"]] <= PAR_CAT:
            res.append(w)
    return res



def main():
    now = datetime.now(timezone.utc)
    erreurs, res = [], {}
    try:
        u = f"{BASE}/api/v1/events/?limit=20&start={int(now.timestamp())}&finish={int((now + timedelta(days=90)).timestamp())}"
        res["calendrier"] = parse_events(get(u).decode("utf-8"))
        print(f"calendrier : {len(res['calendrier'])} compétitions")
    except Exception as e:
        erreurs.append(f"calendrier : {e}")
    try:
        res["classement"] = parse_top(get(f"{BASE}/api/v1/top/{now.year}/?limit=10").decode("utf-8"), now.year)
        res["classTitre"] = f"Classement mondial CTFtime {now.year}"
        print(f"classement : {len(res['classement'])} équipes")
    except Exception as e:
        erreurs.append(f"classement : {e}")
    cfg = {}
    try:
        cfg = json.loads(CFG.read_text(encoding="utf-8"))
    except Exception:
        pass
    sources = [s for s in (cfg.get("sources") or []) if isinstance(s, dict)] or [{"nom": "CTFtime — writeups", "url": f"{BASE}/writeups/rss/", "cat": "", "filtre": 0}]
    cats = [c for c in (cfg.get("cats") or list(MOTS)) if isinstance(c, str) and c.strip() and c != "Autre"]
    # calendriers ICS ajoutés dans l'éditeur
    for s in sources:
        u = str(s.get("url") or "")
        if u.endswith(".ics") or "calendar/ical" in u or u.startswith("webcal"):
            try:
                ev = parse_ics(get(u.replace("webcal://", "https://")).decode("utf-8", "replace"), s.get("nom") or "Calendrier")
                res["calendrier"] = (res.get("calendrier") or []) + ev
                print(f"calendrier {s.get('nom')} : {len(ev)}")
            except Exception as e:
                erreurs.append(f"{s.get('nom')} : {e}")
    sources = [s for s in sources if not (str(s.get("url") or "").endswith(".ics") or "calendar/ical" in str(s.get("url") or "") or str(s.get("url") or "").startswith("webcal"))]
    stats = {}
    try:
        res["writeups"] = corriges(sources, cats, erreurs, stats)
        print(f"writeups : {len(res['writeups'])} ({len(sources)} sources + {len(cats)} recherches)")
    except Exception as e:
        erreurs.append(f"writeups : {e}")
    for e in erreurs:
        print(e, file=sys.stderr)
    old = {}
    try:
        old = json.loads(OUT.read_text(encoding="utf-8"))
    except Exception:
        pass
    for k in ("calendrier", "classement", "writeups", "classTitre"):   # on garde l'ancien si la source est en panne
        if not res.get(k) and old.get(k):
            res[k] = old[k]
    res.update({"maj": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "sources": stats, "erreurs": erreurs[:15]})
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
