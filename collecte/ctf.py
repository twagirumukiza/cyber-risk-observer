#!/usr/bin/env python3
"""Mise à jour automatique de la rubrique CTF -> data/ctf-veille.json

Sources (CTFtime.org, API publique et flux RSS) :
  - calendrier : prochaines compétitions (90 jours) ;
  - classement : top 10 mondial de l'année en cours ;
  - writeups   : derniers corrigés publiés, rangés par catégorie d'après leur titre.

L'éditeur (onglet CTF > « Mettre à jour depuis internet ») applique ces données :
les éléments saisis à la main ne sont jamais modifiés, les éléments d'exemple sont remplacés.
Bibliothèque standard uniquement. Une source en panne n'arrête pas les autres.
"""
import hashlib
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path("data/ctf-veille.json")
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
    try:
        res["writeups"] = parse_writeups(get(f"{BASE}/writeups/rss/"))
        print(f"writeups : {len(res['writeups'])}")
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
    res.update({"maj": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "erreurs": erreurs[:10]})
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
