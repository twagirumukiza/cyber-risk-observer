#!/usr/bin/env python3
"""Rubrique CTF : agrégation multi-sources, vérification, dédoublonnage -> data/ctf-veille.json (résultat brut) et data/ctf.json (ce que lit le journal)

Le journal n'est pas un miroir de CTFtime : il croise plusieurs sources et vérifie ce qu'il publie.

  Compétitions
    - sources : CTFtime (API publique) + calendriers iCal (.ics) ajoutés dans l'éditeur ;
    - fusion : une même compétition annoncée par plusieurs sources est regroupée (liste « src »),
      un écart de date entre sources est signalé (« ecart ») ;
    - lien : toujours le site OFFICIEL de la compétition, jamais une page d'agrégateur ;
    - vérification : le site officiel répond-il ? (« verif » : ok / ko / vide = indéterminé).
  Corrigés (writeups)
    - sources : flux RSS / Atom de la liste « sources » de data/ctf.json (éditable) + recherche
      web par catégorie (Bing Actualités, français et anglais) ;
    - lien : toujours l'article ORIGINAL (les pages d'agrégateur sont remplacées par le lien
      d'origine, ou écartées s'il est introuvable) ;
    - vérification : lien vivant (les 404 / 410 sont écartés), nombre de sources qui le citent (« n »).
  Classement : top 10 mondial de l'année, avec l'évolution depuis la mise à jour précédente (« evo »).

Bibliothèque standard uniquement. Une source en panne n'arrête pas les autres.
"""
import hashlib
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

OUT = Path("data/ctf-veille.json")
CFG = Path("data/ctf.json")
HEAD = {"User-Agent": "Mozilla/5.0 (compatible; CyberRiskObserver-ctf/1.0; +https://github.com/twagirumukiza/cyber-risk-observer)"}
BASE = "https://ctftime.org"
PAR_CAT = 10          # corrigés conservés par catégorie
JOURS_WU = 120        # ancienneté maximale d'un corrigé
PAUSE = 0.8
MAX_RESOLVE = 30      # pages d'agrégateur à résoudre vers l'article d'origine, par exécution
FILTRE = r"ctf|capture the flag|write-?up|walkthrough|wargame|hack ?the ?box|\bhtb\b|picoctf|tryhackme|challenge"
MOTS = {"Web": "web XSS SQLi", "Crypto": "crypto RSA cipher", "Forensic": "forensic memory pcap", "Reverse": "reverse engineering binary", "Pwn": "pwn exploit overflow"}
CATS = [
    ("Web", r"\bweb\b|xss|sqli|sql injection|csrf|ssrf|php|jwt|http|flask|node\.?js"),
    ("Crypto", r"crypto|rsa|aes|cipher|ecc|elliptic|lattice|hash|xor|prng"),
    ("Forensic", r"forensic|memory dump|pcap|wireshark|volatility|disk image|stego|osint"),
    ("Reverse", r"\brev(erse|ersing)?\b|decompil|ghidra|ida\b|obfusc|binary|apk|disassembl"),
    ("Pwn", r"\bpwn|exploit|buffer overflow|rop\b|heap|shellcode|kernel|format string|ret2"),
]
AGREGATEURS = ("ctftime.org", "bing.com", "google.com", "news.google.com")


def get(url, timeout=40):
    req = urllib.request.Request(url, headers=HEAD)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def host(u):
    return urllib.parse.urlparse(str(u)).netloc.lower().replace("www.", "")


def est_agregateur(u):
    h = host(u)
    return any(h == d or h.endswith("." + d) for d in AGREGATEURS)


def norm(s):
    return re.sub(r"[^a-z0-9]+", "", str(s).lower())


def vers_date(raw):
    try:
        try:
            d = parsedate_to_datetime(raw)
        except Exception:
            d = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except Exception:
        return None


def classer(texte):
    for cat, rx in CATS:
        if re.search(rx, texte, re.I):
            return cat
    return "Autre"


# --- Vérification --------------------------------------------------------------------
def statut(url):
    """Code HTTP du lien ; -1 = nom de domaine introuvable ; 0 = indéterminé (délai, blocage…)."""
    for meth in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, headers=HEAD, method=meth)
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            if meth == "HEAD" and e.code in (400, 403, 405, 501):
                continue
            return e.code
        except urllib.error.URLError as e:
            return -1 if isinstance(e.reason, socket.gaierror) else 0
        except Exception:
            return 0
    return 0


def verifier(urls):
    """{url: 'ok' | 'ko' | ''} (ko = page disparue ou domaine introuvable)."""
    urls = sorted({u for u in urls if u})
    with ThreadPoolExecutor(8) as ex:
        codes = list(ex.map(statut, urls))
    res = {}
    for u, c in zip(urls, codes):
        res[u] = "ok" if 200 <= c < 400 else "ko" if c in (404, 410, -1) else ""
    return res


# --- Compétitions -----------------------------------------------------------------------
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
        sur = bool(e.get("onsite"))
        lieu = "sur site" + (f" ({e['location']})" if e.get("location") else "") if sur else "en ligne"
        w = float(e.get("weight") or 0)
        off = str(e.get("url") or "").strip()      # site OFFICIEL de la compétition
        if not off.startswith("http") or est_agregateur(off):
            off = ""
        out.append({
            "ct": e.get("id"), "nom": str(e.get("title", "")).strip()[:140], "date": deb.strftime("%Y-%m-%d"),
            "duree": duree(e.get("duration")), "format": " · ".join(x for x in (fmt, lieu) if x),
            "niveau": f"poids CTFtime {w:g}" if w else "", "url": off,
            "mode": "onsite" if sur else "online", "poids": w, "src": ["CTFtime"],
        })
    return [x for x in out if x["nom"]]


def parse_ics(txt, nom, jours=120):
    lignes = re.sub(r"\r?\n[ \t]", "", txt).splitlines()
    now = datetime.now(timezone.utc)
    out, ev = [], None
    for l in lignes:
        if l.startswith("BEGIN:VEVENT"):
            ev = {}
        elif l.startswith("END:VEVENT") and ev is not None:
            d = ev.get("DTSTART")
            if d and ev.get("SUMMARY") and now - timedelta(days=1) <= d <= now + timedelta(days=jours):
                u = ev.get("URL", "")
                out.append({"ct": "ics" + hashlib.md5((ev["SUMMARY"] + d.strftime("%Y%m%d")).encode()).hexdigest()[:8], "nom": ev["SUMMARY"][:140],
                            "date": d.strftime("%Y-%m-%d"), "duree": "", "format": "", "niveau": "", "mode": "", "poids": 0,
                            "url": u if u.startswith("http") and not est_agregateur(u) else "", "src": [nom]})
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


def fusion(evs):
    """Regroupe les annonces d'une même compétition faites par plusieurs sources."""
    idx, out = {}, []
    for e in evs:
        k = norm(re.sub(r"\b20\d\d\b", "", e["nom"]))
        m = idx.get(k)
        if m and abs((datetime.fromisoformat(e["date"]) - datetime.fromisoformat(m["date"])).days) <= 3:
            for s in e.get("src", []):
                if s not in m["src"]:
                    m["src"].append(s)
            if e["date"] != m["date"]:
                m["ecart"] = 1
            for f in ("url", "duree", "format", "mode"):
                if not m.get(f) and e.get(f):
                    m[f] = e[f]
            continue
        idx[k] = e
        out.append(e)
    return out


# --- Corrigés ------------------------------------------------------------------------------
def parse_feed(xml, nom, jours=JOURS_WU):
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


def direct(lien):
    """Adresse réelle d'un lien de moteur d'actualités (Bing : paramètre url=)."""
    if "apiclick" in lien or "bing.com" in host(lien):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(lien).query).get("url")
        return q[0] if q else ""
    return lien


def news_cat(cat):
    """Recherche web par catégorie (Bing Actualités, liens directs) : aucune catégorie ne reste vide."""
    mots = MOTS.get(cat) or f'"{cat}"'
    q = '("CTF" OR "capture the flag") (writeup OR "write-up" OR walkthrough) (' + " OR ".join(mots.split()) + ")"
    out, vus = [], set()
    for mkt in ("en-US", "fr-FR"):
        url = "https://www.bing.com/news/search?" + urllib.parse.urlencode({"q": q, "format": "rss", "setmkt": mkt})
        try:
            root = ET.fromstring(get(url))
        except Exception as e:
            print(f"  web {cat} ({mkt}) : {e}", file=sys.stderr)
            continue
        for it in root.iter("item"):
            titre = (it.findtext("title") or "").strip()
            lien = direct((it.findtext("link") or "").strip())
            src = ""
            for c in it:
                if c.tag.lower().endswith("source") and (c.text or "").strip():
                    src = c.text.strip()
            d = vers_date(it.findtext("pubDate") or "") or datetime.now(timezone.utc)
            if not titre or not lien.startswith("http") or est_agregateur(lien) or titre.lower() in vus:
                continue
            if d < datetime.now(timezone.utc) - timedelta(days=JOURS_WU):
                continue
            vus.add(titre.lower())
            out.append({"t": titre[:160], "u": lien, "d": d.strftime("%Y-%m-%d"), "s": src or host(lien), "x": titre})
        time.sleep(PAUSE)
    return out


def original(url):
    """Page d'agrégateur (ex. fiche CTFtime) -> lien de l'article d'origine, ou '' si introuvable."""
    try:
        h = get(url, timeout=15).decode("utf-8", "replace")
    except Exception:
        return ""
    for rx in (r'Original writeup[^<]{0,80}<a[^>]+href="(https?://[^"]+)"', r'<a[^>]+href="(https?://[^"]+)"[^>]*>\s*Original writeup', r'Original writeup[^<]{0,40}(https?://[^\s<"]+)'):
        m = re.search(rx, h, re.I)
        if m and not est_agregateur(m.group(1)):
            return m.group(1)
    return ""


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
    # corroboration : combien de sources distinctes citent le même article ?
    nb = {}
    for x in tous:
        nb.setdefault(norm(x["t"])[:70], set()).add(x["s"])
    # dédoublonnage + présélection (les plus récents de chaque catégorie)
    vus_t, vus_u, pre, n = set(), set(), [], {}
    for x in sorted(tous, key=lambda x: x["d"], reverse=True):
        k = norm(x["t"])[:70]
        if k in vus_t or x["u"] in vus_u:
            continue
        vus_t.add(k)
        vus_u.add(x["u"])
        n[x["cat"]] = n.get(x["cat"], 0) + 1
        if n[x["cat"]] <= PAR_CAT + 4:
            x["n"] = len(nb.get(k, ()))
            pre.append(x)
    # lien d'origine : on ne renvoie jamais vers un agrégateur
    resolus = 0
    for x in pre:
        if est_agregateur(x["u"]):
            o = original(x["u"]) if resolus < MAX_RESOLVE else ""
            resolus += 1
            x["u"] = o
            time.sleep(0.3)
    pre = [x for x in pre if x["u"]]
    ver = verifier([x["u"] for x in pre])
    res, n = [], {}
    for x in pre:
        v = ver.get(x["u"], "")
        if v == "ko":
            continue
        n[x["cat"]] = n.get(x["cat"], 0) + 1
        if n[x["cat"]] <= PAR_CAT:
            res.append({"id": "w" + hashlib.md5(x["u"].encode()).hexdigest()[:8], "cat": x["cat"], "titre": x["t"], "niveau": "", "url": x["u"],
                        "d": x["d"], "s": x["s"], "n": x["n"], "v": 1 if v == "ok" else 0})
    return res


# --- Classement ---------------------------------------------------------------------------------
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


def evolution(nouveau, ancien, ancien_maj, now):
    """Place gagnée (+) ou perdue (-) depuis la mise à jour précédente (au moins 20 h plus tôt)."""
    ref = {r["equipe"]: i for i, r in enumerate(ancien or [])}
    recent = False
    try:
        recent = (now - vers_date(ancien_maj)).total_seconds() < 20 * 3600
    except Exception:
        pass
    for i, r in enumerate(nouveau):
        if recent:
            old = next((a for a in (ancien or []) if a.get("equipe") == r["equipe"]), {})
            if "evo" in old:
                r["evo"] = old["evo"]
            if old.get("neuf"):
                r["neuf"] = 1
        elif ancien:
            if r["equipe"] in ref:
                r["evo"] = ref[r["equipe"]] - i
            else:
                r["neuf"] = 1


def main():
    now = datetime.now(timezone.utc)
    erreurs, res, stats = [], {}, {}
    cfg = {}
    try:
        cfg = json.loads(CFG.read_text(encoding="utf-8"))
    except Exception:
        pass
    old = {}
    try:
        old = json.loads(OUT.read_text(encoding="utf-8"))
    except Exception:
        pass
    sources = [s for s in (cfg.get("sources") or []) if isinstance(s, dict)] or [{"nom": "CTFtime — writeups", "url": f"{BASE}/writeups/rss/", "cat": "", "filtre": 0}]
    cats = [c for c in (cfg.get("cats") or list(MOTS)) if isinstance(c, str) and c.strip() and c != "Autre"]
    ics = lambda u: u.endswith(".ics") or "calendar/ical" in u or u.startswith("webcal")
    # compétitions : CTFtime + calendriers iCal, fusionnées puis vérifiées
    evs = []
    try:
        u = f"{BASE}/api/v1/events/?limit=30&start={int(now.timestamp())}&finish={int((now + timedelta(days=90)).timestamp())}"
        evs += parse_events(get(u).decode("utf-8"))
        stats["Compétitions — CTFtime"] = len(evs)
    except Exception as e:
        erreurs.append(f"calendrier CTFtime : {e}")
    for s in sources:
        u = str(s.get("url") or "")
        if ics(u):
            try:
                e2 = parse_ics(get(u.replace("webcal://", "https://")).decode("utf-8", "replace"), s.get("nom") or "Calendrier")
                evs += e2
                stats[f"Compétitions — {s.get('nom')}"] = len(e2)
            except Exception as e:
                erreurs.append(f"{s.get('nom')} : {e}")
    evs = fusion(sorted(evs, key=lambda e: e["date"]))
    ver = verifier([e["url"] for e in evs])
    for e in evs:
        e["verif"] = ver.get(e["url"], "") if e["url"] else ""
    if evs or "calendrier" not in old:
        res["calendrier"] = evs
    print(f"calendrier : {len(evs)} compétitions ({sum(1 for e in evs if len(e['src']) > 1)} croisées, {sum(1 for e in evs if e['verif'] == 'ok')} sites vérifiés)")
    try:
        res["classement"] = parse_top(get(f"{BASE}/api/v1/top/{now.year}/?limit=10").decode("utf-8"), now.year)
        res["classTitre"] = f"Classement mondial {now.year}"
        evolution(res["classement"], old.get("classement"), old.get("maj"), now)
        print(f"classement : {len(res['classement'])} équipes")
    except Exception as e:
        erreurs.append(f"classement : {e}")
    try:
        res["writeups"] = corriges([s for s in sources if not ics(str(s.get('url') or ''))], cats, erreurs, stats)
        print(f"writeups : {len(res['writeups'])} ({len(sources)} sources + {len(cats)} recherches)")
    except Exception as e:
        erreurs.append(f"writeups : {e}")
    for e in erreurs:
        print(e, file=sys.stderr)
    for k in ("calendrier", "classement", "writeups", "classTitre"):   # on garde l'ancien si la source est en panne
        if k not in res or (k != "calendrier" and not res.get(k)):
            if old.get(k):
                res[k] = old[k]
    res.update({"maj": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "sources": stats, "erreurs": erreurs[:15]})
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    publier(res, now)
    return 0


def publier(res, now):
    """Fusionne le résultat dans data/ctf.json (ce que lit le journal) : les éléments saisis à la main
    sont conservés, les éléments automatiques sont remplacés. Le site est ainsi rempli par la dernière
    mise à jour, sans passer par l'éditeur ni dépendre du cache d'un navigateur."""
    try:
        cfg = json.loads(CFG.read_text(encoding="utf-8"))
        if not isinstance(cfg, dict):
            cfg = {}
    except Exception:
        cfg = {}
    for k in ("calendrier", "classement", "writeups"):
        if not isinstance(cfg.get(k), list):
            cfg[k] = []
    if not isinstance(cfg.get("cats"), list) or not cfg["cats"]:
        cfg["cats"] = ["Web", "Crypto", "Forensic", "Reverse", "Pwn"]
    limite = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    cal = [x for x in cfg["calendrier"] if not (x.get("auto") and (x.get("date") or "") < limite)]
    for e in res.get("calendrier", []):
        eid = "ct" + str(e.get("ct"))
        o = {k: e.get(k, "") for k in ("nom", "date", "duree", "format", "niveau", "url", "mode")}
        o.update({"poids": e.get("poids", 0), "src": e.get("src", []), "verif": e.get("verif", ""), "ecart": 1 if e.get("ecart") else 0})
        f = next((x for x in cal if x.get("id") == eid or (e.get("url") and x.get("url") == e["url"]) or (x.get("nom") == e["nom"] and x.get("date") == e["date"])), None)
        if f:
            if f.get("auto"):
                f.update(o)
                f["auto"] = 1
            else:
                f.update({"src": o["src"], "verif": o["verif"], "ecart": o["ecart"]})
            continue
        o["id"], o["auto"] = eid, 1
        cal.append(o)
    cfg["calendrier"] = sorted(cal, key=lambda x: x.get("date") or "")
    if res.get("classement") and cfg.get("classAuto") is not False:
        cfg["classement"] = [dict({"equipe": r["equipe"], "points": r["points"], "pays": r.get("pays", ""), "auto": 1},
                                  **({"evo": r["evo"]} if r.get("evo") is not None else {}), **({"neuf": 1} if r.get("neuf") else {}))
                             for r in res["classement"]]
        if res.get("classTitre"):
            cfg["classTitre"] = res["classTitre"]
    wu = cfg["writeups"]
    for w in res.get("writeups", []):
        if any(x.get("id") == w.get("id") or (w.get("url") and x.get("url") == w["url"]) for x in wu):
            continue
        wu.append({"id": w["id"], "cat": w.get("cat"), "titre": w.get("titre"), "niveau": w.get("niveau", ""), "url": w.get("url", ""),
                   "d": w.get("d", ""), "s": w.get("s", ""), "n": w.get("n", 1), "v": 1 if w.get("v") else 0, "auto": 1})
        if w.get("cat") and w["cat"] not in cfg["cats"]:
            cfg["cats"].append(w["cat"])
    wu = [x for x in wu if not (x.get("auto") and "ctftime.org" in (x.get("url") or ""))]
    wu.sort(key=lambda x: str(x.get("d") or ""), reverse=True)
    n, garde = {}, []
    for x in wu:
        if x.get("auto"):
            n[x.get("cat")] = n.get(x.get("cat"), 0) + 1
            if n[x.get("cat")] > 10:
                continue
        garde.append(x)
    cfg["writeups"] = garde
    cfg["maj"] = now.strftime("%Y-%m-%d")
    CFG.write_text(json.dumps(cfg, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"data/ctf.json mis à jour : {len(cfg['calendrier'])} compétitions, {len(cfg['classement'])} équipes, {len(cfg['writeups'])} writeups")


if __name__ == "__main__":
    sys.exit(main())
