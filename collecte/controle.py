#!/usr/bin/env python3
"""Contrôle automatique de conformité d'un article rédigé par une IA aux consignes de rédaction.

Une IA peut ignorer une consigne : ce module vérifie, après coup et sans IA, ce qui peut l'être :
  - reformulation (pas de copie de la source), citations de 15 mots maximum ;
  - pas d'invention de chiffres, dates, identifiants CVE absents de la source ;
  - français ; source citée par son nom ; format et longueurs demandés ; ton sans sensationnalisme ;
  - contexte suffisant pour la longueur produite.
Résultat : {"ok": bool, "alertes": [{"n": "bloquant"|"avert", "t": "..."}], "copie": 0..100}
« bloquant » = l'article est refusé pour ce fournisseur (repli sur le suivant) ; « avert » = signalé au relecteur.
Python standard uniquement.
"""
import html
import re
import unicodedata

SENSATION = ["incroyable", "choquant", "catastrophique", "terrifiant", "apocalypse", "sans précédent", "scandaleux", "effroyable", "séisme"]
FR = set("le la les un une des du de et en est dans pour que qui sur au aux par avec ce cette ces se son sa ses leur leurs ne pas plus mais ou où a été sont aussi comme entre sans sous cela ont fait peut d l qu".split())
EN = set("the and of to in is are was were for that with this from by on as at it its be has have not but or an which their they been will would can".split())


def _norm(t):
    t = unicodedata.normalize("NFKD", html.unescape(str(t or "")).lower())
    t = "".join(c for c in t if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t)).strip()


def _mots(t):
    return re.findall(r"[a-z0-9]+", _norm(t))


def _texte(a):
    return " ".join(str(a.get(k) or "") for k in ("intro", "resume", "analyse", "action", "conclusion"))


def copie(article_txt, source_txt, n=6):
    """Part (0-100) des suites de n mots de l'article qui figurent telles quelles dans la source."""
    a, s = _mots(article_txt), _mots(source_txt)
    if len(a) < n or len(s) < n:
        return 0
    gs = {tuple(s[i:i + n]) for i in range(len(s) - n + 1)}
    ga = [tuple(a[i:i + n]) for i in range(len(a) - n + 1)]
    return round(100 * sum(1 for g in ga if g in gs) / len(ga))


def faits(t):
    """Chiffres, pourcentages, années, CVE de l'article : ce qu'une IA invente le plus souvent."""
    t = html.unescape(re.sub(r"<[^>]+>", " ", str(t or "")))
    out = set(m.upper() for m in re.findall(r"CVE-\d{4}-\d{3,7}", t, flags=re.I))
    t = re.sub(r"CVE-\d{4}-\d{3,7}", " ", t, flags=re.I)
    out |= {re.sub(r"[\s  ]", "", m.replace(",", ".")) for m in re.findall(r"\d[\d\s  ]*(?:[.,]\d+)?\s?(?:%|millions?|milliards?|M€|Md€|€|euros?|k€|Go|To|Mo)", t)}
    out |= set(re.findall(r"\b(?:19|20)\d{2}\b", t))
    out |= {m for m in re.findall(r"\b\d{3,}\b", t)}
    return out


def verifier(art, source, nom_source="", titre_source="", notion=False, detail=False):
    al = []
    B = lambda t: al.append({"n": "bloquant", "t": t})
    V = lambda t: al.append({"n": "avert", "t": t})
    corps = _texte(art)
    mots = _mots(corps)
    src = f"{source or ''} {titre_source or ''}"
    cp = 0 if notion else copie(corps, src)
    if cp >= 40:
        B(f"Copie probable de la source ({cp} % de passages identiques) : consigne de reformulation non respectée.")
    elif cp >= 20:
        V(f"Reprise importante de la source ({cp} % de passages identiques) : à reformuler.")
    # citations > 15 mots
    for q in re.findall(r"[«\"“]([^»\"”]{20,})[»\"”]", html.unescape(re.sub(r"<[^>]+>", " ", corps))):
        if len(q.split()) > 15:
            V(f"Citation de {len(q.split())} mots (maximum demandé : 15).")
            break
    # chiffres / dates / CVE absents de la source
    if not notion:
        ns = _norm(src).replace(" ", "")
        inv = sorted(f for f in faits(corps) if _norm(f).replace(" ", "") not in ns)
        if len(inv) >= 4:
            B("Plusieurs chiffres ou dates absents de la source (" + ", ".join(inv[:5]) + ") : risque d'invention.")
        elif inv:
            V("Chiffre ou date absent de la source, à vérifier : " + ", ".join(inv[:5]) + ".")
    elif faits(corps):
        V("Une notion de fond ne devrait pas contenir de chiffres précis : " + ", ".join(sorted(faits(corps))[:4]) + ".")
    # langue
    if len(mots) >= 25:
        fr = sum(1 for m in mots if m in FR)
        en = sum(1 for m in mots if m in EN)
        if en > fr or en / len(mots) > 0.08:
            B("Texte probablement rédigé en anglais ou mélangé : consigne « en français » non respectée.")
    # source citée par son nom
    if not notion and nom_source and len(nom_source) >= 3 and _norm(nom_source) not in _norm(corps):
        V(f"La source (« {nom_source} ») n'est pas citée dans le texte.")
    # titre
    t = art.get("titre") or ""
    if len(t) > 110:
        V(f"Titre de {len(t)} caractères (maximum demandé : 110).")
    if titre_source and not notion:
        a, b = set(_mots(t)), set(_mots(titre_source))
        if a and b and len(a & b) / len(a | b) > 0.8:
            V("Titre identique ou presque à celui de la source.")
    if len(re.sub(r"<[^>]+>", "", str(art.get("intro") or ""))) > 300:
        V("Chapô trop long (maximum demandé : 280 caractères).")
    if len((art.get("kicker") or "").split()) > 3:
        V("Étiquette de plus de 3 mots.")
    # format
    p = len(re.findall(r"<p>", str(art.get("resume") or "")))
    mini = 4 if detail else 2
    if p < mini and not notion:
        V(f"« L'information » ne compte que {p} paragraphe(s) (attendu : au moins {mini}).")
    if detail and len(re.findall(r"<li>", str(art.get("action") or ""))) < 5:
        V("Moins de 5 mesures dans « L'action » (attendu : 5 à 7).")
    # ton
    bas = _norm(corps)
    hit = [w for w in SENSATION if _norm(w) in bas]
    if hit:
        V("Vocabulaire sensationnaliste : " + ", ".join(hit) + ".")
    # contexte pauvre
    if not notion and len(_norm(source or "")) < 300 and len(corps) > 1500:
        V("Article long écrit à partir d'un contexte très court : risque d'invention, vérifier chaque fait.")
    return {"ok": not any(a["n"] == "bloquant" for a in al), "alertes": al, "copie": cp}


def resume(c):
    """Phrase courte pour le relecteur."""
    n = len(c.get("alertes") or [])
    if not n:
        return "Contrôle automatique : aucune anomalie détectée (cela ne remplace pas la relecture)."
    return f"Contrôle automatique : {n} alerte{'s' if n > 1 else ''} : " + " ".join(a["t"] for a in c["alertes"][:3])
