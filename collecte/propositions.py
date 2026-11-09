#!/usr/bin/env python3
"""Propositions d'articles du jour -> data/propositions.json

Chaque nuit (workflow « Propositions »), prépare jusqu'à 7 brouillons d'articles par rubrique
(Actualités, Géopolitique, Cyber & numérique, Économie, Société, Notions cyber) à partir de la veille
(data/veille.json) et de la liste de notions (data/notions.json). La rubrique « Analyses » reste
entièrement rédigée à la main. RIEN n'est publié : l'éditeur (onglet « Aperçu ») présente ces
propositions, l'aperçu dans le journal les montre telles qu'elles seront publiées, et le bouton
« Publier maintenant » met en ligne celles que vous gardez.

Rédaction : par les fournisseurs d'IA réglés dans l'éditeur (collecte/ia.py : Claude, OpenAI, Gemini, Groq,
Mistral, OpenRouter, personnalisé ; gratuits ou payants ; repli automatique). Sans aucune clé : « brèves » (titre, accroche de la source,
lien) pour que le circuit fonctionne quand même. Python standard uniquement.
"""
import hashlib
import html
import json
import os
import re
import sys
import urllib.request
import ia
from datetime import datetime, timedelta, timezone
from pathlib import Path

VEILLE = Path("data/veille.json")
ITEMS = Path("data/items.json")
NOTIONS = Path("data/notions.json")
OUT = Path("data/propositions.json")

DUREE_JOURS = 3                                              # une proposition non traitée expire après 3 jours
CFG = ia.config()                                            # réglages de l'éditeur (onglet « IA »), data/ia.json
CLE = bool(ia.disponibles(CFG))                              # au moins un fournisseur utilisable ?
RUBRIQUES = [0, 1, 2, 3, 4, 7]    # Actualités, Géopolitique, Cyber, Économie, Société, Notions (5 = Analyses : à la main)
NOMS = {0: "Actualités", 1: "Géopolitique", 2: "Cyber & numérique", 3: "Économie", 4: "Société", 7: "Notions cyber"}
UA = "Mozilla/5.0 (compatible; CyberRiskObserver/1.0; +https://twagirumukiza.github.io/cyber-risk-observer/)"

SYSTEME = """Tu es rédacteur pour « Cyber Risk Observer », un journal français de veille sur la menace cyber, la gouvernance, les risques et la conformité (GRC). Ton : factuel, sobre, précis, sans sensationnalisme ni jargon inutile.

Règles impératives :
- Tu t'appuies UNIQUEMENT sur les informations fournies. N'invente aucun chiffre, nom, date, attribution, victime ni citation. Si une information manque, ne la complète pas.
- Tu reformules entièrement avec tes propres mots (aucune phrase recopiée ; citation éventuelle de 15 mots maximum entre guillemets). Tu cites la source par son nom.
- Tu écris en français.
- Format HTML minimal : <p>, <ul><li>, <strong>. Pas de titres, pas de liens.
- Si le contexte fourni est trop pauvre pour un article fiable, mets "fiabilite" à "partiel" et reste court.

Réponds par UN SEUL objet JSON, sans texte autour, avec les clés :
"titre" (titre original, 110 caractères max, qui n'est pas celui de la source),
"kicker" (étiquette courte, 3 mots max, ex. « Rançongiciel »),
"intro" (chapô : 1 à 2 phrases, 280 caractères max, qui donnent l'essentiel),
"resume" (« L'information » : 2 à 3 paragraphes, les faits),
"analyse" (1 paragraphe prudent sur la portée pour une organisation ; chaîne vide si rien de solide à en dire),
"conclusion" (1 paragraphe : ce qu'il faut retenir),
"fiabilite" ("ok" ou "partiel"),
"note" (une phrase pour le relecteur : ce qu'il faut vérifier ; chaîne vide si rien)."""

SYSTEME_NOTION = SYSTEME.replace("Tu t'appuies UNIQUEMENT sur les informations fournies. N'invente",
                                 "Il s'agit d'une notion de fond (pas d'actualité) : explique-la avec exactitude, à partir de connaissances établies et consensuelles. N'invente").replace(
    "Tu cites la source par son nom.", "Pas de source à citer.")


def charger(p, defaut):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return defaut


def telecharger(url, limite=250_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Language": "fr,en;q=0.8"})
    with urllib.request.urlopen(req, timeout=12) as r:
        return r.read(limite).decode("utf-8", "replace")


def texte_page(url):
    """Texte lisible d'une page publique (contexte pour la rédaction ; jamais republié tel quel)."""
    try:
        h = telecharger(url)
    except Exception:
        return ""
    h = re.sub(r"(?is)<(script|style|nav|header|footer|aside|form|noscript|svg)[^>]*>.*?</\1>", " ", h)
    paras = re.findall(r"(?is)<p[^>]*>(.*?)</p>", h)
    t = " ".join(html.unescape(re.sub(r"<[^>]+>", " ", p)) for p in paras)
    return re.sub(r"\s+", " ", t).strip()[:6000]


def appeler_ia(systeme, consigne, rub=None):
    """-> (objet JSON, identifiant du fournisseur, modèle). Repli automatique sur le fournisseur suivant."""
    t, f, m = ia.appeler(systeme, consigne, CFG, rub)
    return ia.extraire_json(t), f, m


def nettoyer_html(h, n=4000):
    h = str(h or "")[:n]
    h = re.sub(r"(?is)<(script|style|iframe|object|embed)[^>]*>.*?</\1>", "", h)
    h = re.sub(r"(?i)</?(?!/?(?:p|ul|ol|li|strong|em|b|i)\b)[a-z][^>]*>", "", h)   # seules balises de texte
    h = re.sub(r"(?i)<(p|ul|ol|li|strong|em|b|i)\s[^>]*>", r"<\1>", h)
    return h.strip()


def court(t, n):
    t = re.sub(r"\s+", " ", str(t or "")).strip()
    return t if len(t) <= n else t[:n - 1].rsplit(" ", 1)[0] + "…"


def article_depuis_ia(rep, rub, src):
    intro = court(rep.get("intro"), 300)
    resume = nettoyer_html(rep.get("resume"))
    if not intro or not resume:
        raise ValueError("réponse incomplète")
    return {"titre": court(rep.get("titre"), 140) or src["titre"], "kicker": court(rep.get("kicker"), 40),
            "intro": "<p>" + html.escape(intro, quote=False) + "</p>", "resume": resume,
            "analyse": nettoyer_html(rep.get("analyse")), "conclusion": nettoyer_html(rep.get("conclusion")),
            "fiabilite": "partiel" if rep.get("fiabilite") == "partiel" else "ok", "note": court(rep.get("note"), 240)}


def breve(src):
    """Sans IA : accroche de la source + lien (aucune reprise de texte au-delà de l'extrait du flux)."""
    ex = court(src.get("resume") or src["titre"], 260)
    nom = html.escape(src.get("source") or "la source", quote=False)
    return {"titre": court(src["titre"], 140), "kicker": (src.get("menaces") or [""])[0],
            "intro": "<p>" + html.escape(ex, quote=False) + "</p>",
            "resume": f"<p>Brève à développer. Source : {nom}.</p>", "analyse": "", "conclusion": "",
            "fiabilite": "breve", "note": "Brève non rédigée (aucune clé API configurée) : à compléter ou à écarter."}


def proposer(rub, src, notion=None):
    pid = "p" + hashlib.sha1(((src.get("url") or "") + src["titre"] + str(rub)).encode()).hexdigest()[:10]
    if CLE:
        if notion:
            consigne = f"Notion à expliquer : {src['titre']}\nAngle : {notion.get('angle', '')}\nPublic : décideurs et responsables non techniques d'organisations françaises.\nProduis l'objet JSON demandé."
            rep, f, m = appeler_ia(CFG["consignes"]["notions"] or SYSTEME_NOTION, consigne, rub)
        else:
            page = texte_page(src["url"]) if src.get("url") else ""
            contexte = page or src.get("resume") or ""
            consigne = (f"Source : {src.get('source', '')}\nTitre de la source : {src['titre']}\nDate : {src.get('date', '')}\n"
                        f"Extrait du flux : {src.get('resume', '')}\n\nTexte de la page (peut être incomplet ou absent) :\n{page or '(indisponible)'}\n\nProduis l'objet JSON demandé.")
            rep, f, m = appeler_ia(CFG["consignes"]["articles"] or SYSTEME, consigne, rub)
            if not page and rep.get("fiabilite") == "ok" and len(contexte) < 200:
                rep["fiabilite"] = "partiel"
        art = article_depuis_ia(rep, rub, src)
        art["ia"] = 1
        art["fournisseur"] = CFG["fournisseurs"][f]["nom"]
        art["modele"] = m
    else:
        art = breve(src)
    art.update({"section": rub, "source": "" if notion else (src.get("source") or ""), "url": "" if notion else (src.get("url") or ""),
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "criticite": src.get("criticite") or ""})
    return {"pid": pid, "rubrique": rub, "etat": "propose", "cree": art["date"], "score": src.get("score", 0), "article": art,
            "src": {"titre": src["titre"], "url": src.get("url") or "", "source": src.get("source") or ""}}


def main():
    now = datetime.now(timezone.utc)
    jour = now.strftime("%Y-%m-%d")
    etat = charger(OUT, {})
    props = [p for p in etat.get("items", []) if isinstance(p, dict)]
    vus = list(etat.get("vus", []))
    publies = {x.get("url") for x in charger(ITEMS, []) if isinstance(x, dict) and x.get("url")}
    limite = (now - timedelta(days=DUREE_JOURS)).strftime("%Y-%m-%d")
    # on garde : ce qui attend une décision et n'a pas expiré, plus les décisions récentes (historique court)
    garde = []
    for p in props:
        if p.get("etat") in ("publie", "ecarte"):
            vus.append(p.get("src", {}).get("url") or p.get("pid"))
            continue
        if p.get("cree", jour) < limite:
            vus.append(p.get("src", {}).get("url") or p.get("pid"))
            continue
        garde.append(p)
    deja = set(vus) | publies | {p.get("src", {}).get("url") for p in garde}
    veille = [v for v in charger(VEILLE, []) if isinstance(v, dict) and v.get("titre")]
    notions = [n for n in charger(NOTIONS, []) if isinstance(n, dict) and n.get("sujet")]
    nouveaux, erreurs = 0, []
    for rub in RUBRIQUES:
        cible = CFG["rubriques"][str(rub)]["nombre"]
        besoin = cible - sum(1 for p in garde if p.get("rubrique") == rub)
        if rub == 7:
            cands = [{"titre": n["sujet"], "angle": n.get("angle", ""), "url": "notion:" + n["sujet"]} for n in notions]
        else:
            cands = sorted((v for v in veille if v.get("rubrique") == rub), key=lambda v: (v.get("score", 0), v.get("date", "")), reverse=True)
        for c in cands:
            if besoin <= 0 or nouveaux >= CFG["plafond"]:
                break
            if (c.get("url") or c["titre"]) in deja:
                continue
            try:
                p = proposer(rub, c, notion=c if rub == 7 else None)
            except Exception as e:
                erreurs.append(f"{NOMS[rub]} · {c['titre'][:50]} : {e}")
                deja.add(c.get("url") or c["titre"])
                continue
            if rub == 7:
                p["src"]["url"] = c["url"]
            garde.append(p)
            deja.add(c.get("url") or c["titre"])
            besoin -= 1
            nouveaux += 1
    for e in erreurs:
        print("[erreur]", e, file=sys.stderr)
    manque = {NOMS[r]: CFG["rubriques"][str(r)]["nombre"] - sum(1 for p in garde if p.get("rubrique") == r) for r in RUBRIQUES}
    out = {"maj": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "ia": CLE, "usage": ia.USAGE,
           "manque": {k: v for k, v in manque.items() if v > 0}, "erreurs": erreurs[:15], "vus": vus[-3000:], "items": garde}
    OUT.parent.mkdir(exist_ok=True)
    ia.maj_cles()
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{nouveaux} nouvelles propositions ({'IA : ' + ', '.join(ia.USAGE) if CLE else 'brèves, sans IA'}), {len(garde)} en attente ; manque : {out['manque'] or 'rien'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
