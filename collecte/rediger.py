#!/usr/bin/env python3
"""Brouillon DÉTAILLÉ d'un sujet de la veille, prêt à relire et publier -> data/brouillons/<id>.json

Lancé par le workflow « Brouillon détaillé » (bouton de l'onglet Veille de l'éditeur). Les informations du
sujet arrivent par variables d'environnement (jamais interpolées dans une commande shell).
Rédaction : fournisseurs d'IA réglés dans l'onglet « IA » (repli automatique). Les clés restent dans les secrets GitHub.
Le résultat (ou l'erreur) est toujours écrit, pour que l'éditeur n'attende pas dans le vide. Python standard uniquement.
"""
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import controle
import ia
import propositions as P

DOSSIER = Path("data/brouillons")

SYSTEME = """Tu es rédacteur en chef adjoint de « Cyber Risk Observer », un journal français de veille sur la menace cyber, la gouvernance, les risques et la conformité (GRC). Tu rédiges un article COMPLET, détaillé, prêt à être relu puis publié. Ton : professionnel, factuel, précis, pédagogique, sans sensationnalisme.

Règles impératives :
- Tu t'appuies UNIQUEMENT sur les informations fournies (texte de la page, extrait). N'invente AUCUN chiffre, nom, date, attribution, victime, vulnérabilité (CVE) ni citation. Si une information manque, dis-le simplement ou ne l'évoque pas.
- Tu reformules entièrement avec tes propres mots (aucune phrase recopiée ; citation éventuelle de 15 mots maximum entre guillemets). Tu cites la source par son nom dans le texte.
- Tu écris en français soigné. Pas de remplissage : chaque paragraphe apporte une information ou une idée.
- Format HTML minimal : <p>, <ul><li>, <ol><li>, <strong>, <em>. Pas de titres, pas de liens, pas d'images.
- Dans "analyse", tu replaces les faits dans leur contexte (menace, réglementation comme NIS2, DORA, RGPD, AI Act, CRA quand c'est pertinent, enjeux de gouvernance et de risque). Tu distingues clairement ce qui est établi par la source de ce qui relève de ton analyse, formulée avec prudence.
- Dans "action", tu proposes des mesures concrètes et proportionnées pour une organisation (liste à puces), sans promettre de résultat.
- Si le contexte fourni est trop pauvre pour un article fiable, mets "fiabilite" à "partiel", reste factuel et signale-le dans "note".

Réponds par UN SEUL objet JSON, sans texte autour, avec les clés :
"titre" (titre original, 110 caractères max, différent de celui de la source),
"kicker" (étiquette courte, 3 mots max),
"intro" (chapô : 2 phrases, 320 caractères max, l'essentiel),
"resume" (« L'information » : 4 à 6 paragraphes détaillés : quoi, qui, quand, comment, ampleur, réaction des acteurs),
"analyse" (3 à 4 paragraphes : contexte, portée, enjeux GRC),
"action" (5 à 7 mesures concrètes en liste à puces <ul><li>),
"conclusion" (1 paragraphe : ce qu'il faut retenir),
"liensUtiles" (chaîne vide),
"fiabilite" ("ok" ou "partiel"),
"note" (une phrase pour le relecteur : ce qu'il faut vérifier avant publication ; chaîne vide si rien)."""


def ecrire(id_, d):
    DOSSIER.mkdir(parents=True, exist_ok=True)
    d["maj"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    (DOSSIER / f"{id_}.json").write_text(json.dumps(d, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def menage():
    """Supprime les brouillons de plus de 14 jours."""
    if DOSSIER.exists():
        for f in DOSSIER.glob("*.json"):
            if time.time() - f.stat().st_mtime > 14 * 86400:
                f.unlink()


def texte_long(url):
    """Texte de la page : paragraphes lisibles (jusqu'à ~12 000 caractères)."""
    try:
        h = P.telecharger(url, 400_000)
    except Exception:
        return ""
    h = re.sub(r"(?is)<(script|style|nav|header|footer|aside|form|noscript|svg)[^>]*>.*?</\1>", " ", h)
    paras = re.findall(r"(?is)<(?:p|li|h2|h3)[^>]*>(.*?)</(?:p|li|h2|h3)>", h)
    t = " ".join(html.unescape(re.sub(r"<[^>]+>", " ", p)) for p in paras)
    return re.sub(r"\s+", " ", t).strip()[:12000]


def main():
    id_ = re.sub(r"[^a-z0-9]", "", os.environ.get("ID", "").lower())[:40]
    if len(id_) < 3:
        print("identifiant invalide")
        return 0
    menage()
    url = os.environ.get("SRC_URL", "").strip()
    titre = os.environ.get("SRC_TITRE", "").strip()[:300]
    if not titre:
        ecrire(id_, {"erreur": "titre manquant"})
        return 0
    if url and not re.match(r"^https://[^\s/]+\.[^\s/]+", url):
        url = ""                       # uniquement des pages https publiques
    src = {"titre": titre, "url": url, "source": os.environ.get("SRC_SOURCE", "")[:100], "resume": os.environ.get("SRC_RESUME", "")[:1500],
           "date": os.environ.get("SRC_DATE", "")[:10]}
    rub = int(os.environ.get("SRC_RUBRIQUE", "0") or 0) if os.environ.get("SRC_RUBRIQUE", "0").isdigit() else 0
    cfg = ia.config()
    if not ia.disponibles(cfg, rub):
        ecrire(id_, {"erreur": "Aucun fournisseur d'IA utilisable (onglet IA de l'éditeur : activez-en un ou ajoutez une clé)."})
        return 0
    page = texte_long(url) if url else ""
    consigne = (f"Source : {src['source']}\nTitre de la source : {src['titre']}\nDate : {src['date']}\nExtrait du flux : {src['resume']}\n\n"
                f"Texte de la page (peut être incomplet ou absent) :\n{page or '(indisponible)'}\n\nProduis l'objet JSON demandé.")
    try:
        texte, f, m = ia.appeler(cfg["consignes"].get("detail") or SYSTEME, consigne, cfg, rub, valider=P.valider_ctrl(page + " " + src["resume"], src["source"], titre))
        rep = ia.extraire_json(texte)
        intro, resume = P.court(rep.get("intro"), 340), P.nettoyer_html(rep.get("resume"), 9000)
        if not intro or not resume:
            raise ValueError("réponse incomplète")
        analyse = P.nettoyer_html(rep.get("analyse"), 6000)
        action = P.nettoyer_html(rep.get("action"), 3000)
        fiab = "partiel" if rep.get("fiabilite") == "partiel" or len(page) < 300 else "ok"
        art = {"titre": P.court(rep.get("titre"), 140) or titre, "kicker": P.court(rep.get("kicker"), 40),
               "intro": "<p>" + html.escape(intro, quote=False) + "</p>", "resume": resume, "analyse": analyse, "action": action,
               "conclusion": P.nettoyer_html(rep.get("conclusion"), 2500), "fiabilite": fiab,
               "note": P.court(rep.get("note"), 300) or ("Texte de la page indisponible ou court : vérifier les faits à la source." if len(page) < 300 else ""),
               "section": rub, "source": src["source"], "url": url, "date": src["date"] or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
               "fournisseur": cfg["fournisseurs"][f]["nom"], "modele": m}
        c = controle.verifier(art, page + " " + src["resume"], src["source"], titre, False, True)
        art["controle"] = c
        if c["alertes"]:
            art["note"] = P.court((art.get("note") or "") + " " + controle.resume(c), 600)
        ecrire(id_, {"article": art})
    except Exception as e:
        ecrire(id_, {"erreur": str(e)[:300]})
    return 0


if __name__ == "__main__":
    sys.exit(main())
