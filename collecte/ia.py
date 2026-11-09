#!/usr/bin/env python3
"""Gestionnaire d'IA : plusieurs fournisseurs (gratuits ou payants), avec repli automatique.

Réglages (sans aucun secret) : data/ia.json, modifiables depuis l'éditeur (onglet « IA »).
Clés : UNIQUEMENT dans les secrets du dépôt GitHub (Settings > Secrets and variables > Actions),
jamais dans le navigateur ni dans un fichier. Le workflow les reçoit en variables d'environnement.

  python collecte/ia.py test     -> teste chaque fournisseur dont la clé existe et liste ses modèles
                                    -> data/ia-etat.json (clés présentes oui/non, résultats, modèles)

Python standard uniquement.
"""
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CONFIG = Path("data/ia.json")
ETAT = Path("data/ia-etat.json")

FOURNISSEURS = {
    "anthropic": {"nom": "Claude (Anthropic)", "type": "anthropic", "url": "https://api.anthropic.com/v1/messages",
                  "cle": "ANTHROPIC_API_KEY", "gratuit": False, "modele": "claude-sonnet-5-5", "actif": True},
    "openai": {"nom": "OpenAI", "type": "openai", "url": "https://api.openai.com/v1/chat/completions",
               "cle": "OPENAI_API_KEY", "gratuit": False, "modele": "gpt-4.1-mini", "actif": True},
    "gemini": {"nom": "Google Gemini", "type": "openai", "url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
               "cle": "GEMINI_API_KEY", "gratuit": True, "modele": "gemini-2.5-flash", "actif": True},
    "groq": {"nom": "Groq", "type": "openai", "url": "https://api.groq.com/openai/v1/chat/completions",
             "cle": "GROQ_API_KEY", "gratuit": True, "modele": "openai/gpt-oss-120b", "actif": True},
    "mistral": {"nom": "Mistral", "type": "openai", "url": "https://api.mistral.ai/v1/chat/completions",
                "cle": "MISTRAL_API_KEY", "gratuit": True, "modele": "mistral-small-latest", "actif": True},
    "openrouter": {"nom": "OpenRouter", "type": "openai", "url": "https://openrouter.ai/api/v1/chat/completions",
                   "cle": "OPENROUTER_API_KEY", "gratuit": True, "modele": "", "actif": True},
    # OPTION, désactivée par défaut (à cocher dans l'onglet IA). 100 % gratuit, sans compte ni clé (service public de Pollinations). Qualité et disponibilité variables,
    # envois anonymes mais non confidentiels : à garder en dernier recours. Vérifier avec le bouton « Tester ».
    "pollinations": {"nom": "Pollinations (gratuit, sans clé)", "type": "openai", "url": "https://text.pollinations.ai/openai",
                     "cle": "", "sanscle": True, "gratuit": True, "modele": "openai", "actif": False},
}
ORDRE = ["anthropic", "openai", "gemini", "groq", "mistral", "openrouter", "pollinations"]
RUBRIQUES = {"0": "Actualités", "1": "Géopolitique", "2": "Cyber & numérique", "3": "Économie", "4": "Société", "7": "Notions cyber"}
USAGE = {}     # "fournisseur · modèle" -> {"n": appels réussis, "e": erreurs}


def config():
    """Réglages = valeurs par défaut + data/ia.json (qui peut ajouter des fournisseurs personnalisés)."""
    try:
        c = json.loads(CONFIG.read_text(encoding="utf-8"))
        if not isinstance(c, dict):
            c = {}
    except Exception:
        c = {}
    f = {k: dict(v) for k, v in FOURNISSEURS.items()}
    for k, v in (c.get("fournisseurs") or {}).items():
        if isinstance(v, dict) and re.fullmatch(r"[a-z0-9_-]{2,30}", str(k)):
            f.setdefault(k, {"nom": k, "type": "openai", "url": "", "cle": "", "gratuit": False, "modele": "", "actif": True})
            f[k].update({a: b for a, b in v.items() if a in ("nom", "type", "url", "cle", "gratuit", "modele", "actif")})
    ordre = [k for k in (c.get("ordre") or []) if k in f] + [k for k in ORDRE + list(f) if k in f and k not in (c.get("ordre") or [])]
    ordre = list(dict.fromkeys(ordre))
    rub = {}
    for k in RUBRIQUES:
        r = (c.get("rubriques") or {}).get(k) or {}
        rub[k] = {"nombre": max(0, min(15, int(r.get("nombre", 7)))) if str(r.get("nombre", 7)).lstrip("-").isdigit() else 7,
                  "fournisseur": r.get("fournisseur") or "auto", "modele": str(r.get("modele") or "")}
    plafond = c.get("plafond")
    return {"fournisseurs": f, "ordre": ordre, "rubriques": rub,
            "plafond": int(plafond) if str(plafond).isdigit() else 48,
            "consignes": {"articles": str((c.get("consignes") or {}).get("articles") or ""),
                          "notions": str((c.get("consignes") or {}).get("notions") or "")}}


def secret(nom):
    if not nom:
        return ""
    v = os.environ.get(nom, "").strip()
    if v:
        return v
    try:
        return str(json.loads(os.environ.get("TOUS_SECRETS") or "{}").get(nom, "")).strip()
    except Exception:
        return ""


def a_cle(p):
    """Utilisable côté clé : fournisseur sans clé (service gratuit anonyme) ou secret présent."""
    return bool(p.get("sanscle")) or bool(secret(p.get("cle")))


def disponibles(cfg, rub=None):
    """Fournisseurs utilisables (actifs, clé présente, adresse https), dans l'ordre de repli."""
    ordre = list(cfg["ordre"])
    voulu = (cfg["rubriques"].get(str(rub)) or {}).get("fournisseur") if rub is not None else None
    if voulu and voulu != "auto" and voulu in ordre:
        ordre.remove(voulu)
        ordre.insert(0, voulu)
    out = []
    for k in ordre:
        p = cfg["fournisseurs"][k]
        if p.get("actif") is False or not str(p.get("url", "")).startswith("https://") or not a_cle(p):
            continue
        out.append(k)
    return out


def _post(url, entetes, corps, delai=120):
    req = urllib.request.Request(url, data=json.dumps(corps).encode(), method="POST", headers={"content-type": "application/json", **entetes})
    with urllib.request.urlopen(req, timeout=delai) as r:
        return json.loads(r.read().decode())


def _get(url, entetes):
    req = urllib.request.Request(url, headers=entetes)
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.loads(r.read().decode())


def completer(p, modele, systeme, consigne):
    cle = secret(p["cle"])
    if p.get("type") == "anthropic":
        rep = _post(p["url"], {"x-api-key": cle, "anthropic-version": "2023-06-01"},
                    {"model": modele, "max_tokens": 4000, "system": systeme, "messages": [{"role": "user", "content": consigne}]})
        return "".join(b.get("text", "") for b in rep.get("content", []) if b.get("type") == "text")
    rep = _post(p["url"], {"Authorization": "Bearer " + cle} if cle else {},
                {"model": modele, "messages": [{"role": "system", "content": systeme}, {"role": "user", "content": consigne}]})
    return (rep.get("choices") or [{}])[0].get("message", {}).get("content") or ""


def appeler(systeme, consigne, cfg, rub=None, valider=None):
    """Essaie les fournisseurs dans l'ordre ; passe au suivant en cas d'erreur (quota, panne…). -> (texte, id, modèle)"""
    erreurs = []
    rr = cfg["rubriques"].get(str(rub)) or {}
    for k in disponibles(cfg, rub):
        p = cfg["fournisseurs"][k]
        modele = (rr.get("modele") if rr.get("fournisseur") == k and rr.get("modele") else "") or p.get("modele") or ""
        if not modele:
            erreurs.append(f"{p['nom']} : aucun modèle choisi")
            continue
        cle_usage = f"{p['nom']} · {modele}"
        try:
            t = completer(p, modele, systeme, consigne)
            if not t.strip():
                raise ValueError("réponse vide")
            if valider:
                valider(t)             # ex. JSON exploitable ; sinon on passe au fournisseur suivant
            USAGE.setdefault(cle_usage, {"n": 0, "e": 0})["n"] += 1
            return t, k, modele
        except Exception as e:
            USAGE.setdefault(cle_usage, {"n": 0, "e": 0})["e"] += 1
            erreurs.append(f"{p['nom']} : {str(e)[:120]}")
    raise RuntimeError("aucun fournisseur n'a répondu (" + " ; ".join(erreurs) + ")" if erreurs else "aucun fournisseur disponible (clé absente ?)")


def extraire_json(t):
    t = re.sub(r"```(?:json)?", "", str(t))
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b <= a:
        raise ValueError("réponse sans JSON : « " + re.sub(r"\s+", " ", t.strip())[:100] + " »")
    try:
        return json.loads(t[a:b + 1])
    except ValueError as e:
        raise ValueError("JSON invalide (" + str(e)[:60] + ")")


def modeles(p):
    cle = secret(p["cle"])
    if p.get("type") == "anthropic":
        d = _get("https://api.anthropic.com/v1/models?limit=100", {"x-api-key": cle, "anthropic-version": "2023-06-01"})
    else:
        d = _get(re.sub(r"/chat/completions/?$", "/models", p["url"]), {"Authorization": "Bearer " + cle})
    return sorted({str(m.get("id") or m.get("name", "")).replace("models/", "") for m in (d.get("data") or d.get("models") or []) if isinstance(m, dict)})[:300]


def tester():
    cfg = config()
    res = {"maj": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "cles": {}, "tests": {}, "modeles": {}}
    for k, p in cfg["fournisseurs"].items():
        res["cles"][k] = a_cle(p)
        if not res["cles"][k] or not str(p.get("url", "")).startswith("https://"):
            continue
        t0 = time.time()
        try:
            ml = [] if p.get("sanscle") else modeles(p)
            res["modeles"][k] = ml
        except Exception as e:
            ml = []
            res["modeles"][k] = []
            res["tests"][k] = {"ok": False, "erreur": "liste des modèles : " + str(e)[:140]}
        modele = p.get("modele") or (ml[0] if ml else "")
        try:
            if not modele:
                raise ValueError("aucun modèle choisi")
            txt = completer(p, modele, "Réponds en français, en une phrase.", "Qu'est-ce qu'un SOC en cybersécurité ?")
            res["tests"][k] = {"ok": True, "ms": int((time.time() - t0) * 1000), "modele": modele, "extrait": txt.strip()[:200]}
        except Exception as e:
            res["tests"][k] = {"ok": False, "modele": modele, "erreur": str(e)[:160]}
        print(k, res["tests"][k].get("ok"), res["tests"][k].get("erreur", ""))
    ETAT.parent.mkdir(exist_ok=True)
    ETAT.write_text(json.dumps(res, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return 0


def maj_cles():
    """Met à jour seulement l'indicateur « clé présente » (aucune valeur de clé n'est écrite)."""
    cfg = config()
    try:
        e = json.loads(ETAT.read_text(encoding="utf-8"))
    except Exception:
        e = {}
    e["cles"] = {k: a_cle(p) for k, p in cfg["fournisseurs"].items()}
    e.setdefault("maj", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    ETAT.parent.mkdir(exist_ok=True)
    ETAT.write_text(json.dumps(e, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(tester() if (sys.argv[1:] or ["test"])[0] == "test" else 0)
