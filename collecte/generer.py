#!/usr/bin/env python3
"""Génère les pages statiques du journal pour le référencement (SEO).

Lit data/items.json (écrit par l'éditeur) et produit :
  articles/<slug>/index.html   une vraie page par article (texte lisible par Google)
  rubriques/<slug>/index.html  une page par rubrique
  lexique/index.html           le lexique
  threat-actors/index.html     l'observatoire des acteurs de la menace (data/acteurs.json)
  sitemap.xml, robots.txt
Le design est repris de index.html (même feuille de style).
Aucune dépendance : bibliothèque standard Python uniquement.

Usage : python collecte/generer.py [--site https://exemple.github.io/depot/]
"""
import html
import json
import os
import re
import shutil
import sys
import unicodedata
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent

S = [["Actualités", "France et international"],
     ["Géopolitique", "Relations internationales, conflits, diplomatie"],
     ["Cyber & numérique", "Cybersécurité, IA, souveraineté numérique"],
     ["Économie", "Entreprises, marchés, innovation"],
     ["Société", "Éducation, culture, enjeux sociaux"],
     ["Analyses", "Opinions, enquêtes et articles scientifiques"],
     ["CTF", "Actualité des Capture The Flag"],
     ["Notions cyber", "Une notion de cybersécurité expliquée : hygiène, règles, bonnes pratiques"],
     ["Lexique", "Termes, sigles et notions expliqués"]]
RS = ["actualites", "geopolitique", "cyber-numerique", "economie", "societe", "analyses", "ctf", "notions-cyber", "lexique"]
RUB_PAGES = [0, 1, 2, 3, 4, 5, 7]          # rubriques qui ont une page statique (CTF = contenu d'exemple)
MOIS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"]


# ------------------------------------------------------------------ utilitaires
def esc(t):
    return html.escape("" if t is None else str(t), quote=True)


def unaccent(t):
    return "".join(c for c in unicodedata.normalize("NFD", str(t)) if unicodedata.category(c) != "Mn")


def slugify(t, n=70):
    s = re.sub(r"[^a-z0-9]+", "-", unaccent(t).lower()).strip("-")
    s = s[:n].strip("-")
    return s or "article"


def fd(d):
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", str(d or ""))
    if not m:
        return ""
    y, mo, da = int(m[1]), int(m[2]), int(m[3])
    return f"{da}{'er' if da == 1 else ''} {MOIS[mo - 1]} {y}"


def num(v, a, b, d):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return d
    return min(b, max(a, v))


def safe_url(u):
    u = str(u or "").strip()
    return u if re.match(r"^(https?://|mailto:)", u, re.I) else ""


def img_ok(v):
    v = str(v or "")
    return v if re.match(r"^images/[\w.-]+$", v) else ""


def lbl(u):
    try:
        h = re.sub(r"^www\.", "", re.match(r"^https?://([^/]+)", u)[1])
    except Exception:
        return u
    return {"linkedin.com": "LinkedIn", "x.com": "X", "twitter.com": "X", "github.com": "GitHub", "bsky.app": "Bluesky",
            "youtube.com": "YouTube", "facebook.com": "Facebook", "instagram.com": "Instagram"}.get(h, h)


def hexc(v):
    v = str(v or "").strip().lower()
    m = re.match(r"^#([0-9a-f]{6})$", v)
    if m:
        return "#" + m[1]
    m = re.match(r"^#([0-9a-f])([0-9a-f])([0-9a-f])$", v)
    if m:
        return "#" + m[1] * 2 + m[2] * 2 + m[3] * 2
    m = re.match(r"^rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*([\d.]+)\s*)?\)$", v)
    if m:
        if m[4] is not None and float(m[4]) == 0:
            return ""
        return "#" + "".join("%02x" % min(255, int(x)) for x in (m[1], m[2], m[3]))
    return ""


# ------------------------------------------------------------------ nettoyage HTML (même liste blanche que le journal)
OKT = {"p", "br", "strong", "b", "em", "i", "u", "a", "ul", "ol", "li", "h3", "h4", "blockquote", "table", "thead", "tbody",
       "tr", "th", "td", "caption"}
DROPT = {"script", "style", "iframe", "object", "embed", "svg", "math", "template", "noscript", "form", "input", "button",
         "textarea", "select", "link", "meta"}
VOID = {"br", "img", "hr", "input", "meta", "link", "wbr"}
ALT = {"p", "h3", "h4", "li", "blockquote", "td", "th"}
LEX = {}  # id -> texte brut du lexique (pour les infobulles)


class Clean(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self.stack = []      # (tag_source, emitted_close_html or None)
        self.skip = 0

    def _style(self, attrs, tag):
        st = dict(attrs).get("style") or ""
        m = re.search(r"text-align\s*:\s*(left|right|center|justify)", st, re.I)
        return m[1].lower() if (m and tag in ALT) else ""

    def handle_starttag(self, tag, attrs):
        if self.skip:
            if tag not in VOID:
                self.skip += 1
            return
        if tag in DROPT:
            if tag not in VOID:
                self.skip = 1
            return
        a = dict(attrs)
        t = "p" if tag == "div" else tag
        close = None
        if tag == "div" and "vid" in (a.get("class") or "").split():
            src = (a.get("data-src") or "").strip()
            if re.fullmatch(r"https://www\.youtube-nocookie\.com/embed/[\w-]{11}|https://player\.vimeo\.com/video/\d{5,12}|https://www\.dailymotion\.com/embed/video/[A-Za-z0-9]{5,12}", src):
                self.out.append(f'<div class="vid"><iframe src="{esc(src)}" title="Vidéo" loading="lazy" allowfullscreen referrerpolicy="strict-origin-when-cross-origin" allow="encrypted-media; picture-in-picture; fullscreen"></iframe></div>')
            elif re.fullmatch(r"https://[^\s\"'<>]+\.(?:mp4|webm|ogg)(?:\?[^\s\"'<>]*)?", src, re.I):
                self.out.append(f'<div class="vid"><video controls preload="metadata" playsinline src="{esc(src)}"></video></div>')
        elif tag == "span":
            cls = (a.get("class") or "").split()
            tip = (a.get("data-tip") or "").strip()
            lex = a.get("data-lex") or ""
            if "tip" in cls and (tip or lex in LEX):
                txt = plain(tip) if tip else LEX.get(lex, "")
                self.out.append(f'<span class="tip" title="{esc(txt[:700])}">')
                close = "</span>"
            else:
                bg = hexc(re.search(r"background(?:-color)?\s*:\s*([^;]+)", a.get("style") or "", re.I)[1]) \
                    if re.search(r"background(?:-color)?\s*:", a.get("style") or "", re.I) else ""
                mc = re.search(r"(?:^|;)\s*color\s*:\s*([^;]+)", a.get("style") or "", re.I)
                fc = hexc(mc[1]) if mc else ""
                if fc == "#010203":
                    fc = ""
                if bg or fc:
                    st = (f"background-color:{bg};" if bg else "") + (f"color:{fc}" if fc else "")
                    self.out.append(f'<span{" class=\"hl\"" if bg else ""} style="{st.rstrip(";")}">')
                    close = "</span>"
        elif t in OKT:
            if t == "a":
                h = safe_url(a.get("href"))
                if h:
                    self.out.append(f'<a href="{esc(h)}" rel="noopener noreferrer" target="_blank">')
                    close = "</a>"
            else:
                al = self._style(attrs, t)
                mc2 = re.search(r"(?:^|;)\s*color\s*:\s*([^;]+)", dict(attrs).get("style") or "", re.I)
                fc2 = hexc(mc2[1]) if mc2 else ""
                sty = (f"text-align:{al};" if al else "") + (f"color:{fc2}" if fc2 and fc2 != "#010203" else "")
                extra = f' style="{sty.rstrip(";")}"' if sty else ""
                if t in ("td", "th"):
                    for k in ("colspan", "rowspan"):
                        try:
                            n = int(a.get(k) or 0)
                        except ValueError:
                            n = 0
                        if 1 < n <= (30 if k == "colspan" else 100):
                            extra += f' {k}="{n}"'
                if t == "table":
                    self.out.append('<div class="tw">')
                self.out.append(f"<{t}{extra}>")
                close = f"</{t}>" + ("</div>" if t == "table" else "")
                if t == "br":
                    close = None
                    self.stack.append((tag, None))
                    return
        if tag in VOID:
            return
        self.stack.append((tag, close))

    def handle_startendtag(self, tag, attrs):
        if tag == "br" and not self.skip:
            self.out.append("<br>")

    def handle_endtag(self, tag):
        if self.skip:
            self.skip -= 1
            return
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                while len(self.stack) > i:
                    _, c = self.stack.pop()
                    if c:
                        self.out.append(c)
                return

    def handle_data(self, data):
        if not self.skip:
            self.out.append(esc(data).replace("&#x27;", "'"))

    def result(self):
        while self.stack:
            _, c = self.stack.pop()
            if c:
                self.out.append(c)
        return "".join(self.out)


def sanitize(h):
    p = Clean()
    p.feed(str(h or ""))
    p.close()
    return p.result()


class Txt(HTMLParser):
    BLOCK = {"p", "li", "h3", "h4", "blockquote", "div", "br", "tr", "td", "th", "table", "ul", "ol"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.t = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in DROPT:
            self.skip += 1
        if tag in self.BLOCK:
            self.t.append(" ")

    def handle_startendtag(self, tag, attrs):
        if tag in self.BLOCK:
            self.t.append(" ")

    def handle_endtag(self, tag):
        if tag in DROPT and self.skip:
            self.skip -= 1
        if tag in self.BLOCK:
            self.t.append(" ")

    def handle_data(self, d):
        if not self.skip:
            self.t.append(d)


def plain(h):
    h = "" if h is None else str(h)
    if re.search(r"</?[a-z][^>]*>", h, re.I):
        p = Txt()
        p.feed(h)
        p.close()
        h = "".join(p.t)
    return re.sub(r"\s+", " ", h).strip()


def rich(t):
    t = "" if t is None else str(t)
    if not t.strip():
        return ""
    if re.search(r"</?[a-z][^>]*>", t, re.I):
        return sanitize(t)
    return "".join("<p>" + esc(p.strip()).replace("\n", "<br>") + "</p>" for p in re.split(r"\n{2,}", t))


def lk(t):
    return re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
                  lambda m: f'<a href="{m[2]}" rel="noopener noreferrer" target="_blank">{m[1]}</a>', esc(t))


def lite(t, n=160):
    t = plain(t)
    if len(t) <= n:
        return t
    t = t[:n]
    k = t.rfind(" ")
    if k > n * 0.6:
        t = t[:k]
    return re.sub(r"[\s,;:.\-–]+$", "", t) + "…"


# ------------------------------------------------------------------ configuration
def site_url():
    for i, a in enumerate(sys.argv):
        if a == "--site" and i + 1 < len(sys.argv):
            return sys.argv[i + 1].rstrip("/") + "/"
        if a.startswith("--site="):
            return a.split("=", 1)[1].rstrip("/") + "/"
    if os.environ.get("SITE_URL"):
        return os.environ["SITE_URL"].rstrip("/") + "/"
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, name = repo.split("/", 1)
        if name.lower() == owner.lower() + ".github.io":
            return f"https://{owner}.github.io/"
        return f"https://{owner}.github.io/{name}/"
    return "https://twagirumukiza.github.io/cyber-risk-observer/"


def sec_of(x):
    s = x.get("section")
    try:
        k = int(s)
        if 0 <= k < len(S):
            return k
    except (TypeError, ValueError):
        pass
    r = x.get("rubrique")
    for i, v in enumerate(S):
        if v[0] == r:
            return i
    return 2


# ------------------------------------------------------------------ rendu d'un article
def ims(x, pre=""):
    px, py, pz = num(x.get("imgX"), 0, 100, 50), num(x.get("imgY"), 0, 100, 50), num(x.get("imgZ"), 1, 3, 1)
    s = f"object-position:{px:g}% {py:g}%;"
    if pz > 1:
        s += f"transform:scale({pz:g});transform-origin:{px:g}% {py:g}%"
    return s


def gal(lst, base):
    out = []
    for m in (lst if isinstance(lst, list) else [])[:6]:
        src = img_ok((m or {}).get("image"))
        if src:
            leg = esc((m or {}).get("legende") or "")
            out.append((src, leg))
    if not out:
        return ""
    return f"<div class='gal g{len(out)}'>" + "".join(
        f"<figure><img src='{base}{s}' alt='{l}' loading='lazy'>" + (f"<small class='cap'>{l}</small>" if l else "") + "</figure>"
        for s, l in out) + "</div>"


def article_body(x, base, url, related):
    """Reproduit la mise en page de l'article du journal (fonction article() de index.html)."""
    titre = esc(x.get("titre") or "Sans titre")
    kicker = esc(x.get("kicker") or x.get("source") or "")
    std = esc(plain(x.get("resume")))
    inf = rich(x.get("resume")) or ""
    intro = rich(x.get("intro"))
    chapo = f"<div class='std chapo'>{intro}</div>" if intro else f"<p class='std'>{std}</p>"
    st_intro = esc(x.get("stIntro") or "")
    ana = rich(x.get("analyse"))
    con = rich(x.get("conclusion"))
    acts = [lk(a) for a in (x.get("actions") if isinstance(x.get("actions"), list) else ([x["action"]] if x.get("action") else []))]
    ahh = rich(x.get("actionsHtml"))
    T = [esc(x.get("stInfo") or ""), esc(x.get("stAna") or ""), esc(x.get("stAct") or ""), esc(x.get("stCon") or "")]

    def HH(i, d, u=False):
        return T[i] or (("\x01" + d) if u else d)

    h1 = HH(0, "L’information", True) if inf else ""
    h2 = HH(1, "L’analyse", True) if ana else ""
    h3 = HH(2, "L’action", True) if (acts or ahh) else ""
    h4 = HH(3, "Conclusion") if con else ""
    med = x.get("medias") if isinstance(x.get("medias"), dict) else {}
    parts = []
    for k, p in enumerate((x.get("parties") if isinstance(x.get("parties"), list) else [])[:12]):
        p = p or {}
        ac = p.get("type") == "action"
        parts.append({"id": esc(str(p.get("id") or f"p{k}")), "ac": ac, "t": esc(p.get("titre") or ""),
                      "h": "" if ac else rich(p.get("texte")),
                      "l": [lk(t.strip()) for t in str(p.get("texte") or "").split("\n") if t.strip()] if ac else [],
                      "g": gal(p.get("imgs"), base)})

    pos = x.get("imgPos") if x.get("imgPos") in ("tete", "gauche", "droite", "milieu") else "tete"
    image = img_ok(x.get("image"))
    fg = ""
    if image:
        cap = f"<small class='cap'>Photo : {esc(x.get('credit'))}</small>" if x.get("credit") else ""
        fg = (f"<figure class='fg fg-{pos}'><div class=\"th\"><img src=\"{base}{image}\" alt=\"{esc(x.get('alt') or x.get('titre') or '')}\" "
              f"style=\"{ims(x)}\" fetchpriority=\"high\"></div>{cap}</figure>")
    infb = f"<div class='lv'><h2>{h1}</h2>{inf}</div>" if inf else ""
    top = fg if pos == "tete" else ""
    mid = fg if pos == "milieu" else ""
    side = f"<div class='mix mix-{pos}'>{fg}<div class='mixt'>{infb}</div></div>" if (fg and pos in ("gauche", "droite")) else ""

    lus = []
    for l in str(x.get("liensUtiles") or "").split("\n"):
        q = l.split("|")
        u = safe_url((q[-1] if len(q) > 1 else q[0]).strip())
        tt = "|".join(q[:-1]).strip() if len(q) > 1 else ""
        if re.match(r"^https?:", u, re.I):
            lus.append((esc(u), esc(tt or lbl(u))))
    lu = ("<div class='lv l5'><h2>Pour aller plus loin</h2><ul>" + "".join(
        f"<li><a href='{u}' rel='noopener noreferrer' target='_blank'>{t}</a></li>" for u, t in lus[:10]) + "</ul></div>") if lus else ""
    intr = ""

    BL = {}
    for p in parts:
        if p["ac"]:
            BL["p:" + p["id"]] = "<div class='lv l3'><h2>" + (p["t"] or "L’action") + "</h2><ul>" + "".join(f"<li>{t}</li>" for t in p["l"]) + "</ul>" + p["g"] + "</div>"
        else:
            BL["p:" + p["id"]] = "<div class='lv l6'>" + (f"<h2>{p['t']}</h2>" if p["t"] else "") + p["h"] + p["g"] + "</div>"
    BL["info"] = (side or infb) + gal(med.get("info"), base) + mid
    BL["ana"] = f"<div class='lv l2'><h2>{h2}</h2>{ana}{gal(med.get('ana'), base)}</div>" if ana else ""
    if ahh:
        BL["act"] = f"<div class='lv l3'><h2>{h3}</h2>{ahh}{gal(med.get('act'), base)}</div>"
    elif acts:
        BL["act"] = f"<div class='lv l3'><h2>{h3}</h2><ul>" + "".join(f"<li>{a}</li>" for a in acts) + f"</ul>{gal(med.get('act'), base)}</div>"
    else:
        BL["act"] = ""
    BL["con"] = f"<div class='lv l4'><h2>{h4}</h2>{con}{gal(med.get('con'), base)}</div>" if con else ""

    pk = ["p:" + p["id"] for p in parts]
    ks = ["info", "ana", "act", "con"] + pk
    o = []
    for k in (x.get("ordre") if isinstance(x.get("ordre"), list) else []):
        k = str(k)
        if k in ks and k not in o:
            o.append(k)
    d = ["info", "ana", "act"] + pk + ["con"]
    for i, k in enumerate(d):
        if k not in o:
            pv = None
            for q in range(i - 1, -1, -1):
                if d[q] in o:
                    pv = d[q]
                    break
            o.insert(0 if pv is None else o.index(pv) + 1, k)
    ordh = "".join(BL.get(k, "") for k in o)
    n = [0]

    def numb(_):
        n[0] += 1
        return f"{n[0]}. "
    ordh = re.sub("\x01", numb, ordh)

    # auteur
    au = ""
    aname, arole = esc(x.get("auteur") or ""), esc(x.get("auteurRole") or "")
    aphoto = img_ok(x.get("auteurPhoto"))
    alinks = [safe_url(l) for l in str(x.get("auteurLiens") or "").split("\n")]
    alinks = [l for l in alinks if re.match(r"^https?:", l, re.I)][:6]
    if aname or aphoto or alinks:
        au = ("<aside class='au' aria-label='Auteur'>" + (f"<img src='{base}{aphoto}' alt='' width='72' height='72'>" if aphoto else "") + "<div>"
              + (f"<b>{aname}</b>" if aname else "") + (f"<span>{arole}</span>" if arole else "")
              + (("<div class='aul'>" + "".join(f"<a href='{esc(l)}' rel='noopener noreferrer' target='_blank'>{esc(lbl(l))}</a>" for l in alinks) + "</div>") if alinks else "")
              + "</div></aside>")

    src = ""
    surl = x.get("url") if re.match(r"^https?://", str(x.get("url") or "")) else ""
    if surl or x.get("source"):
        src = "<div class='src'><b>Source :</b> " + (f"<a href='{esc(surl)}' rel='noopener'>{esc(x.get('source') or surl)}</a>" if surl else esc(x.get("source"))) + "</div>"

    relh = ""
    if related:
        relh = ("<h2 style='margin-top:26px;font:700 1.3rem var(--head)'>" + ("À lire aussi" if isinstance(x.get("related"), list) else "Dans la même rubrique")
                + "</h2><ul>" + "".join(f"<li><a href='{u}'>{t}</a></li>" for u, t in related) + "</ul>")

    eu, et = html.escape(url, quote=True), esc(x.get("titre") or "")
    from urllib.parse import quote
    qu, qt = quote(url, safe=""), quote(str(x.get("titre") or ""), safe="")
    share = ("<div class='shr'><span>Partager</span><span class='shl'>"
             f"<a href='https://www.linkedin.com/sharing/share-offsite/?url={qu}' target='_blank' rel='noopener noreferrer'>LinkedIn</a>"
             f"<a href='https://twitter.com/intent/tweet?url={qu}&amp;text={qt}' target='_blank' rel='noopener noreferrer'>X</a>"
             f"<a href='https://www.facebook.com/sharer/sharer.php?u={qu}' target='_blank' rel='noopener noreferrer'>Facebook</a>"
             f"<a href='https://wa.me/?text={qt}%20{qu}' target='_blank' rel='noopener noreferrer'>WhatsApp</a>"
             f"<a href='https://t.me/share/url?url={qu}&amp;text={qt}' target='_blank' rel='noopener noreferrer'>Telegram</a>"
             f"<a href='mailto:?subject={qt}&amp;body={qu}'>E-mail</a></span></div>")

    k = sec_of(x)
    crumb = f"<div class='crumb'><a href='{base}'>Accueil</a> › <a href='{base}rubriques/{RS[k]}/'>{esc(S[k][0])}</a></div>"
    by = f"<div class='by'><span>Par {aname or 'la rédaction'}</span><span>{esc(fd(x.get('date')))}</span></div>"
    return (f"<div class='art'>{crumb}<span class='k'>{kicker}</span><h1>{titre}</h1>{chapo}{by}"
            f"{top}{intr}{ordh}{lu}{au}{share}{src}{relh}"
            f"<p class='noprint' style='margin-top:22px'><a href='{base}#article-{esc(x.get('id'))}'>Ouvrir dans le journal interactif (recherche, infobulles, lexique) →</a></p></div>")


# ------------------------------------------------------------------ gabarit de page
def load_template():
    src = (ROOT / "index.html").read_text(encoding="utf-8")
    css = re.search(r"<style>(.*?)</style>", src, re.S)[1]
    fonts = re.search(r'<link href="https://fonts\.googleapis\.com[^>]*>', src)
    theme = re.search(r"<script>(try\{var _t=.*?)</script>", src, re.S)
    return css, fonts[0] if fonts else "", theme[1] if theme else ""


EXTRA_CSS = """
.shl{display:flex;gap:14px;flex-wrap:wrap}.shl a{text-decoration:underline}
.mast .tabs a{color:#fff;padding:10px 12px;font:600 .95rem var(--head);border-bottom:3px solid transparent;display:inline-block}
.mast .tabs a[aria-current=page]{border-bottom-color:var(--yel)}.mast .tabs{display:flex;flex-wrap:wrap}
.mast .logo{color:#fff;text-decoration:none}
.tip{border-bottom:2px solid #1f5fd1;cursor:help}.vid{position:relative;aspect-ratio:16/9;margin:1.2em 0;background:#000;border-radius:6px;overflow:hidden}.vid iframe,.vid video{position:absolute;inset:0;width:100%;height:100%;border:0}
.list-st{list-style:none;margin:0;padding:0}.list-st li{padding:14px 0;border-top:1px solid var(--line)}.list-st li:first-child{border-top:0}
.list-st h2{margin:2px 0;font:700 1.25rem var(--head)}.list-st p{margin:4px 0;color:var(--muted)}.list-st time{font-size:.8rem;color:var(--muted)}
.lxd dt{font:700 1.1rem var(--head);margin-top:16px}.lxd dd{margin:2px 0 0}
.to-actor{border:1px solid var(--line);border-radius:8px;margin:10px 0}.to-actor summary{cursor:pointer;padding:12px 14px;font:700 1.1rem var(--head)}.to-actor summary small{display:block;font:400 .84rem var(--body);color:var(--muted);margin-top:3px}
.to-det{padding:4px 14px 14px;border-top:1px solid var(--line)}.to-det dt{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-top:10px;font-weight:700}.to-det dd{margin:2px 0 0}
.to-notice{margin:16px 0;padding:12px 16px;border:1px solid #c9a24f;background:rgba(255,229,0,.12);border-radius:8px}
"""


def page(base, title, desc, canonical, body, tpl, extra_head="", active=None, og_image="", og_type="website", jsonld=None):
    css, fonts, theme = tpl
    nav = f'<a href="{base}">Accueil</a>' + "".join(
        f'<a href="{base}rubriques/{RS[k]}/"' + (' aria-current="page"' if active == k else "") + f">{esc(S[k][0])}</a>" for k in RUB_PAGES if k != 0
    ) + f'<a href="{base}lexique/"' + (' aria-current="page"' if active == 8 else "") + ">Lexique</a>" + f'<a href="{base}threat-actors/"' + (' aria-current="page"' if active == 9 else "") + ">Threat Actors</a>"
    ld = ""
    if jsonld:
        ld = '<script type="application/ld+json">' + json.dumps(jsonld, ensure_ascii=False).replace("</", "<\\/") + "</script>"
    img = f'<meta property="og:image" content="{esc(og_image)}"><meta name="twitter:card" content="summary_large_image"><meta name="twitter:image" content="{esc(og_image)}">' if og_image else '<meta name="twitter:card" content="summary">'
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<link rel="icon" type="image/png" sizes="32x32" href="{base}images/favicon-32.png"><link rel="icon" type="image/png" sizes="192x192" href="{base}images/favicon-192.png"><link rel="shortcut icon" href="{base}favicon.ico"><link rel="apple-touch-icon" href="{base}images/apple-touch-icon.png">
<title>{esc(title)}</title>
<meta name="description" content="{esc(desc)}">
<link rel="canonical" href="{esc(canonical)}">
<meta property="og:site_name" content="Cyber Risk Observer"><meta property="og:locale" content="fr_FR"><meta property="og:type" content="{og_type}">
<meta property="og:title" content="{esc(title)}"><meta property="og:description" content="{esc(desc)}"><meta property="og:url" content="{esc(canonical)}">
{img}
{extra_head}
{fonts}
<script>{theme}</script>
<style>{css}{EXTRA_CSS}</style>
{ld}
</head>
<body>
<header class="mast"><div class="w">
<a class="logo" href="{base}" aria-label="Cyber Risk Observer, retour à l’accueil">Cyber Risk<br>Observer</a>
<div class="tag">Veille cyber, géopolitique cyber et GRC</div>
<nav class="tabs" aria-label="Rubriques">{nav}</nav>
</div></header>
<main class="w">
{body}
</main>
<footer class="ft"><div class="w" style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap"><span>Cyber Risk Observer – by twagirumukiza</span><span><a href="{base}">Journal interactif</a> · <a href="{base}#plan-du-site">Plan du site</a> · <a href="{base}#archives">Articles archivés</a></span></div></footer>
</body>
</html>
"""


# ------------------------------------------------------------------ programme principal
def main():
    base = site_url()
    items_path = ROOT / "data" / "items.json"
    if not items_path.exists():
        print("data/items.json absent : rien à générer.")
        return 0
    try:
        items = json.loads(items_path.read_text(encoding="utf-8") or "[]")
    except Exception as e:
        print("items.json illisible :", e)
        return 1
    if not isinstance(items, list):
        items = []
    items = [x for x in items if isinstance(x, dict) and x.get("titre") and x.get("statut") in ("valide", "archive")]
    today = datetime.now(ZoneInfo("Europe/Paris")).strftime("%Y-%m-%d")

    # lexique
    lex = [x for x in items if sec_of(x) == 8 and x.get("statut") == "valide"]
    for x in lex:
        LEX[re.sub(r"[^\w.-]", "-", str(x.get("id") or ""))] = plain(x.get("resume"))[:700]

    arts = [x for x in items if sec_of(x) != 8 and not (x["statut"] == "valide" and x.get("date") and str(x["date"]) > today)]
    arts.sort(key=lambda x: str(x.get("date") or ""), reverse=True)

    # adresses stables (data/slugs.json)
    sp = ROOT / "data" / "slugs.json"
    try:
        slugs = json.loads(sp.read_text(encoding="utf-8")) if sp.exists() else {}
    except Exception:
        slugs = {}
    used = set(slugs.values())
    for x in arts:
        i = str(x.get("id"))
        if i not in slugs:
            s = base_s = slugify(x["titre"])
            n = 2
            while s in used:
                s = f"{base_s}-{n}"
                n += 1
            slugs[i] = s
            used.add(s)
    slugs = {k: v for k, v in slugs.items() if k in {str(x.get("id")) for x in arts}}
    sp.parent.mkdir(exist_ok=True)
    sp.write_text(json.dumps(slugs, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    def aurl(x):
        return f"{base}articles/{slugs[str(x['id'])]}/"

    tpl = load_template()
    for d in ("articles", "rubriques", "lexique", "archives", "threat-actors"):
        shutil.rmtree(ROOT / d, ignore_errors=True)

    urls = [(base, today)]
    by_sec = {}
    for x in arts:
        if x["statut"] == "valide":
            by_sec.setdefault(sec_of(x), []).append(x)
    archived = [x for x in arts if x["statut"] == "archive"]

    # pages d'articles
    for x in arts:
        k = sec_of(x)
        url = aurl(x)
        rel_ids = x.get("related") if isinstance(x.get("related"), list) else None
        if rel_ids is not None:
            rel = [y for y in arts if str(y.get("id")) in map(str, rel_ids) and y is not x]
        else:
            rel = [y for y in by_sec.get(k, []) if y is not x][:3]
        related = [(aurl(y), esc(y["titre"])) for y in rel]
        body = article_body(x, base, url, related)
        desc = lite(x.get("intro"), 158) or lite(x.get("resume"), 158) or lite(x.get("analyse"), 158) or S[k][1]
        image = img_ok(x.get("image"))
        og = base + image if image else ""
        date = str(x.get("date") or "")[:10]
        ld = {"@context": "https://schema.org", "@type": "NewsArticle", "headline": str(x["titre"])[:110],
              "description": desc, "mainEntityOfPage": {"@type": "WebPage", "@id": url}, "inLanguage": "fr",
              "articleSection": S[k][0],
              "author": {"@type": "Person", "name": x["auteur"]} if x.get("auteur") else {"@type": "Organization", "name": "Cyber Risk Observer"},
              "publisher": {"@type": "Organization", "name": "Cyber Risk Observer", "url": base}}
        if date:
            ld["datePublished"] = date
            ld["dateModified"] = date
        if og:
            ld["image"] = [og]
        extra = f'<meta property="article:published_time" content="{date}"><meta property="article:section" content="{esc(S[k][0])}">' if date else ""
        out = ROOT / "articles" / slugs[str(x["id"])]
        out.mkdir(parents=True, exist_ok=True)
        (out / "index.html").write_text(
            page(base, f"{x['titre']} – Cyber Risk Observer", desc, url, body, tpl, extra, active=k, og_image=og, og_type="article", jsonld=ld),
            encoding="utf-8")
        urls.append((url, date or today))

    # pages de rubriques
    for k in RUB_PAGES:
        lst = by_sec.get(k, [])
        cards = "".join(
            f"<li><span class='k'>{esc(y.get('kicker') or '')}</span><h2><a href='{aurl(y)}'>{esc(y['titre'])}</a></h2>"
            f"<p>{esc((lite(y.get('intro'), 220) or lite(y.get('resume'), 220)))}</p><time>{esc(fd(y.get('date')))}</time></li>" for y in lst)
        body = (f"<div class='art'><div class='crumb'><a href='{base}'>Accueil</a> › {esc(S[k][0])}</div><h1>{esc(S[k][0])}</h1>"
                f"<p style='color:var(--muted)'>{esc(S[k][1])}</p>" + (f"<ul class='list-st'>{cards}</ul>" if cards else "<p>Aucun article pour l’instant.</p>") + "</div>")
        url = f"{base}rubriques/{RS[k]}/"
        out = ROOT / "rubriques" / RS[k]
        out.mkdir(parents=True, exist_ok=True)
        (out / "index.html").write_text(
            page(base, f"{S[k][0]} – Cyber Risk Observer", f"{S[k][0]} : {S[k][1]}. Articles de veille et d’analyse du Cyber Risk Observer.", url, body, tpl, active=k),
            encoding="utf-8")
        urls.append((url, (str(lst[0].get("date") or today)[:10]) if lst else today))

    # archives
    if archived:
        cards = "".join(
            f"<li><span class='k'>{esc(S[sec_of(y)][0])}</span><h2><a href='{aurl(y)}'>{esc(y['titre'])}</a></h2>"
            f"<p>{esc((lite(y.get('intro'), 220) or lite(y.get('resume'), 220)))}</p><time>{esc(fd(y.get('date')))}</time></li>" for y in archived)
        body = (f"<div class='art'><div class='crumb'><a href='{base}'>Accueil</a> › Archives</div><h1>Archives</h1>"
                f"<p style='color:var(--muted)'>Articles plus anciens, retirés de la page d’accueil.</p><ul class='list-st'>{cards}</ul></div>")
        url = f"{base}archives/"
        out = ROOT / "archives"
        out.mkdir(parents=True, exist_ok=True)
        (out / "index.html").write_text(
            page(base, "Archives – Cyber Risk Observer", "Archives du Cyber Risk Observer : anciens articles de veille et d’analyse.", url, body, tpl), encoding="utf-8")
        urls.append((url, today))

    # lexique
    if lex:
        lex.sort(key=lambda x: unaccent(x["titre"]).lower())
        dl = "".join(f"<dt id='{esc(re.sub(r'[^\w.-]', '-', str(x.get('id') or '')))}'>{esc(x['titre'])}"
                     + (f" <small style='font-weight:400;color:var(--muted)'>— {esc(x.get('kicker'))}</small>" if x.get("kicker") else "")
                     + f"</dt><dd>{rich(x.get('resume'))}</dd>" for x in lex)
        body = (f"<div class='art lexq'><div class='crumb'><a href='{base}'>Accueil</a> › Lexique</div><h1>Lexique</h1>"
                f"<p style='color:var(--muted)'>{esc(S[8][1])}</p><dl class='lxd'>{dl}</dl></div>")
        url = f"{base}lexique/"
        out = ROOT / "lexique"
        out.mkdir(parents=True, exist_ok=True)
        (out / "index.html").write_text(
            page(base, "Lexique cyber – Cyber Risk Observer", "Lexique : termes, sigles et notions de cybersécurité expliqués simplement.", url, body, tpl, active=8),
            encoding="utf-8")
        urls.append((url, today))

    # observatoire des acteurs de la menace (data/acteurs.json, écrit par l'éditeur)
    ap = ROOT / "data" / "acteurs.json"
    if ap.exists():
        try:
            ad = json.loads(ap.read_text(encoding="utf-8"))
        except Exception:
            ad = {}
        acts = [a for a in (ad.get("acteurs") or []) if isinstance(a, dict) and a.get("nom")]
        if acts:
            cats = [(c.get("k"), c.get("l")) for c in (ad.get("cats") or []) if isinstance(c, dict) and c.get("k")] or [("state", "APT / liés à un État"), ("crime", "Cybercriminalité"), ("hacktivist", "Hacktivisme")]
            parts = []
            for ck, cl in cats:
                lst = [a for a in acts if a.get("cat") == ck]
                if not lst:
                    continue
                cards = ""
                for a in lst:
                    sub = " · ".join(x for x in (a.get("debut"), a.get("affil")) if x)
                    dd = "".join(f"<dt>{esc(f.get('l'))}</dt><dd>{esc(f.get('v'))}</dd>" for f in (a.get("champs") or []) if isinstance(f, dict) and f.get("v"))
                    cards += (f"<details class='to-actor' id='{esc(a.get('id') or '')}'><summary>{esc(a['nom'])}"
                              + (f" <span style='font-weight:400;color:var(--muted)'>/ {esc(a['alias'])}</span>" if a.get("alias") else "")
                              + f"<small>{esc(sub)}</small></summary><div class='to-det'><dl>{dd}</dl></div></details>")
                parts.append(f"<h2 style='font:700 1.35rem var(--head);margin-top:26px'>{esc(cl)} ({len(lst)})</h2>{cards}")

            def tab(head, rows):
                if not rows:
                    return ""
                th = "".join(f"<th>{esc(h)}</th>" for h in head)
                tr = "".join("<tr>" + "".join(f"<td>{esc((r + [''] * len(head))[i])}</td>" for i in range(len(head))) + "</tr>" for r in rows if isinstance(r, list))
                return f"<div class='tw'><table><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table></div>"

            ttp = tab(["Mode opératoire", "Objectif principal", "Groupes représentatifs cités"], ad.get("ttp"))
            vei = tab(["Domaine de veille", "Groupes à suivre"], ad.get("veille"))
            notice = (f"<div class='to-notice'><strong>Précaution méthodologique.</strong> {esc(ad.get('notice'))}</div>" if ad.get("notice") else "")
            body = (f"<div class='art'><div class='crumb'><a href='{base}'>Accueil</a> › Threat Actors Observatory</div>"
                    f"<h1>Threat Actors Observatory</h1>"
                    f"<p style='color:var(--muted)'>Registre de veille des groupes de hackers, cybercriminels et hacktivistes : {len(acts)} acteurs, leurs motivations, leurs modes opératoires et les secteurs exposés.</p>"
                    f"{notice}{''.join(parts)}"
                    + (f"<h2 style='font:700 1.35rem var(--head);margin-top:30px'>Comparer les modes opératoires (TTP)</h2>{ttp}" if ttp else "")
                    + (f"<h2 style='font:700 1.35rem var(--head);margin-top:30px'>Axes de veille recommandés</h2>{vei}" if vei else "")
                    + f"<p style='margin-top:26px'><a href='{base}#threat-actors' style='text-decoration:underline'>Ouvrir l’observatoire interactif (recherche et filtres)</a></p></div>")
            url = f"{base}threat-actors/"
            out = ROOT / "threat-actors"
            out.mkdir(parents=True, exist_ok=True)
            (out / "index.html").write_text(
                page(base, "Threat Actors Observatory – Cyber Risk Observer",
                     f"Registre de veille de {len(acts)} groupes de hackers, cybercriminels et hacktivistes : motivations, modes opératoires, cibles.",
                     url, body, tpl, active=9), encoding="utf-8")
            urls.append((url, str(ad.get("maj") or today)[:10]))

    # rubrique CTF (data/ctf.json, écrit par l'éditeur ; éléments d'exemple exclus)
    cp = ROOT / "data" / "ctf.json"
    if cp.exists():
        try:
            cd = json.loads(cp.read_text(encoding="utf-8"))
        except Exception:
            cd = {}
        if isinstance(cd, dict):
            keep = lambda l: [x for x in (l or []) if isinstance(x, dict) and not x.get("ex")]
            cal = sorted([c for c in keep(cd.get("calendrier")) if c.get("nom") and (not c.get("date") or str(c["date"]) >= today)], key=lambda c: str(c.get("date") or "9"))
            rk = [r for r in keep(cd.get("classement")) if r.get("equipe")]
            wu = [w for w in keep(cd.get("writeups")) if w.get("titre")]
            if cal or rk or wu:
                def lien(t, u):
                    u = str(u or "")
                    return f"<a href='{esc(u)}' rel='noopener' style='text-decoration:underline'>{esc(t)}</a>" if u.startswith(("http://", "https://")) and "ctftime.org" not in u else esc(t)
                hh = lambda t: f"<h2 style='font:700 1.35rem var(--head);margin-top:26px'>{esc(t)}</h2>"
                body = (f"<div class='art'><div class='crumb'><a href='{base}'>Accueil</a> › CTF</div><h1>CTF</h1>"
                        f"<p style='color:var(--muted)'>{esc(cd.get('intro') or 'Actualité des Capture The Flag : compétitions, classements et corrigés commentés.')}</p>")
                if cal:
                    body += hh("Calendrier") + "<ul>" + "".join(f"<li><b>{esc(c.get('date'))}</b> — {lien(c['nom'], c.get('url'))} <span style='color:var(--muted)'>{esc(' · '.join(x for x in (c.get('duree'), c.get('format'), c.get('niveau')) if x))}</span></li>" for c in cal) + "</ul>"
                if rk:
                    body += hh(cd.get("classTitre") or "Classement") + "<div class='tw'><table><thead><tr><th>Rang</th><th>Équipe</th><th>Points</th></tr></thead><tbody>" + "".join(f"<tr><td>{i + 1}</td><td>{esc(r['equipe'])}</td><td>{esc(r.get('points'))}</td></tr>" for i, r in enumerate(rk)) + "</tbody></table></div>"
                if cd.get("debuter"):
                    body += hh("Débuter") + f"<p>{esc(cd['debuter'])}</p>"
                if wu:
                    body += hh("Writeups") + "<ul>" + "".join(f"<li><b>{esc(w.get('cat'))}</b> — {lien(w['titre'], w.get('url'))}</li>" for w in wu) + "</ul>"
                body += f"<p style='margin-top:26px'><a href='{base}#ctf' style='text-decoration:underline'>Ouvrir la rubrique interactive</a></p></div>"
                url = f"{base}rubriques/ctf/"
                out = ROOT / "rubriques" / "ctf"
                out.mkdir(parents=True, exist_ok=True)
                (out / "index.html").write_text(
                    page(base, "CTF – Cyber Risk Observer", "Calendrier des Capture The Flag, classement et writeups.", url, body, tpl, active=6), encoding="utf-8")
                urls.append((url, str(cd.get("maj") or today)[:10]))

    # sitemap + robots
    sm = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for u, d in urls:
        sm.append(f"<url><loc>{html.escape(u)}</loc><lastmod>{d}</lastmod></url>")
    sm.append("</urlset>")
    (ROOT / "sitemap.xml").write_text("\n".join(sm) + "\n", encoding="utf-8")
    (ROOT / "robots.txt").write_text(f"User-agent: *\nAllow: /\n\nSitemap: {base}sitemap.xml\n", encoding="utf-8")
    print(f"{len(arts)} articles, {len(RUB_PAGES)} rubriques, {len(lex)} termes de lexique, {len(urls)} adresses dans sitemap.xml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
