# -*- coding: utf-8 -*-
"""Logger partagé (commande + proxy REST) : fichier rotatif hors dossier d'app
(SHC-safe), sans secret, incassable (repli stderr)."""

import logging
import logging.handlers
import os
import re
import sys

# Caractères de contrôle à neutraliser dans un message journalisé. Les valeurs
# journalisées (index, query, pattern, nom de profil) viennent de l'utilisateur :
# un saut de ligne y forge une fausse entrée de journal (CWE-117). Démontré : un
# non-admin injectait une ligne « user=admin » dans le journal du proxy
# privilégié, ruinant la traçabilité. On neutralise au FORMATAGE, donc une fois
# pour tous les sites d'appel, présents et futurs, et avant que la valeur ne soit
# rejetée par la validation (qui intervient plus tard).
_CTRL = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x85\u2028\u2029]")
# U+0085, U+2028 et U+2029 (1.20.1) : Splunk ne coupe pas les événements sur
# eux, mais les outils qui lisent le fichier ligne à ligne (Python, éditeurs) y
# voient des fins de ligne : une valeur hostile y forgeait une fausse entrée.

# Longueur maximale d'une ligne écrite (1.20.1), en octets UTF-8. Mesuré : une
# valeur saisie (index=, profile=) de 1 Mo donnait une ligne de 1 Mo, recopiée
# telle quelle dès le niveau INFO — Splunk la tronquait en silence à 100 000
# octets dans _internal (« Truncating line »), et cinq recherches de ce genre
# faisaient tourner le fichier, une vingtaine en évinçaient l'historique. Sous le
# TRUNCATE de 100 000 octets des sourcetypes de l'app, la coupe dite.
LIGNE_MAX_OCTETS = 60000


def court(texte, maxi=80):
    """Texte borné à `maxi` caractères, la coupe dite."""
    t = str(texte)
    return t if len(t) <= maxi else f"{t[:maxi]} [...] et {len(t) - maxi} caractères de plus"


def apercu(valeur, maxi=80):
    """Valeur saisie par l'utilisateur, citée dans un message d'erreur : bornée
    (mesuré, une étiquette invalide de 300 Ko revenait entière dans le message
    du job et au journal)."""
    t = str(valeur)
    return repr(t) if len(t) <= maxi else f"{t[:maxi]!r} [...] et {len(t) - maxi} caractères de plus"


def _borne_ligne(ligne):
    octets = ligne.encode("utf-8")
    if len(octets) <= LIGNE_MAX_OCTETS:
        return ligne
    garde = octets[:LIGNE_MAX_OCTETS].decode("utf-8", "ignore")
    return f"{garde} [...] et {len(ligne) - len(garde)} caractères de plus"

# Identifiants embarqués dans une URL (`http://compte:motdepasse@hôte`). Un
# `es_host` saisi sous cette forme finissait EN CLAIR dans esearch.log — lui-même
# indexé dans `_internal`, bien plus largement lisible que storage/passwords
# (CWE-532, démontré). Toute l'information d'identification est masquée,
# pas seulement le mot de passe : un jeton seul (`https://jeton@hôte`) en est un.
_URL_AVEC_IDENTIFIANTS = re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@]+@")


class _FormatSansSautDeLigne(logging.Formatter):
    def format(self, record):
        # On neutralise le message RENDU (message + arguments déjà substitués),
        # pas l'asctime/levelname qui sont produits par logging lui-même.
        message = _URL_AVEC_IDENTIFIANTS.sub(r"\1***@", super().format(record))
        message = _CTRL.sub(lambda m: ("\\x%02x" if ord(m.group()) < 0x100 else "\\u%04x")
                            % ord(m.group()), message)
        return _borne_ligne(message)


class _FichierTournant(logging.handlers.RotatingFileHandler):
    """Fichier rotatif partagé par PLUSIEURS processus : chaque recherche (la
    commande) et le proxy persistant écrivent dans esearch.log.

    Mesuré (1.20.0) : quand une recherche faisait tourner le fichier, le proxy
    gardait son descripteur sur l'ancien, renommé esearch.log.1, et y écrivait
    la suite ; trois rotations plus tard, ce fichier est supprimé. Avant chaque
    écriture, on rouvre donc le fichier si le chemin ne désigne plus celui
    qu'on tient (même principe que WatchedFileHandler)."""

    def emit(self, record):
        if self.stream is not None:
            try:
                sur_disque = os.stat(self.baseFilename)
                tenu = os.fstat(self.stream.fileno())
                deplace = (sur_disque.st_dev, sur_disque.st_ino) != (tenu.st_dev, tenu.st_ino)
            except FileNotFoundError:
                deplace = True
            except OSError:
                deplace = False
            if deplace:
                self.stream.close()
                self.stream = self._open()
        super().emit(record)


# Mode debug d'UNE recherche (`| esearch debug=true`, 1.17.0). Le niveau global
# `[settings] log_level` vaut pour toutes les recherches de tous les
# utilisateurs ; ici, seules les lignes de la recherche concernée passent en
# DEBUG, marquées pour être retrouvées : `[debug sid=<sid> debug_tag=<étiquette>]`.
# L'étiquette vient de l'utilisateur : forme bornée, sans espace ni crochet, pour
# que le marqueur reste lisible et cherchable tel quel.
_ETIQUETTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
# Identifiant de recherche Splunk (`1792310956.135`, `scheduler__admin__…`,
# `rt_md_…`) : transmis par la commande au proxy, donc revalidé là-bas.
_SID = re.compile(r"^[A-Za-z0-9_.:@-]{1,200}$")


def valide_etiquette(valeur):
    """Étiquette de debug_tag=, ou ValueError avec la forme attendue."""
    if not _ETIQUETTE.match(valeur or ""):
        raise ValueError(f"debug_tag invalide : {apercu(valeur)} (1 à 64 caractères, lettres, "
                         "chiffres et _ . : -, en commençant par une lettre ou un chiffre)")
    return valeur


def valide_sid(valeur):
    if not _SID.match(valeur or ""):
        raise ValueError(f"sid invalide : {apercu(valeur)}")
    return valeur


def marqueur_debug(sid=None, etiquette=None):
    """Marqueur des lignes d'une recherche en mode debug."""
    return "[" + " ".join(["debug"] + ([f"sid={sid}"] if sid else [])
                          + ([f"debug_tag={etiquette}"] if etiquette else [])) + "]"


# Ligne « requête envoyée à Elasticsearch » : marquée par ce drapeau (extra),
# elle est la seule écrite par une recherche debug=t en portée `query`.
REQUETE = {"esearch_requete": True}
PORTEES = ("query", "all")


def portee_debug(valeur):
    """[settings] debug_search_scope : `query` (défaut) ou `all` ; une valeur
    illisible vaut `query`, la portée la plus étroite."""
    v = (valeur or "query").strip().lower()
    return v if v in PORTEES else "query"


def est_requete(record):
    return bool(getattr(record, "esearch_requete", False))


class JournalRecherche(logging.LoggerAdapter):
    """Journal d'UNE recherche en mode debug (debug=t).

    Portée `all` : chaque ligne de la recherche porte le marqueur et est
    écrite, DEBUG compris, quel que soit le niveau global. Portée `query`
    (défaut, [settings] debug_search_scope) : seule la ligne de la requête
    envoyée à Elasticsearch (extra=REQUETE) est marquée et forcée ; les autres
    suivent le journal ordinaire, comme pour une recherche sans debug.

    `echo` reçoit, formatée, chaque ligne marquée : la commande l'écrit dans le
    search.log du job (inspecteur), le proxy la renvoie à la commande.

    Le niveau du logger partagé n'est jamais modifié : le proxy est un processus
    persistant qui sert tous les utilisateurs, et y passer le logger en DEBUG
    pour une recherche y aurait passé aussi les recherches voisines."""

    def __init__(self, logger, marqueur, tout=True, echo=None):
        super().__init__(logger, {})
        self.marqueur = marqueur
        self.tout = tout
        self.echo = echo

    def isEnabledFor(self, level):
        return not self.logger.disabled

    def log(self, level, msg, *args, **kwargs):
        if self.logger.disabled:
            return
        if not self.tout and not (kwargs.get("extra") or {}).get("esearch_requete"):
            if self.logger.isEnabledFor(level):
                self.logger.log(level, msg, *args, **kwargs)
            return
        msg = f"{self.marqueur} {msg}"
        record = self.logger.makeRecord(self.logger.name, level, "(debug)", 0, msg, args,
                                        kwargs.get("exc_info"), extra=kwargs.get("extra"))
        # Sous le niveau global aussi : logger.handle ne refiltre pas le niveau.
        self.logger.handle(record)
        if self.echo:
            self.echo(_FORMAT_ECHO.format(record))


_FORMAT_ECHO = _FormatSansSautDeLigne("[%(levelname)s] %(message)s")


# Bornes de la requête affichée (journal, warning, page Query), coupe dite :
# chaîne quelconque (requête Lucene…) 10 000 caractères ; valeur ou nom de champ
# d'une liste terms 200 (1.20.1 : mesuré, UNE valeur de 1 Mo, ou 100 valeurs de
# 10 Ko, donnaient une requête affichée de 1 Mo) ; texte entier 50 000.
CHAINE_MAX, TERME_MAX, REQUETE_AFFICHEE_MAX = 10000, 200, 50000


def _abrege(valeur, max_terms, cle=None):
    """Copie lisible d'un corps de requête : listes `terms` coupées après
    `max_terms` éléments, valeurs et chaînes bornées, la coupe dite."""
    if isinstance(valeur, dict):
        return {k: (_abrege_terms(v, max_terms) if k == "terms" and isinstance(v, dict)
                    else _abrege(v, max_terms, k)) for k, v in valeur.items()}
    if isinstance(valeur, list):
        return [_abrege(v, max_terms) for v in valeur]
    if isinstance(valeur, str):
        return court(valeur, CHAINE_MAX)
    return valeur


def _abrege_terms(terms, max_terms):
    sortie = {}
    for champ, valeurs in terms.items():
        if isinstance(valeurs, list):
            reste = len(valeurs) - max_terms
            valeurs = [court(v, TERME_MAX) if isinstance(v, str) else v for v in valeurs[:max_terms]]
            if reste > 0:
                valeurs.append(f"[...] et {reste} de plus")
        sortie[court(champ, TERME_MAX)] = valeurs
    return sortie


def requete_lisible(methode, url, corps, max_terms=100):
    """« POST http://hôte/index/_search {corps} » : identifiants d'URL masqués,
    corps abrégé (listes terms, valeurs, chaînes, texte entier) avec la coupe dite."""
    import json
    url = court(_URL_AVEC_IDENTIFIANTS.sub(r"\1***@", url), CHAINE_MAX)
    texte = f"{methode} {url} {json.dumps(_abrege(corps, max(1, int(max_terms))), ensure_ascii=False)}"
    return court(texte, REQUETE_AFFICHEE_MAX)


def get_logger(name="esearch"):
    """Retourne le logger `esearch` (singleton). Écrit dans
    $SPLUNK_HOME/var/log/splunk/esearch.log (rotatif 5 Mo x3)."""
    logger = logging.getLogger(name)
    if getattr(logger, "_esearch_configured", False):
        return logger
    logger.propagate = False
    logger.setLevel(logging.INFO)
    try:
        handler = _FichierTournant(
            os.path.join(os.environ.get("SPLUNK_HOME", "/opt/splunk"),
                         "var", "log", "splunk", "esearch.log"),
            maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    except Exception:                       # repli : stderr (search.log)
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_FormatSansSautDeLigne(
        "%(asctime)s [%(levelname)s] [pid=%(process)d] %(message)s"))
    logger.addHandler(handler)
    logger._esearch_configured = True
    return logger
