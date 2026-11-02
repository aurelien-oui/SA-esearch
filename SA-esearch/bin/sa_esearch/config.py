# -*- coding: utf-8 -*-
"""Lecture d'esearch.conf (par splunkd, 1.26.7) et résolution de la connexion."""

import base64
import os
import re
import ssl
from urllib.parse import quote, urlsplit

from sa_esearch import APP_NAME
from sa_esearch.log import apercu, court

VALID_PAGINATIONS = ("auto", "pit", "scroll")

# Caractères de contrôle interdits dans un identifiant (clé API, mot de passe,
# nom d'utilisateur) : ils deviennent une valeur d'en-tête HTTP ou d'auth basic.
_CTRL_IDENTIFIANT = re.compile(r"[\r\n\x00-\x1f\x7f]")


def entete_basic(utilisateur, mot_de_passe):
    """En-tête `Authorization: Basic` encodé en UTF-8 (RFC 7617).

    `requests` encode l'auth basic en latin-1, alors qu'Elasticsearch la décode
    en UTF-8. Un mot de passe CORRECT contenant « é » était donc refusé (401),
    et un « € » ou un caractère non latin levait une UnicodeEncodeError dont le
    message — affiché et journalisé — désignait la position du caractère dans le
    mot de passe. L'en-tête est donc construit ici, en UTF-8, comme le fait curl.
    """
    jeton = f"{utilisateur}:{mot_de_passe}".encode()   # UTF-8
    return "Basic " + base64.b64encode(jeton).decode("ascii")


def valide_identifiant(valeur, quoi):
    """Identifiant sûr à placer dans un en-tête HTTP, ou ValueError.

    Un secret contenant un CRLF (ou autre caractère de contrôle) faisait lever à
    `requests` une `InvalidHeader` dont le message CONTIENT la valeur du secret —
    laquelle finissait en clair dans esearch.log et, sur le chemin ad hoc, à
    l'écran (CWE-532). On rejette ici, avec un message qui ne réénonce JAMAIS la
    valeur : on ne nomme que le champ fautif.
    """
    if valeur is None:
        raise ValueError(f"{quoi} manquant")
    if _CTRL_IDENTIFIANT.search(valeur):
        raise ValueError(
            f"{quoi} invalide : contient un caractère de contrôle "
            "(saut de ligne, tabulation…). Corrigez le secret du profil.")
    return valeur


def load_conf(logger=None, service=None):
    """esearch.conf, lu par splunkd (`conf_splunkd`) avec le service fourni :
    jeton de l'utilisateur pour les commandes, jeton système pour le proxy.

    Jusqu'en 1.26.6, l'app lisait elle-même les fichiers default/ et local/
    (`configparser`) : deux lecteurs, deux vérités possibles (M6 de la revue).
    Cette lecture est retirée, sans repli : sans splunkd, pas de conf."""
    if service is None:
        raise RuntimeError("configuration esearch : splunkd non fourni (lecture de la "
                           "conf impossible)")
    return conf_splunkd(service, logger)


def conf_splunkd(service, logger=None):
    """esearch.conf tel que Splunk le lit (1.26.7, M6 de la revue de conception).

    Jusqu'en 1.26.6, l'app relisait elle-même default/ et local/ avec
    `configparser`, dont la grammaire n'est pas celle de Splunk (continuations)
    et qui ignore les autres couches que Splunk fusionne : la page Configuration
    et `btool` pouvaient montrer une autre conf que celle exécutée. Désormais une
    seule source, splunkd (`configs/conf-esearch`, namespace de l'app), avec le
    jeton de l'appelant (commandes) ou le jeton système (proxy).

    Ce que splunkd rend, mesuré sur 9.3.14 : des chaînes ; les booléens du
    `[settings]` normalisés en « 1 » / « 0 » (lus par `as_bool`) ; en plus des
    clés de la conf, `disabled` et `eai:*`, écartées ici ; une valeur en
    continuation de ligne jointe par un saut de ligne, que
    `_detecte_continuations` signale comme avant.

    Échec de lecture : RuntimeError qui le nomme, jamais de repli sur les
    fichiers — ce serait revenir à deux lectures possibles."""
    import configparser
    import json
    cp = configparser.RawConfigParser(strict=False, interpolation=None)
    cp.optionxform = str
    try:
        rep = service.get("configs/conf-esearch", owner="nobody", app=APP_NAME,
                          count=0, output_mode="json")
        entrees = json.loads(rep.body.read()).get("entry") or []
    except Exception as e:
        if logger:
            logger.error("esearch.conf illisible par splunkd : %s", e)
        raise RuntimeError(f"configuration esearch illisible par splunkd "
                           f"({e.__class__.__name__}: {court(str(e), 200)})") from None
    for entree in entrees:
        nom = entree.get("name")
        if not nom or nom == "default" or cp.has_section(nom):
            continue
        cp.add_section(nom)
        for cle, valeur in (entree.get("content") or {}).items():
            if cle == "disabled" or cle.startswith("eai:"):
                continue
            if isinstance(valeur, bool):
                valeur = "1" if valeur else "0"
            cp.set(nom, cle, "" if valeur is None else str(valeur))
    _detecte_continuations(cp, logger)
    return cp


def service_appelant(searchinfo):
    """Service splunklib au nom de l'utilisateur de la recherche (son jeton de
    session), ciblé sur le namespace de l'app."""
    from splunklib import client
    u = urlsplit(searchinfo.splunkd_uri)
    return client.Service(scheme=u.scheme, host=u.hostname, port=u.port,
                          token=searchinfo.session_key, owner="nobody", app=APP_NAME)


def _detecte_continuations(cp, logger=None):
    """Repère les valeurs issues d'une CONTINUATION de ligne Splunk.

    Splunk stocke une valeur multi-ligne avec un `\\` en fin de ligne et la
    rend jointe par un saut de ligne. Jusqu'en 1.26.6, l'app lisait le fichier
    avec `configparser`, qui voyait la ligne suivante comme une CLÉ à part
    entière : un profil montré `auth_type = none` pouvait s'exécuter en
    `apikey`. Lue par splunkd (1.26.7), la valeur est la même partout, mais
    aucune clé de la conf n'admet de saut de ligne : on la signale et le profil
    touché est refusé.

    Refuser la saisie côté page de configuration ne suffit pas : un navigateur
    supprime déjà les sauts de ligne dans un `<input type=text>`, si bien que le
    vrai vecteur est ailleurs — écriture REST directe, script d'automatisation,
    édition manuelle du fichier. La détection doit donc être ICI, au chargement,
    quelle que soit la façon dont la valeur est arrivée.
    """
    suspectes = []
    sections = {}
    for section in cp.sections():
        for cle, valeur in cp.items(section):
            # Deux formes : l'antislash en FIN de valeur (ligne suivante non
            # indentée, lue comme une clé distincte), et l'antislash SUIVI d'un
            # saut de ligne au MILIEU (ligne suivante indentée, que configparser
            # fusionne dans la valeur). La seconde échappait à la détection.
            # Lue par splunkd (1.26.7), la continuation arrive JOINTE par un
            # saut de ligne : aucune clé de la conf n'en admet.
            if isinstance(valeur, str) and (valeur.rstrip().endswith("\\")
                                            or "\\\n" in valeur or "\n" in valeur):
                suspectes.append(f"[{section}] {cle}")
                sections.setdefault(section, []).append(cle)
    if not suspectes:
        return
    cp.esearch_continuations = suspectes
    cp.esearch_sections_continuation = sections
    if logger:
        logger.warning(
            "esearch.conf : valeur(s) terminée(s) par '\\' — continuation de "
            "ligne Splunk : %s. Splunk et l'app ne lisent PAS la même chose ; "
            "la ligne suivante est vue comme une clé distincte. Corrigez la "
            "valeur (pas de saut de ligne).", ", ".join(suspectes))


def erreurs_conf(cp):
    """Message d'alerte si une valeur de la conf est sur plusieurs lignes
    (continuation), sinon None. Les fichiers illisibles sont l'affaire de
    splunkd depuis 1.26.7 (`btool check` les signale).

    Volontairement COURT : Splunk tronque les messages de recherche, et un
    message trop long dégrade une erreur lisible en « The search job terminated
    unexpectedly ». Le fichier et la ligne fautive sont dans esearch.log.
    """
    suspectes = getattr(cp, "esearch_continuations", None)
    if suspectes:
        # Ne pas désigner une seule valeur quand il y en a plusieurs : le
        # message nommait la première trouvée, qui n'est pas forcément celle du
        # profil utilisé, et envoyait corriger le mauvais endroit.
        quoi = (suspectes[0] if len(suspectes) == 1
                else "%d valeurs (dont %s)" % (len(suspectes), suspectes[0]))
        return ("esearch.conf : %s sur plusieurs lignes (continuation '\\') — "
                "valeur invalide (détail dans esearch.log)" % quoi)
    return None


def conf_get(cp, section, key, default=None):
    try:
        v = cp.get(section, key)
        return v.strip() if isinstance(v, str) else v
    except Exception:
        return default


# Durée Elasticsearch strictement positive : entier + unité (30s, 2m, 1h…).
_DUREE_ES = re.compile(r"^\s*([0-9]+)\s*(nanos|micros|ms|s|m|h|d)\s*$")


def conf_duree(cp, section, key, default, warn=None):
    """Durée Elasticsearch de configuration (`page_keep_alive`), ou le défaut.

    Même règle que conf_int : une saisie invalide n'est pas transmise telle
    quelle. Sans ce contrôle, `abc` faisait échouer toutes les recherches
    paginées, et `0s` ou `-1m` passaient EN SILENCE alors qu'un contexte qui
    expire aussitôt peut casser une pagination en cours de route.
    """
    raw = conf_get(cp, section, key)
    if raw in (None, ""):
        return default
    m = _DUREE_ES.match(str(raw))
    if not m or int(m.group(1)) == 0:
        if warn:
            warn(f"esearch: [{section}] {key}='{raw}' n'est pas une durée positive "
                 f"(ex. 30s, 2m, 1h) — valeur par défaut {default} utilisée")
        return default
    return f"{int(m.group(1))}{m.group(2)}"


def conf_int(cp, section, key, default, minimum=1, maximum=None, warn=None):
    """Entier de configuration robuste à une saisie humaine.

    La page de configuration expose ces clés en champ libre : une valeur vide,
    non numérique (« 50 000 », « abc ») ou hors bornes ne doit PAS faire échouer
    toutes les recherches avec une exception Python. On journalise/avertit et on
    retombe sur la valeur par défaut.
    """
    raw = conf_get(cp, section, key)
    if raw in (None, ""):
        return int(default)
    try:
        # tolère les séparateurs de milliers usuels (espace fine, insécable, _)
        val = int(str(raw).replace(" ", "").replace(" ", "")
                  .replace(" ", "").replace("_", ""))
    except (TypeError, ValueError):
        if warn:
            warn(f"esearch: [{section}] {key}='{raw}' n'est pas un entier — "
                 f"valeur par défaut {default} utilisée")
        return int(default)
    if val < minimum or (maximum is not None and val > maximum):
        borne = f"{minimum}..{maximum}" if maximum is not None else f"≥ {minimum}"
        if warn:
            warn(f"esearch: [{section}] {key}={val} hors bornes ({borne}) — "
                 f"valeur par défaut {default} utilisée")
        return int(default)
    return val


def as_bool(v, default=False):
    """Booléen de configuration. Une valeur VIDE vaut « non renseigné », donc le
    défaut — et non `False`.

    Sans cela, `verify_certs =` (valeur vide, qu'une écriture REST ou une
    édition manuelle produit facilement) désactivait la vérification TLS alors
    que la documentation annonce `true` par défaut : un réglage de sécurité qui
    tombait du mauvais côté en silence."""
    if v is None or str(v).strip() == "":
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


class Connection:
    """Paramètres résolus d'une connexion Elasticsearch."""

    def __init__(self, es_host, auth=None, headers=None, verify=True,
                 timefield="@timestamp", max_limit=50000, pagination="auto",
                 cert=None, detect_version=False, max_timeout_read=300,
                 index_pattern="*", keep_alive="2m", debug_terms_max=100,
                 esql_max_bytes=65536, esql_max_depth=100, esql_hide_keyword=True,
                 esql_mode="sync", esql_async_wait="10s", esql_async_keep_alive="5m",
                 max_response_mb=256, query_max_bytes=1024 * 1024, query_max_depth=30):
        self.es_host = es_host.rstrip("/")
        self.auth = auth
        self.headers = headers or {}
        self.verify = verify
        self.timefield = timefield
        self.max_limit = max_limit
        self.pagination = pagination
        self.cert = cert          # mTLS : chemin PEM ou (cert, key), sinon None
        self.detect_version = detect_version   # GET / de détection (opt-in)
        self.max_timeout_read = max_timeout_read  # plafond serveur du timeout ES
        self.max_response_mb = max_response_mb    # plafond d'une réponse ES, décompressée
        self.query_max_bytes = query_max_bytes    # bornes de query= (engine.bornes)
        self.query_max_depth = query_max_depth
        # Périmètre listé par | esindices (menu de la page Query). N'est PAS un
        # contrôle d'accès : ES reste seul juge de ce que la clé peut lire.
        self.index_pattern = index_pattern or "*"
        # Durée de vie du contexte de pagination ES (PIT/scroll) entre deux
        # pages. Doit couvrir un aller-retour commande <-> proxy.
        self.keep_alive = keep_alive or "2m"
        # Éléments d'une liste `terms` montrés dans la requête affichée en debug
        # (journal, warning, page Query) ; la suite est résumée « [...] et X de plus ».
        self.debug_terms_max = debug_terms_max
        # ES|QL (1.22.0) : bornes de la requête, et colonnes `X.keyword` masquées
        # quand `X` est rendu ([settings], surchargeable par profil).
        self.esql_max_bytes = esql_max_bytes
        self.esql_max_depth = esql_max_depth
        self.esql_hide_keyword = esql_hide_keyword
        # Mode des requêtes ES|QL du profil (1.24.0) : sync, ou async (8.13+) ;
        # attente par interrogation et conservation du résultat côté ES.
        self.esql_mode = esql_mode
        self.esql_async_wait = esql_async_wait
        self.esql_async_keep_alive = esql_async_keep_alive


# Bornes des requêtes ES|QL ([settings], section « ES|QL » de la page
# Configuration). Plafonds : 1 000 000 de caractères, la limite propre d'ES 9.5 ;
# 400, la profondeur d'expression d'ES (constante de son parseur, mesurée).
# Ces deux plafonds sont ceux d'Elasticsearch, pas d'un cluster de test : inutile de les relever.
ESQL_OCTETS = (65536, 1024, 1000000)
ESQL_PROFONDEUR = (100, 1, 400)


# Requête Lucene (query=), réglable depuis la 1.26.0 : défauts d'engine.py,
# mesurés en 1.17.1 (StackOverflowError vers 3 000 niveaux,
# OutOfMemoryError pour 4 Mo sur un tas de 512 Mo). Contrairement à ES|QL,
# Elasticsearch ne borne lui-même ni l'un ni l'autre : plafonds volontairement
# hauts, un cluster de production pouvant tenir bien plus qu'un tas de 512 Mo. La taille
# reste bornée par `http.max_content_length` d'Elasticsearch (2 Gio au plus).
REQUETE_OCTETS = (1024 * 1024, 1024, 2147483647)
REQUETE_PROFONDEUR = (30, 1, 100000)


def bornes_requete(cp, warn=None):
    """(taille maximale en octets, imbrication maximale) de query= (et de
    l'expression des lookups en mode lucene). Lues sans résoudre de connexion :
    le proxy valide AVANT de lire un secret."""
    d, mini, maxi = REQUETE_OCTETS
    octets = conf_int(cp, "settings", "query_max_bytes", d, minimum=mini, maximum=maxi,
                      warn=warn)
    d, mini, maxi = REQUETE_PROFONDEUR
    profondeur = conf_int(cp, "settings", "query_max_depth", d, minimum=mini, maximum=maxi,
                          warn=warn)
    return octets, profondeur


def bornes_esql(cp, warn=None):
    """(taille maximale en octets, imbrication maximale) des requêtes ES|QL.
    Lues sans résoudre de connexion : le proxy valide AVANT de lire un secret."""
    d, mini, maxi = ESQL_OCTETS
    octets = conf_int(cp, "settings", "esql_max_bytes", d, minimum=mini, maximum=maxi, warn=warn)
    d, mini, maxi = ESQL_PROFONDEUR
    profondeur = conf_int(cp, "settings", "esql_max_depth", d, minimum=mini, maximum=maxi,
                          warn=warn)
    return octets, profondeur


ESQL_LOOKUP_VALEURS = (1000, 1, 65536)


def esql_lookup_max(cp, warn=None):
    """Valeurs (exactes ou à joker) d'un lookup inséré dans une requête ES|QL :
    au-delà, refus explicite. Mesuré : 10 000 valeurs en liste ont arrêté un
    nœud 8.15.5 sous charge ; 1 000 passent sur toutes les versions."""
    d, mini, maxi = ESQL_LOOKUP_VALEURS
    return conf_int(cp, "settings", "esql_lookup_values_max", d, minimum=mini, maximum=maxi,
                    warn=warn)


MODES_ESQL = ("sync", "async")
ESQL_ASYNC_MAX = (1800, 10, 86400)


def esql_mode(cp, profile):
    """Mode ES|QL d'un profil : sync (défaut) ou async. Une valeur illisible
    est refusée : un mode inattendu ne doit pas passer en silence."""
    v = (conf_get(cp, f"profile:{profile}", "esql_mode", "") or "sync").strip().lower()
    if v not in MODES_ESQL:
        raise ValueError(f"[profile:{profile}] esql_mode invalide : {v} (sync ou async)")
    return v


def esql_async_max(cp, warn=None):
    """Durée maximale (s) d'une requête ES|QL asynchrone, interrogations
    comprises : au-delà, la commande l'annule. ES|QL n'a pas de délai côté
    serveur : sans cette borne, une requête asynchrone n'aurait pas de fin."""
    d, mini, maxi = ESQL_ASYNC_MAX
    return conf_int(cp, "settings", "esql_async_max", d, minimum=mini, maximum=maxi, warn=warn)


def esql_masque_keyword(cp, profile=None):
    """Masquer `X.keyword` quand `X` est rendu : le profil s'il le précise, sinon
    [settings], sinon oui (comme Discover de Kibana par défaut)."""
    globale = as_bool(conf_get(cp, "settings", "esql_hide_keyword"), True)
    if profile:
        return as_bool(conf_get(cp, f"profile:{profile}", "esql_hide_keyword"), globale)
    return globale


def profile_auth_type(cp, profile):
    """auth_type d'un profil (none|basic|apikey) SANS lire le secret.
    Retourne None si `profile` est vide (mode ad hoc)."""
    if not profile:
        return None
    section = f"profile:{profile}"
    if not cp.has_section(section):
        return None
    return (conf_get(cp, section, "auth_type", "none") or "none").lower()


def profile_timefield(cp, profile):
    """timefield d'un profil (non secret), défaut @timestamp."""
    if profile and cp.has_section(f"profile:{profile}"):
        return conf_get(cp, f"profile:{profile}", "timefield", "@timestamp")
    return "@timestamp"


# ---------------- accès par rôle (allowed_roles) ----------------
# Un profil se réserve à des rôles Splunk : `*` (tout porteur d'esearch_run),
# `admin` (administrateurs seuls), ou une liste « r1,r2 ». Depuis la 1.16.0, la
# règle vaut pour TOUS les profils, authentifiés ou non : tous passent par le
# proxy, qui la contrôle. Absente ou vide : ouvert, comme avant la 1.15.0 —
# l'interface oblige à trancher, la conf écrite à la main garde l'ancien
# comportement.
# Le rôle `admin` (direct ou hérité) passe toujours : il peut de toute façon
# modifier la conf. Les recherches de propriétaire `nobody` s'exécutent en
# `splunk-system-user`, qui hérite d'admin : elles passent aussi (OPERATIONS §5).
TOUS_LES_ROLES = "*"
ROLE_ADMIN = "admin"
# Administrateurs : `admin` (Splunk Enterprise) et `sc_admin`, qui le remplace sur
# Splunk Cloud (1.25.0, contrôle AppInspect check_kos_are_accessible). Ils passent
# toujours, comme `admin` depuis la 1.15.0.
ROLES_ADMIN = frozenset((ROLE_ADMIN, "sc_admin"))
# Splunk interdit espaces, deux-points, points-virgules et barres obliques dans
# un nom de rôle ; la virgule est notre séparateur, l'étoile un mot réservé.
_ROLE_VALIDE = re.compile(r"^[^\s:;/,*]+$")


def profile_allowed_roles(cp, profile):
    """Règle d'accès d'un profil : None (non configurée), "*", ou frozenset
    de rôles. ValueError si la valeur est illisible : une restriction mal
    écrite ne doit pas se lire comme une absence de restriction."""
    brut = conf_get(cp, f"profile:{profile}", "allowed_roles", "") or ""
    brut = brut.strip()
    if not brut:
        return None
    if brut == TOUS_LES_ROLES:
        return TOUS_LES_ROLES
    roles = [r.strip().lower() for r in brut.split(",") if r.strip()]
    fautifs = [r for r in roles if not _ROLE_VALIDE.match(r)]
    if fautifs or not roles:
        raise ValueError(
            f"[profile:{profile}] allowed_roles illisible : {apercu(brut)} (attendu : "
            "'*', 'admin' ou une liste de rôles séparés par des virgules ; "
            "'*' s'emploie seul)")
    return frozenset(roles)


def roles_effectifs(directs, imports):
    """Rôles directs plus tous ceux qu'ils importent, récursivement.
    `imports` : {rôle: [rôles importés]} (authorization/roles)."""
    vus, pile = set(), [r.lower() for r in directs]
    while pile:
        r = pile.pop()
        if r not in vus:
            vus.add(r)
            pile.extend(i.lower() for i in imports.get(r, ()))
    return vus


def acces_profil(regle, roles):
    """Vrai si un appelant portant `roles` (effectifs) peut utiliser le profil."""
    if regle is None or regle == TOUS_LES_ROLES or ROLES_ADMIN & set(roles):
        return True
    return bool(regle & set(roles))


def refus_profil(profile, disponibles):
    """Message de refus NEUTRE : un profil inexistant et un profil interdit
    reçoivent le même, pour que l'erreur ne révèle ni l'existence d'un profil
    réservé ni les rôles qui y ont droit. Il cite les profils que l'appelant
    PEUT utiliser — l'aide utile. Le motif exact va dans esearch.log."""
    return (f"profil '{court(profile)}' inconnu ou non autorisé — profils disponibles "
            f"pour vous : {', '.join(disponibles) or 'aucun'}")


def profils(cp):
    """Noms de tous les profils déclarés, dans l'ordre du fichier."""
    return [s.split(":", 1)[1] for s in cp.sections() if s.startswith("profile:")]


def profils_ordonnes(cp):
    """Profils dans l'ordre de priorité de `[settings] profile_order`.

    Cet ordre désigne le profil d'une recherche qui n'en précise pas : le
    premier que l'appelant a le droit d'utiliser. Un profil absent de la liste
    vient après ceux qui y figurent, par ordre alphabétique — un profil créé
    n'est donc jamais perdu ; un nom de la liste qui n'existe plus est ignoré."""
    existants = profils(cp)
    brut = conf_get(cp, "settings", "profile_order", "") or ""
    vus = []
    for nom in (n.strip() for n in brut.split(",")):
        if nom in existants and nom not in vus:
            vus.append(nom)
    return vus + sorted(n for n in existants if n not in vus)


def opaque_id(utilisateur):
    """Valeur de l'en-tête X-Opaque-Id : rend chaque requête Elasticsearch
    imputable à l'utilisateur Splunk (tâches en cours, slow logs, journaux de
    dépréciation). Traçabilité seulement : ES n'en tire aucun droit. Le nom
    est encodé : un en-tête HTTP n'admet ni contrôle ni caractère non ASCII."""
    return "splunk/" + quote(utilisateur or "?", safe="@._-")


def resolve_connection(cmd, cp, secret_provider):
    """Construit la Connection depuis les options SPL + esearch.conf.

    `cmd` porte les options (profile, es_host, user, password, apikey,
    timefield, write_warning). `secret_provider(profile, username)` fournit le
    secret storage/passwords (injecté : lecture user côté commande, lecture
    système côté proxy REST).
    Lève ValueError avec un message utilisateur en cas de config invalide.
    """
    settings = "settings"
    warn = getattr(cmd, "write_warning", None)
    alerte = erreurs_conf(cp)
    if alerte and warn:
        warn(alerte)
    max_limit = conf_int(cp, settings, "max_limit", 50000, minimum=1, warn=warn)
    pagination = (conf_get(cp, settings, "pagination", "auto") or "auto").lower()
    detect_version = as_bool(conf_get(cp, settings, "detect_version"), False)
    max_timeout_read = conf_int(cp, settings, "max_timeout_read", 300,
                                minimum=1, warn=warn)
    keep_alive = conf_duree(cp, settings, "page_keep_alive", "2m", warn=warn)
    max_response_mb = conf_int(cp, settings, "max_response_mb", 256, minimum=1,
                               maximum=4096, warn=warn)
    debug_terms_max = conf_int(cp, settings, "debug_terms_max", 100, minimum=1,
                               maximum=100000, warn=warn)
    esql_max_bytes, esql_max_depth = bornes_esql(cp, warn)
    query_max_bytes, query_max_depth = bornes_requete(cp, warn)
    esql_hide_keyword = esql_masque_keyword(cp, cmd.profile)
    esql_async_wait = conf_duree(cp, settings, "esql_async_wait", "10s", warn=warn)
    esql_async_keep_alive = conf_duree(cp, settings, "esql_async_keep_alive", "5m", warn=warn)
    mode_esql = "sync"
    headers = {}
    auth = None
    cert = None

    if cmd.profile:
        # Défense en profondeur : le nom de profil sert à composer le realm
        # storage/passwords et la section conf. On le restreint à un jeu sûr.
        if not re.match(r"^[A-Za-z0-9_.-]+$", cmd.profile) or re.match(r"^\.+$", cmd.profile):
            raise ValueError("Nom de profil invalide (autorisés : A-Z a-z 0-9 _ . -)")
        section = f"profile:{cmd.profile}"
        if not cp.has_section(section):
            known = [s.split(":", 1)[1] for s in cp.sections()
                     if s.startswith("profile:")]
            raise ValueError(
                f"Profil '{cmd.profile}' inconnu dans esearch.conf "
                f"(profils disponibles : {', '.join(known) or 'aucun'})"
                # Sans ce rappel, une conf illisible se présente comme un profil
                # supprimé et l'exploitant cherche au mauvais endroit.
                + (f". ATTENTION : {alerte}" if alerte else ""))
        if cmd.es_host or cmd.user or cmd.password or cmd.apikey:
            raise ValueError("profile= est exclusif de es_host/user/password/apikey")

        touchees = getattr(cp, "esearch_sections_continuation", {}).get(section)
        if touchees:
            # Ne PAS exécuter un profil dont une valeur tient sur plusieurs
            # lignes : aucune clé n'en admet, et jusqu'en 1.26.6 l'app en lisait
            # une autre que Splunk.
            raise ValueError(
                f"[{section}] : {', '.join(touchees)} sur plusieurs lignes "
                "(continuation '\\' en fin de ligne) — valeur invalide. Corrigez "
                "la valeur avant d'utiliser ce profil.")

        es_host = conf_get(cp, section, "es_host")
        if not es_host:
            raise ValueError(f"[{section}] es_host manquant")
        verify_certs = as_bool(conf_get(cp, section, "verify_certs"), True)
        ca_file = chemin_splunk(conf_get(cp, section, "ca_file"))
        # Validé comme client_cert/client_key : sans ce contrôle, `requests`
        # lève une OSError non interceptée et l'utilisateur ne voit qu'un
        # « erreur interne » opaque au lieu du chemin fautif.
        if ca_file and verify_certs and not os.path.isfile(ca_file):
            raise ValueError(f"[{section}] ca_file introuvable : {ca_file}")
        verify = ca_file if (verify_certs and ca_file) else verify_certs
        timefield = cmd.timefield or conf_get(cp, section, "timefield", "@timestamp")
        max_limit = conf_int(cp, section, "max_limit", max_limit, minimum=1, warn=warn)
        pagination = (conf_get(cp, section, "pagination", pagination) or pagination).lower()
        index_pattern = conf_get(cp, section, "index_pattern", "*") or "*"

        auth_type = (conf_get(cp, section, "auth_type", "none") or "none").lower()
        if auth_type == "basic":
            username = conf_get(cp, section, "username")
            if not username:
                raise ValueError(f"[{section}] username requis pour auth_type=basic")
            headers["Authorization"] = entete_basic(
                valide_identifiant(username, "username"),
                valide_identifiant(secret_provider(cmd.profile, username), "secret"))
        elif auth_type == "apikey":
            cle = valide_identifiant(secret_provider(cmd.profile, "apikey"), "clé API")
            headers["Authorization"] = f"ApiKey {cle}"
        elif auth_type != "none":
            raise ValueError(f"[{section}] auth_type invalide : {auth_type}")

        mode_esql = esql_mode(cp, cmd.profile)
        cert = _client_cert(cp, section)
        verifie_materiel_tls(section, ca_file if (verify_certs and ca_file) else None, cert)

    else:  # ----- mode ad hoc -----
        if not cmd.es_host:
            raise ValueError("Précisez profile=<nom> (recommandé) ou es_host=<url>")
        if not as_bool(conf_get(cp, settings, "allow_adhoc_host", "false"), False):
            raise ValueError(
                "es_host ad hoc désactivé ([settings] allow_adhoc_host=false). "
                "Utilisez profile=<nom>")
        # Splunk écrit le texte COMPLET de la recherche (audit.log, index _audit,
        # historique, inspecteur) avant même que la commande démarre : la valeur
        # y est déjà, et l'app ne peut pas l'empêcher (mesuré, 1.16.2). La
        # fonction reste ; l'avertissement le dit (1.26.0, décision utilisateur).
        if cmd.user or cmd.password or cmd.apikey or urlsplit(cmd.es_host).password:
            cmd.write_warning(
                "esearch: identifiants dans la recherche (user=, password=, apikey= ou "
                "compte:mot_de_passe@ dans es_host) : Splunk les a déjà écrits en clair "
                "dans audit.log (index _audit), l'historique et l'inspecteur de la "
                "recherche — l'app ne peut pas l'empêcher. Préférez profile= (secret "
                "chiffré dans storage/passwords) ; à défaut, restreignez la lecture de "
                "_audit et _internal.")
        if cmd.apikey:
            headers["Authorization"] = f"ApiKey {valide_identifiant(cmd.apikey, 'clé API')}"
        elif cmd.user and cmd.password:
            headers["Authorization"] = entete_basic(
                valide_identifiant(cmd.user, "user"),
                valide_identifiant(cmd.password, "password"))
        es_host = cmd.es_host
        verify = as_bool(conf_get(cp, settings, "verify_certs", "true"), True)
        timefield = cmd.timefield or "@timestamp"
        index_pattern = "*"

    if pagination not in VALID_PAGINATIONS:
        raise ValueError(f"pagination invalide : {pagination} "
                         f"(valeurs : {', '.join(VALID_PAGINATIONS)})")
    # Identifiants sur un transport en clair (1.26.4, E2 de la revue) : on
    # avertit sans refuser — un cluster de test en http reste utilisable.
    if headers.get("Authorization") and warn \
            and urlsplit(es_host.strip()).scheme.lower() == "http":
        warn("esearch: identifiants envoyés en clair (es_host en http://) : "
             "quiconque observe le réseau peut les lire. Passez Elasticsearch "
             "en https://.")
    return Connection(es_host, auth=auth, headers=headers, verify=verify,
                      timefield=timefield, max_limit=max_limit,
                      pagination=pagination, cert=cert,
                      detect_version=detect_version,
                      max_timeout_read=max_timeout_read, max_response_mb=max_response_mb,
                      query_max_bytes=query_max_bytes, query_max_depth=query_max_depth,
                      index_pattern=index_pattern, keep_alive=keep_alive,
                      debug_terms_max=debug_terms_max, esql_max_bytes=esql_max_bytes,
                      esql_max_depth=esql_max_depth, esql_hide_keyword=esql_hide_keyword,
                      esql_mode=mode_esql, esql_async_wait=esql_async_wait,
                      esql_async_keep_alive=esql_async_keep_alive)


def chemin_splunk(valeur):
    """Chemin de certificat, avec la convention des fichiers .conf de Splunk.

    `$SPLUNK_HOME` (ou `${SPLUNK_HOME}`) est remplacé, et un chemin RELATIF est
    pris sous $SPLUNK_HOME (`etc/auth/esearch/ca.pem`). Les certificats se
    rangent ainsi sous `$SPLUNK_HOME/etc/auth/esearch/`, comme ceux de Splunk,
    sans écrire dans esearch.conf un chemin propre à une machine."""
    if not valeur:
        return valeur
    home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    valeur = valeur.replace("${SPLUNK_HOME}", home).replace("$SPLUNK_HOME", home)
    return valeur if os.path.isabs(valeur) else os.path.join(home, valeur)


_PEM_CHIFFRE = re.compile(r"Proc-Type: *4, *ENCRYPTED|BEGIN ENCRYPTED PRIVATE KEY")


def verifie_materiel_tls(section, ca_file, cert):
    """Charge localement la CA et le couple certificat/clé client d'un profil.

    Sans ce contrôle, ces erreurs de CONFIGURATION n'apparaissaient qu'à la
    connexion, après trois tentatives réseau, sous la forme d'un « SSLError »
    sans cause côté proxy — et même le journal ne disait que « unknown error »
    pour une CA au format DER. On les nomme ici, avant tout appel réseau.

    Une clé chiffrée n'est JAMAIS soumise à OpenSSL sans fonction de phrase de
    passe : son invite par défaut pourrait chercher un terminal. Le rappel rend
    une phrase vide, donc un échec immédiat."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca_file:
        try:
            ctx.load_verify_locations(cafile=ca_file)
        except (ssl.SSLError, OSError, ValueError):
            raise ValueError(
                f"[{section}] ca_file illisible : {ca_file} — certificat(s) PEM "
                "attendu(s) (un fichier DER se convertit avec « openssl x509 "
                "-inform DER -in <fichier> -out <fichier>.pem »)")
    if not cert:
        return
    certfile, keyfile = cert if isinstance(cert, tuple) else (cert, None)
    try:
        with open(keyfile or certfile, encoding="ascii", errors="replace") as f:
            chiffree = bool(_PEM_CHIFFRE.search(f.read()))
    except OSError:
        chiffree = False
    if chiffree:
        raise ValueError(
            f"[{section}] clé client chiffrée par une phrase de passe : non "
            "supporté — la déchiffrer à l'installation (OPERATIONS.md, mTLS)")
    try:
        ctx.load_cert_chain(certfile, keyfile, password=lambda: b"")
    except ssl.SSLError as e:
        if "KEY_VALUES_MISMATCH" in str(e) or "key values mismatch" in str(e):
            raise ValueError(f"[{section}] client_key ne correspond pas à client_cert")
        raise ValueError(
            f"[{section}] certificat ou clé client illisible — PEM non chiffré attendu")
    except OSError:
        raise ValueError(f"[{section}] certificat ou clé client illisible (droits ?)")


def _client_cert(cp, section):
    """mTLS : (client_cert, client_key) validés, ou client_cert seul, sinon None.

    La clé PEM doit être NON chiffrée (requests ne gère pas la passphrase).
    Pour une clé protégée par passphrase : voir OPERATIONS.md (déchiffrer à
    l'install via `openssl rsa`, permissions 600)."""
    import os
    client_cert = chemin_splunk(conf_get(cp, section, "client_cert"))
    client_key = chemin_splunk(conf_get(cp, section, "client_key"))
    if not client_cert and not client_key:
        return None
    if not client_cert:
        raise ValueError(f"[{section}] client_key sans client_cert")
    for label, path in (("client_cert", client_cert), ("client_key", client_key)):
        if path and not os.path.isfile(path):
            raise ValueError(f"[{section}] {label} introuvable : {path}")
    return (client_cert, client_key) if client_key else client_cert
