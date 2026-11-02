#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Handler REST privilégié pour esearch (endpoint /esearch_proxy).

Seul chemin vers un profil, depuis la 1.16.0 : | esearch, | esindices et
| esprofiles y passent pour TOUS les profils, authentifiés ou non, depuis
n'importe quelle app dont Splunk ES. Il contrôle d'abord le droit de
l'appelant sur le profil (allowed_roles), puis exécute la requête sans jamais
exposer le secret :

  - déclaré `passSystemAuth = true` dans restmap.conf → reçoit le jeton
    SYSTÈME, avec lequel il lit le secret dans storage/passwords (les users
    non-admin n'ont pas ce droit) ;
  - la requête Elasticsearch est faite ICI (côté serveur) ; on ne renvoie que
    les documents (`hits`), JAMAIS le secret ;
  - protégé par la capability `esearch_run` (`capability` dans restmap.conf,
    toutes méthodes ; le handler n'accepte de plus que POST).

Le secret ne quitte donc jamais le contexte système du search head.
"""
import hashlib
import json
import logging
import os
import re
import sys
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

import requests
import sa_esearch  # noqa: F401  (effet de bord : shim de compat avant le SDK)
from sa_esearch import APP_NAME, asynchrone, engine, esql, filtres
from sa_esearch import config as cfg
from sa_esearch.diagnostic import message_injoignable
from sa_esearch.log import (
    JournalRecherche,
    apercu,
    get_logger,
    marqueur_debug,
    portee_debug,
    valide_etiquette,
    valide_sid,
)
from splunk.persistconn.application import PersistentServerConnectionApplication
from splunklib import client

logger = get_logger()

# Rôles lus pour le contrôle allowed_roles, gardés le temps de servir les pages
# d'une même recherche sans relire splunkd à chaque page. Conséquence : un
# retrait de rôle prend effet en CACHE_ROLES_S au plus (OPERATIONS §5).
CACHE_ROLES_S = 60
_cache_roles = {}


def _en_cache(cle, calcul):
    maintenant = time.monotonic()
    vu = _cache_roles.get(cle)
    if vu and vu[0] > maintenant:
        return vu[1]
    valeur = calcul()
    # Une entrée par session : sans purge, le processus persistant garderait
    # celles de chaque recherche planifiée passée.
    for k in [k for k, (fin, _) in _cache_roles.items() if fin <= maintenant]:
        del _cache_roles[k]
    _cache_roles[cle] = (maintenant + CACHE_ROLES_S, valeur)
    return valeur


def _lit_json(service, chemin, **query):
    return json.loads(service.get(chemin, output_mode="json", **query).body.read())


class ESearchProxy(PersistentServerConnectionApplication):

    def __init__(self, command_line=None, command_arg=None):
        super().__init__()
        # Alerte sur l'état de la conf, posée au chargement. Elle doit accompagner
        # AUSSI les réponses d'erreur : les avertissements collectés pendant la
        # requête sont perdus dès qu'une exception survient, or c'est justement le
        # cas où l'utilisateur a besoin de savoir que la conf lue n'est pas celle
        # qu'il croit (« Secret introuvable » alors que le profil s'affiche
        # `auth_type = none` dans l'interface).
        self._alerte_conf = None
        self._appelant = "?"
        self._log = logger

    def _avec_alerte(self, message):
        return f"{message}. ATTENTION : {self._alerte_conf}" if self._alerte_conf else message

    def handle(self, in_bytes):
        self._alerte_conf = None
        self._log = logger
        self._echo, self._requete = [], []
        try:
            return self._handle(in_bytes)
        except (ValueError, RuntimeError) as e:
            self._log.error("proxy: %s", e)
            return self._json({"error": self._avec_alerte(str(e))}, status=400)
        except requests.exceptions.RequestException as e:
            # Panne opérationnelle (ES éteint, DNS, TLS, timeout) et non défaut
            # du code : la remonter en 502 avec la cause, au lieu d'un « erreur
            # interne » 500 qui envoyait chercher un bug dans l'app. Sans
            # préfixe « esearch: » : la commande le pose sur toute erreur du
            # proxy, ce qui donnait « esearch: esearch: … » à l'écran.
            self._log.error("proxy: Elasticsearch injoignable (%s: %s)",
                            e.__class__.__name__, e)
            # Cause TLS connue -> phrase fixe ; jamais le texte brut de
            # l'exception (il resterait dans le journal, pas à l'écran).
            return self._json({"error": message_injoignable(e)}, status=502)
        except Exception as e:
            self._log.error("proxy: erreur interne %s", e.__class__.__name__)
            return self._json({"error": f"proxy: erreur interne ({e.__class__.__name__})"},
                              status=500)

    # ------------------------------------------------------------------
    def _handle(self, in_bytes):
        args = json.loads(in_bytes) if isinstance(in_bytes, (str, bytes, bytearray)) else in_bytes

        # Défense en profondeur : la capability est posée par restmap.conf, mais
        # une erreur de déclaration y est invisible — `capability.post` laissait
        # passer PUT, GET et DELETE sans aucun contrôle. Le handler n'accepte
        # donc que POST, la seule méthode qu'il ait jamais eu à servir.
        methode = (args.get("method") or "").upper()
        if methode and methode != "POST":
            return self._json({"error": f"méthode {methode} refusée : "
                                        "cet endpoint ne répond qu'en POST"}, 405)

        system_key = args.get("system_authtoken")
        if not system_key:
            return self._json({"error": "jeton système absent (passSystemAuth requis)"}, 500)
        # Qui appelle : une requête exécutée avec le secret de service doit
        # être imputable. Jamais de secret ici, seulement l'identifiant Splunk.
        self._appelant = ((args.get("session") or {}).get("user")) or "?"
        raw = args.get("payload") or ""
        if not raw and args.get("form"):
            # corps form-encodé : reconstituer un dict {k:v}
            raw = json.dumps({k: v for k, v in args["form"]})
        params = json.loads(raw) if raw else {}

        # Service splunklib SYSTÈME, ciblé sur le namespace de l'app TA : lit
        # la conf (1.26.7, M6 : par splunkd, plus par les fichiers) et le
        # secret storage/passwords avec les privilèges système. Le handler
        # tourne sur le search head -> management sur la loopback.
        mgmt = os.environ.get("SPLUNKD_URI", "https://127.0.0.1:8089")
        u = urlsplit(mgmt)
        sysvc = client.Service(scheme=u.scheme, host=u.hostname or "127.0.0.1",
                               port=u.port or 8089, token=system_key,
                               owner="nobody", app=APP_NAME, sharing="app")
        cp = cfg.load_conf(logger, sysvc)
        # Lignes marquées d'une requête en mode debug, renvoyées à la commande
        # (search.log du job) ; la requête envoyée à Elasticsearch, idem.
        self._echo, self._requete = [], []
        self._log = self._journal(params, cp, self._echo.append)
        # `[settings] log_level` doit valoir ICI aussi : la requête s'exécute
        # dans ce processus, et OPERATIONS.md §dépannage demande DEBUG pour la
        # diagnostiquer. Sans cela le réglage n'avait aucun effet là où il sert.
        niveau = (cfg.conf_get(cp, "settings", "log_level", "INFO") or "INFO").upper()
        logger.setLevel(getattr(logging, niveau, logging.INFO))
        self._alerte_conf = cfg.erreurs_conf(cp)
        action = params.get("action") or "page"
        actions = ("page", "esql", "esql_suite", "esql_annule", "indices", "profiles")
        if action not in actions:
            return self._json({"error": f"action inconnue : {action} "
                                        f"(valeurs : {', '.join(actions)})"}, 400)
        profile = params.get("profile")
        if not profile and action != "profiles":
            return self._json({"error": "profile requis"}, 400)


        # Rôles de l'appelant, lus une seule fois par requête, et seulement si
        # un profil restreint est en jeu.
        lus = []

        def roles():
            if not lus:
                lus.append(self._roles_appelant(args, sysvc, u))
            return lus[0]

        # action=profiles : les profils que l'appelant peut utiliser, dans
        # l'ordre de priorité — le premier est son profil par défaut. Alimente
        # le menu de la page Query (| esprofiles) et les recherches sans profile=.
        if action == "profiles":
            dispo = self._disponibles(cp, roles)
            self._log.info("proxy: user=%s %d profil(s) disponible(s) : %s",
                           self._appelant, len(dispo), ",".join(dispo))
            return self._json(dict({"profiles": dispo, "warnings": (
                [self._alerte_conf] if self._alerte_conf else [])}, **self._trace()))

        # Droit d'utiliser le profil : contrôlé ICI, avant toute lecture de
        # secret. Depuis la 1.16.0, TOUS les profils passent par le proxy, qui
        # est donc le seul chemin vers un profil — la commande tourne avec les
        # droits de l'utilisateur, un contrôle chez elle se contournerait en
        # appelant cet endpoint directement. Profil inexistant et profil
        # interdit reçoivent la même réponse ; le motif reste au journal.
        motif = self._refus(cp, profile, roles)
        if motif:
            self._log.warning("proxy: REFUS user=%s profil=%s %s",
                              self._appelant, profile, motif)
            return self._json({"error": self._avec_alerte(cfg.refus_profil(
                profile, self._disponibles(cp, roles)))}, 403)

        # Valider AVANT toute lecture de secret : une requête malformée ne doit
        # pas coûter un parcours de storage/passwords en contexte système.
        ident = None
        if action in ("esql_suite", "esql_annule"):
            # Requête asynchrone (1.24.0) : l'id d'Elasticsearch n'arrive que dans
            # le jeton signé remis à CET utilisateur pour CE profil (asynchrone.py).
            ident = asynchrone.verifie(self._exige(params, "jeton"), profile, self._appelant)
        if action in ("esql", "esql_suite"):
            engine.ordre_tri(params)
        if action == "esql":
            # Mêmes garanties pour ES|QL (1.22.0) : bornes propres à ES|QL
            # (carte « Protections du cluster et du search head »), apostrophes refusées, et
            # l'expression des lookups bornée comme une requête Lucene.
            esql.valide(self._exige(params, "esql"), *cfg.bornes_esql(cp))
            if params.get("esql_filtre"):
                engine.valide_requete(params["esql_filtre"], *cfg.bornes_requete(cp))
            engine.ordre_tri(params)
        if action in ("page", "esql", "esql_suite"):
            # Bornes de la requête (taille, imbrication) : elles protègent le
            # cluster d'une requête qui le ferait tomber (engine.valide_requete).
            if action == "page":
                engine.valide_requete(self._exige(params, "query"), *cfg.bornes_requete(cp))
            filtres.valide_filtres(params.get("filtres"))
            limit = self._exige(params, "limit")
            try:
                if int(limit) < 1:
                    raise ValueError
            except (TypeError, ValueError):
                return self._json({"error": f"limit invalide : {apercu(limit)} "
                                            "(entier >= 1 attendu)"}, 400)

        # Le secret du profil se lit par le NOM de son entrée (1.26.4, F1 de la
        # revue) : splunkd la nomme « <realm>:<user>: » en échappant les
        # deux-points internes (esearch\:prod:apikey:). Jusqu'en 1.26.3, le proxy
        # parcourait tous les secrets de l'app pour en garder un.
        def secret_provider(prof, username):
            realm = f"esearch:{prof}"
            nom = "{}:{}:".format(*(x.replace(":", "\\:") for x in (realm, username)))
            try:
                return sysvc.storage_passwords[nom].clear_password
            except KeyError:
                raise RuntimeError(f"Secret introuvable (realm='{realm}', "
                                   f"username='{username}')") from None

        warnings = []
        opts = SimpleNamespace(
            profile=profile, es_host=None, user=None, password=None, apikey=None,
            # `timefield` vient de la SPL : resolve_connection retombe sur celui
            # du profil s'il est vide, exactement comme sur le chemin direct.
            timefield=params.get("timefield") or None, write_warning=warnings.append)
        conn = cfg.resolve_connection(opts, cp, secret_provider)
        conn.headers["X-Opaque-Id"] = cfg.opaque_id(self._appelant)

        # Options de transport transmises par la commande (I1), avec plafond
        # serveur sur le timeout de lecture (anti-abus, [settings] max_timeout_read).
        tr = self._transport(params, conn.max_timeout_read)

        # action=indices : listing des cibles interrogeables (menu de la page
        # Query). Même profil, même connexion, mêmes plafonds ; ne renvoie que
        # des noms. Les options propres à la recherche ne s'appliquent pas.
        if action == "indices":
            names = engine.list_indices(
                conn, pattern=params.get("pattern") or None,
                timeouts=tr["timeouts"], retry=tr["retry"], backoff=tr["backoff"],
                logger=self._log, warn=warnings.append)
            self._log.info("proxy: user=%s %d cible(s) listée(s) pour le profil %s",
                           self._appelant, len(names), profile)
            return self._json(dict({"indices": names, "warnings": warnings}, **self._trace()))
        if action == "esql_annule":
            esql.annule(conn, ident, timeouts=tr["timeouts"], logger=self._log)
            self._log.info("proxy: user=%s profil=%s ES|QL asynchrone annulée", self._appelant,
                           profile)
            return self._json(dict({"annule": True, "warnings": warnings}, **self._trace()))
        if action in ("esql", "esql_suite"):
            self._log.info("proxy: user=%s profil=%s ES|QL %s limit=%s timeout_read=%s",
                           self._appelant, profile, conn.esql_mode if action == "esql"
                           else "suite", params.get("limit"), tr["timeouts"][1])
            if action == "esql":
                r = esql.execute(conn, params, logger=self._log, warn=warnings.append,
                                 trace=self._requete.append, **tr)
            else:
                r = esql.suite(conn, ident, params, logger=self._log, warn=warnings.append, **tr)
            if r.get("en_cours"):
                jeton = asynchrone.signe(r["id"], profile, self._appelant,
                                         conn.esql_async_keep_alive)
                return self._json(dict({"en_cours": True, "jeton": jeton, "warnings": warnings},
                                       **self._trace()))
            return self._json(dict({"rows": r["rows"], "coupe": r["coupe"],
                                    "colonnes": r["colonnes"], "warnings": warnings},
                                   **self._trace()))
        self._log.info("proxy: user=%s profil=%s index=%s limit=%s timeout_read=%s",
                       self._appelant, profile, params.get("index"), params.get("limit"),
                       tr["timeouts"][1])

        # action=page : UNE page + le curseur de la suivante. Le proxy ne garde
        # rien entre deux appels — c'est la commande qui porte le curseur — donc
        # sa mémoire ne dépend plus du volume total demandé.
        cursor = self._cursor(params.get("cursor"))
        r = engine.fetch_page(conn, params, cursor, logger=self._log,
                              warn=warnings.append, keep_alive=conn.keep_alive,
                              trace=self._requete.append, **tr)
        hits = [h.get("_source", {}) for h in r["hits"]]
        self._log.info("proxy: page de %d hits, suite=%s (%d avertissement(s))",
                       len(hits), "oui" if r["cursor"] else "non", len(warnings))

        reponse = {"hits": hits, "cursor": r["cursor"], "total": r["total"], "warnings": warnings}
        # es_metadata=true (1.25.0) : `_index` et `_id`, liste parallèle aux hits.
        if cfg.as_bool(params.get("metadata"), False):
            reponse["meta"] = [[h.get("_index"), h.get("_id")] for h in r["hits"]]
        # `_time` décodé par Elasticsearch (1.26.4), liste parallèle aux hits ;
        # absente quand rien n'a été décodé.
        temps = engine.temps_es(r["hits"], conn.timefield)
        if any(t is not None for t in temps):
            reponse["temps"] = temps
        return self._json(dict(reponse, **self._trace()))

    # ------------------------------------------------------------------
    @staticmethod
    def _refus(cp, profile, roles):
        """Motif de refus du profil pour l'appelant (pour le journal), ou None.
        `roles` : fonction rendant ses rôles effectifs, appelée seulement si le
        profil est restreint. Une règle illisible lève ValueError : profil
        fermé, avec un message qui le dit à l'administrateur."""
        if not re.match(r"^[A-Za-z0-9_.-]+$", profile) or re.match(r"^\.+$", profile):
            return "motif=nom invalide"
        if not cp.has_section(f"profile:{profile}"):
            return "motif=inconnu"
        regle = cfg.profile_allowed_roles(cp, profile)
        if regle in (None, cfg.TOUS_LES_ROLES):
            return None
        r = roles()
        if cfg.acces_profil(regle, r):
            return None
        return f"allowed_roles={','.join(sorted(regle))} rôles={','.join(sorted(r))}"

    def _disponibles(self, cp, roles):
        """Profils utilisables par l'appelant, dans l'ordre de priorité."""
        dispo = []
        for nom in cfg.profils_ordonnes(cp):
            try:
                if self._refus(cp, nom, roles) is None:
                    dispo.append(nom)
            except ValueError as e:          # règle illisible : profil fermé
                self._log.warning("proxy: %s", e)
        return dispo

    def _roles_appelant(self, args, sysvc, u):
        """Rôles effectifs de l'appelant : directs, plus tous ceux qu'ils
        importent. Les directs sont lus avec le jeton de SA session
        (current-context) et non par son nom : c'est la session qui fait foi,
        quelle que soit la source du compte. La carte des imports est lue en
        système, une fois pour tous les appelants (cache) : un utilisateur
        ordinaire n'y voit que ses propres rôles (vérifié)."""
        jeton = (args.get("session") or {}).get("authtoken")
        if not jeton:
            # Sans jeton, pas d'identité vérifiable : refuser plutôt que deviner.
            raise RuntimeError("session de l'appelant absente : impossible de "
                               "vérifier les rôles (passSession requis)")

        def directs():
            svc = client.Service(scheme=u.scheme, host=u.hostname or "127.0.0.1",
                                 port=u.port or 8089, token=jeton)
            entree = _lit_json(svc, "authentication/current-context")["entry"][0]
            return list(entree["content"].get("roles") or [])

        def imports():
            return {e["name"].lower(): list(e["content"].get("imported_roles") or [])
                    for e in _lit_json(sysvc, "authorization/roles", count=0)["entry"]}

        # Cache indexé par SESSION (empreinte du jeton), pas par nom : une
        # nouvelle connexion n'hérite pas des rôles d'une session plus ancienne
        # du même compte. Avant, une session ouverte avant un retrait de groupe
        # (SAML : rôles figés à la connexion) remplissait l'entrée du compte, et
        # la session suivante, aux bons rôles, en héritait 60 s (constaté).
        # Les pages d'une même recherche partagent un jeton : elles profitent
        # toujours du cache.
        empreinte = hashlib.sha256(jeton.encode()).hexdigest()
        return cfg.roles_effectifs(_en_cache(("session", empreinte), directs),
                                   _en_cache(("imports",), imports))

    @staticmethod
    def _journal(params, cp, echo):
        """Journal de la requête : marqué et complet si la recherche est en mode
        debug (`| esearch debug=true`). Le marqueur et l'étiquette viennent du
        processus de recherche de l'utilisateur : revalidés ici, comme le reste."""
        debug = cfg.as_bool(params.get("debug"), False)
        etiquette = params.get("debug_tag") or None
        if etiquette is not None and not debug:
            raise ValueError("debug_tag ne s'emploie qu'avec debug")
        if not debug:
            return logger
        sid = valide_sid(params["sid"]) if params.get("sid") else None
        if etiquette is not None:
            valide_etiquette(etiquette)
        portee = portee_debug(cfg.conf_get(cp, "settings", "debug_search_scope", "query"))
        return JournalRecherche(logger, marqueur_debug(sid, etiquette),
                                tout=(portee == "all"), echo=echo)

    def _trace(self):
        """Ce qu'une recherche en mode debug reçoit en plus de la réponse : ses
        lignes marquées et la requête envoyée. Rien hors mode debug."""
        if not isinstance(self._log, JournalRecherche):
            return {}
        trace = {"journal": list(self._echo)}
        if self._requete:
            trace["requete"] = self._requete[0]
        return trace

    @staticmethod
    def _exige(params, cle):
        """Paramètre obligatoire, ou ValueError (donc 400 et pas 500)."""
        v = params.get(cle)
        if v is None or v == "":
            raise ValueError(f"{cle} requis")
        return v

    @staticmethod
    def _cursor(brut):
        """Curseur de pagination reçu de la commande.

        Il transite par le processus de recherche de l'utilisateur : on le
        traite donc comme une donnée NON FIABLE. On n'en déduit aucun droit —
        l'hôte, le secret et les plafonds viennent toujours de la conf du
        profil, et Elasticsearch reste seul juge de ce que la clé peut lire.
        On se contente de vérifier la forme attendue.
        """
        if not brut:
            return None
        try:
            c = json.loads(brut) if isinstance(brut, str) else brut
        except (TypeError, ValueError):
            raise ValueError("curseur de pagination illisible")
        if not isinstance(c, dict) or not (c.get("pit") or c.get("scroll")):
            raise ValueError("curseur de pagination invalide")
        garde = {k: c[k] for k in ("pit", "scroll", "after", "n", "dv", "s") if k in c}
        if not isinstance(garde.get("n", 0), int) or garde.get("n", 0) < 0:
            raise ValueError("curseur de pagination invalide (compteur)")
        # `dv` : date demandée à Elasticsearch (1.26.4). Il ne change que la
        # forme de la requête de l'appelant, jamais ses droits ; tout autre
        # chose que true vaut false.
        if "dv" in garde:
            garde["dv"] = garde["dv"] is True
        # `s` : index où la période s'applique aussi en secondes (1.27.0). Même
        # nature que `dv` : la forme de la requête, jamais un droit (une valeur
        # de terms sur _index ne donne accès à rien). Forme seule vérifiée.
        if "s" in garde and not (isinstance(garde["s"], list) and garde["s"] and all(
                isinstance(i, str) and 0 < len(i) <= 255 for i in garde["s"])):
            raise ValueError("curseur de pagination invalide (index en secondes)")
        # Un curseur PIT sans `after` levait un KeyError plus bas, rendu en 500
        # « erreur interne » — alors que c'est une donnée reçue, donc un 400.
        if garde.get("pit") and not isinstance(garde.get("after"), list):
            raise ValueError("curseur de pagination invalide "
                             "(pit sans position `after`)")
        return garde

    # Plafonds SERVEUR des options de transport. Les validators de la commande
    # ne sont pas un contrôle : cet endpoint est appelable directement par tout
    # porteur d'esearch_run (rôle `user` par défaut).
    MAX_RETRY = 5
    MAX_BACKOFF = 1.0
    MAX_CONNECT = 30
    # La commande attend le proxy max(timeout_read, max_timeout_read) + 60 s
    # (esearch._call_proxy) : l'appel doit tenir dans le budget plus cette marge,
    # moins 10 s de sécurité.
    MARGE = 50

    @classmethod
    def _transport(cls, params, max_timeout_read):
        def _borne(k, default, mini, maxi):
            try:
                v = int(params.get(k, default))
            except (TypeError, ValueError, OverflowError):
                # OverflowError : `json.loads` accepte `Infinity`, et
                # `int(float("inf"))` lève OverflowError — ce qui sortait en 500
                # « erreur interne » pour une simple entrée invalide.
                return default
            return max(mini, min(v, maxi))

        budget = max(1, int(max_timeout_read))
        read_to = _borne("timeout_read", 30, 1, budget)
        connect = _borne("timeout_connect", 5, 1, cls.MAX_CONNECT)
        retry = _borne("retry_count", 3, 0, cls.MAX_RETRY)
        try:
            backoff = float(params.get("backoff_base", 0.5))
        except (TypeError, ValueError, OverflowError):
            backoff = 0.5
        backoff = max(0.0, min(backoff, cls.MAX_BACKOFF))

        # BUDGET TOTAL de l'appel. Jusqu'en 1.25.1, urllib3 rejouait aussi une
        # recherche dont la lecture avait expiré : un appel durait jusqu'à
        # (tentatives + 1) × (connect + read), et le nombre de tentatives était
        # borné en conséquence. Depuis la 1.26.0, seuls la connexion impossible
        # et les 429/503 sont rejoués (client.py, read=0) : le pire cas est UNE
        # lecture, plus une connexion par tentative, plus les attentes d'urllib3
        # entre tentatives (aucune avant la première reprise, puis
        # backoff × 2^(k-1)). L'ancienne formule supprimait toute reprise dès
        # que timeout_read dépassait la moitié du budget (vu en revue, 1.26.4).
        def pire_cas(n):
            return read_to + (n + 1) * connect + backoff * (2 ** n - 2 if n > 1 else 0)

        while retry > 0 and pire_cas(retry) > budget + cls.MARGE:
            retry -= 1

        return {
            "timeouts": (connect, read_to),
            "retry": retry,
            "backoff": backoff,
        }

    @staticmethod
    def _json(obj, status=200):
        return {"payload": json.dumps(obj), "status": status,
                "headers": [("Content-Type", "application/json")]}

    def handleStream(self, handle, in_bytes):
        raise NotImplementedError()

    def done(self):
        pass
