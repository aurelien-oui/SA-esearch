#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Commande de recherche générante `| esearch` : interroge Elasticsearch et
retourne les documents comme événements Splunk, sans indexation.

Deux modes de connexion :
  - profil (recommandé, prod)  : | esearch profile=prod query="..."
    -> via le proxy REST : droit de l'appelant contrôlé (allowed_roles), hôte,
       TLS et auth depuis esearch.conf + storage/passwords. Sans profile= :
       le premier profil autorisé dans l'ordre fixé par l'administrateur.
  - ad hoc (environnement de test) : | esearch es_host="http://..." query="..."
    -> désactivable via [settings] allow_adhoc_host = false

Protocole SCPv2 (chunked). Logique applicative dans bin/sa_esearch/.
"""

import json
import logging
import math
import os
import sys
import time
import traceback
from urllib.parse import urlsplit

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Libs vendorisées (requests, certifi, ...) prioritaires sur celles de Splunk
_LIB = os.path.join(APP_ROOT, "bin", "lib")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

import requests
import sa_esearch  # noqa: F401  (effet de bord : shim de compat avant le SDK)
from sa_esearch import config as cfg
from sa_esearch import engine, esql, esql_lookups, filtres, temps
from sa_esearch.arguments import ArgumentsSignales
from sa_esearch.diagnostic import message_injoignable, tronque
from sa_esearch.log import (
    JournalRecherche,
    court,
    get_logger,
    marqueur_debug,
    portee_debug,
    valide_etiquette,
)
from sa_esearch.proxy import appel_proxy
from sa_esearch.transform import build_event
from splunklib import client, results
from splunklib.searchcommands import (
    Configuration,
    GeneratingCommand,
    Option,
    dispatch,
    validators,
)

logger = get_logger()


@Configuration()
class ESearchCommand(ArgumentsSignales, GeneratingCommand):

    # Interlocuteur HTTP effectif : sert à nommer le bon composant en cas de
    # panne réseau (Elasticsearch en mode ad hoc, ou splunkd pour un profil).
    _via_proxy = False
    # Journal de CETTE recherche : le logger partagé, ou, avec debug=true, un
    # journal qui marque et écrit toutes ses lignes (voir _journal).
    _log = logger

    profile = Option(require=False)
    es_host = Option(require=False)
    index = Option(require=False)
    # Obligatoire, contrôlé à l'exécution (ArgumentsSignales) : avec
    # require=True, son absence ne donnait qu'une erreur opaque de Splunk.
    query = Option(require=False)
    # Requête ES|QL (1.22.0), à la place de query= : envoyée telle quelle à
    # POST /_query, la période et les lookups à côté (sa_esearch/esql.py).
    esql = Option(require=False)

    @property
    def OBLIGATOIRES(self):  # nom attendu par ArgumentsSignales
        if self.esql is not None:
            return ()
        return (("query", 'query="*" pour tout ramener, ou esql= pour une requête ES|QL'),)

    limit = Option(require=False, default=100, validate=validators.Integer(minimum=1))
    timefield = Option(require=False)
    # Tri sur le champ date : none (défaut, ordre de stockage), asc (du plus
    # ancien au plus récent), desc (du plus récent au plus ancien). Validé dans
    # engine.build_payload, commun aux chemins direct et proxy.
    sort = Option(require=False, default="none")
    # Bornes écrites dans la commande (1.25.0), prioritaires sur le sélecteur de
    # temps, avec la sémantique et la résolution de Splunk (sa_esearch/temps.py).
    earliest = Option(require=False)
    latest = Option(require=False)
    # Métadonnées des documents (1.25.0) : es_index et es_id, pour dédoublonner
    # ou ouvrir le document dans Kibana. ES|QL : `FROM … METADATA _index, _id`.
    # Pas `metadata` : ce nom masquerait self.metadata de splunklib (commande cassée).
    es_metadata = Option(require=False, default=False, validate=validators.Boolean())

    # Dépréciés : credentials en clair dans la SPL (préférer profile=)
    user = Option(require=False)
    password = Option(require=False)
    apikey = Option(require=False)

    _source_include = Option(require=False)
    _source_exclude = Option(require=False)

    retry_count = Option(require=False, default=3, validate=validators.Integer(minimum=0, maximum=5))
    backoff_base = Option(require=False, default=0.5, validate=validators.Float(minimum=0, maximum=1.0))
    timeout_connect = Option(require=False, default=5, validate=validators.Integer(minimum=1, maximum=30))
    timeout_read = Option(require=False, default=30, validate=validators.Integer(minimum=1))

    # compress= / compress_threshold= : RETIRÉES en 1.14.0. Elles gzippaient le
    # corps des REQUÊTES au-delà de 8 Ko ; mesuré sur le fil, ces corps font
    # 0,2 à 0,4 Ko en usage courant : l'option ne
    # changeait rien, sauf pour une requête de plus de 8 Ko, gain négligeable
    # devant les réponses. Ce qui pèse, ce sont les RÉPONSES : elles sont demandées
    # compressées (Accept-Encoding: gzip, client.py) et ne le sont que si le
    # cluster l'accepte — `http.compression`, désactivée par défaut en HTTPS
    # (OPERATIONS § 7bis).
    # Encore DÉCLARÉES, sans effet, pour échouer en le disant : sans elles, Splunk
    # 9.3 n'affiche qu'« External search command exited unexpectedly » — une
    # recherche sauvegardée cassée ne disait pas pourquoi (vérifié).
    compress = Option(require=False)
    compress_threshold = Option(require=False)

    # Mode debug de CETTE recherche seulement (1.17.0) : ses lignes de journal,
    # commande et proxy, passent en DEBUG (le texte de la requête compris) et
    # portent le marqueur `[debug sid=<sid> debug_tag=<étiquette>]`, quel que
    # soit `[settings] log_level`, qui vaut, lui, pour toutes les recherches.
    # debug_tag= : nom libre, facultatif, pour retrouver la recherche dans le
    # journal ; il n'a de sens qu'avec debug=true.
    debug = Option(require=False, default=False, validate=validators.Boolean())
    debug_tag = Option(require=False)

    # Filtres par lookup Splunk (1.18.0) : lookups d'inclusion et d'exclusion
    # (noms séparés par des virgules), lues avec les droits de l'utilisateur et
    # traduites en Lucene ajouté à query= (sa_esearch/filtres.py). Combinaison
    # par défaut : ET (inclusion_type / exclusion_type = and|or). Colonnes :
    # toutes, sauf `_*` et [settings] lookup_fields_ignore ; lookup_fields_keep
    # restreint, lookup_fields_ignore écarte en plus.
    lookup_include = Option(require=False)
    lookup_exclude = Option(require=False)
    inclusion_type = Option(require=False)
    exclusion_type = Option(require=False)
    lookup_fields_keep = Option(require=False)
    lookup_fields_ignore = Option(require=False)
    # lucene (défaut) : expression Lucene ajoutée à query= ; terms (1.19.0) :
    # un filtre Elasticsearch `terms` par lookup, une colonne chacune, valeurs
    # exactes, jusqu'à 65 536 valeurs par lookup (index.max_terms_count).
    lookup_mode = Option(require=False)
    # ES|QL (1.23.0) : où s'appliquent les lookups. source (défaut) : aux
    # documents, avant la requête (filtre DSL, sémantique de query=) ; result :
    # aux colonnes du résultat, en fin de requête. Les marqueurs $lookup$,
    # $lookup_include$, $lookup_exclude$ placent les lookups à un endroit précis.
    lookup_stage = Option(require=False)
    # Filtres terms de la recherche (structure de sa_esearch/filtres.py).
    _filtres = None

    # Le chemin direct ne sert que le mode ad hoc : aucun profil, donc aucun
    # secret. Ce fournisseur défensif garantit qu'aucune lecture n'y survient.
    @staticmethod
    def _no_secret(profile_name, username):
        raise RuntimeError(
            "profil inattendu sur le chemin direct — bug de routage")

    # ---------------- bornes temporelles Splunk ----------------
    def _time_bounds(self):
        """Bornes effectives du time picker (earliest, latest) en epoch.

        Robustesse aux montées de version de Splunk : on privilégie l'API
        SUPPORTÉE (searchinfo.earliest_time/latest_time, peuplée nativement en
        SCPv2) dès qu'elle donne une fenêtre, et on ne retombe sur le format
        interne info.csv (_search_et/_search_lt) que si le natif est vide.
        Ceinture + bretelles :
          - le natif protège si Splunk change le format d'info.csv ;
          - info.csv protège si une version ne peuple pas le natif
            (le time picker continue de fonctionner dans les deux cas).
        "All time" = (0, 0) des deux côtés -> aucun filtre (comportement voulu).
        `earliest=` / `latest=` écrits dans la commande priment sur le tout.
        """
        if self.earliest is not None or self.latest is not None:
            return self._bornes_commande()

        def _f(v):
            try:
                return float(v) if v not in (None, "", "0", "0.0") else 0.0
            except (TypeError, ValueError):
                return 0.0

        sinfo = getattr(self._metadata, "searchinfo", None)

        # 1) Source primaire : métadata natif (API supportée)
        earliest = _f(getattr(sinfo, "earliest_time", None) if sinfo else None)
        latest = _f(getattr(sinfo, "latest_time", None) if sinfo else None)
        source = "searchinfo"

        # 2) Repli info.csv seulement si le natif ne donne aucune borne
        if earliest == 0.0 and latest == 0.0:
            data = self._info_csv()
            for ke, kl in (("_search_et", "_search_lt"), ("search_et", "search_lt")):
                if ke in data or kl in data:
                    e2, l2 = _f(data.get(ke)), _f(data.get(kl))
                    if e2 or l2:
                        earliest, latest, source = e2, l2, "info.csv"
                    break

        # Bornes inversées ou égales : refusées, comme earliest=/latest= dans la
        # commande et comme Splunk lui-même (« latest_time must be after
        # earliest_time », mesuré sur 9.3.14 — la recherche n'est pas créée).
        # Jusqu'en 1.26.3, elles étaient permutées en silence (F7 de la revue).
        if earliest > 0 and latest > 0 and latest <= earliest:
            raise ValueError(f"période invalide : la fin ({latest:.3f}) n'est pas "
                             f"postérieure au début ({earliest:.3f})")
        self._log.info("esearch: bornes temps=%s earliest=%s latest=%s",
                       source, earliest, latest)
        return earliest, latest

    def _info_csv(self):
        """Première ligne d'info.csv (dispatch de la recherche), {} si absent."""
        sinfo = getattr(self._metadata, "searchinfo", None)
        dispatch_dir = getattr(sinfo, "dispatch_dir", None) if sinfo else None
        if not dispatch_dir:
            return {}
        try:
            import csv
            with open(os.path.join(dispatch_dir, "info.csv"),
                      encoding="utf-8", newline="") as fh:
                reader = csv.reader(fh)
                return dict(zip(next(reader, []), next(reader, [])))
        except Exception as e:
            self._log.warning("info.csv illisible: %s", e)
            return {}

    def _bornes_commande(self):
        """earliest= / latest= de la commande, résolus par splunkd par rapport au
        `now` de la recherche (colonne `now` d'info.csv, la référence du
        sélecteur). Sans elle, l'heure courante, et le journal le dit."""
        try:
            now = float(self._info_csv().get("now") or "")
        except ValueError:
            now = time.time()
            self._log.warning("esearch: `now` absent d'info.csv, heure courante retenue")
        si = self._metadata.searchinfo
        u = urlsplit(si.splunkd_uri)
        svc = client.Service(scheme=u.scheme, host=u.hostname, port=u.port,
                             token=si.session_key, owner="-", app=si.app)
        earliest, latest = temps.bornes(self.earliest, self.latest,
                                        temps.resolveur(svc, now), now)
        self._log.info("esearch: bornes temps=commande earliest=%s latest=%s",
                       earliest, latest)
        return earliest, latest

    # ---------------- générateur principal ----------------
    # write_error/write_warning de splunklib appellent message.format() : un
    # message contenant des accolades ({...}, ex. JSON) planterait (KeyError).
    # On passe le message comme ARGUMENT de format -> accolades neutralisées.
    def _err(self, msg):
        self.write_error("{}", msg)

    def _warn(self, msg):
        # Un même message une seule fois par recherche (1.26.4) : le proxy
        # renvoie ses avertissements de profil (conf, transport en clair) à
        # chaque page.
        vus = self.__dict__.setdefault("_avert_vus", set())
        if msg not in vus:
            vus.add(msg)
            self.write_warning("{}", msg)

    def _sid(self):
        return getattr(getattr(self._metadata, "searchinfo", None), "sid", None) or None

    def _journal(self, cp):
        """Journal de la recherche : celui d'une recherche debug=true, ou le
        journal ordinaire. Étiquette vide = pas d'étiquette (page Query)."""
        if self.debug_tag and not self.debug:
            raise ValueError("debug_tag= ne s'emploie qu'avec debug=true")
        if not self.debug:
            return logger
        etiquette = valide_etiquette(self.debug_tag) if self.debug_tag else None
        marqueur = marqueur_debug(self._sid(), etiquette)
        portee = portee_debug(cfg.conf_get(cp, "settings", "debug_search_scope", "query"))
        self.write_info("{}", f"esearch: mode debug — lignes marquées {marqueur} dans "
                        "esearch.log (index _internal, lisible par les administrateurs) "
                        "et dans le search.log de ce job")
        return JournalRecherche(logger, marqueur, tout=(portee == "all"), echo=self._echo)

    @staticmethod
    def _echo(ligne):
        """Ligne marquée -> search.log du job (inspecteur). Splunk l'y étiquette
        ERROR, comme toute sortie d'erreur d'une commande : la ligne porte son
        vrai niveau entre crochets."""
        sys.stderr.write(ligne + "\n")
        sys.stderr.flush()

    def _planifiee(self):
        """Recherche lancée par le planificateur (sid `scheduler__…`) : ses
        résultats et ses messages peuvent être vus par d'autres que l'auteur."""
        return (self._sid() or "").startswith(("scheduler__", "rt_scheduler__"))

    def _requete_envoyee(self, texte):
        """Requête envoyée à Elasticsearch, montrée en warning à l'utilisateur
        (une fois par recherche), sauf pour une recherche planifiée."""
        if getattr(self, "_requete_montree", False):
            return
        self._requete_montree = True
        if not self._planifiee():
            self._warn(f"esearch debug — requête envoyée à Elasticsearch : {texte}")

    def _utilisateur(self):
        """Utilisateur Splunk de la recherche (journal, X-Opaque-Id)."""
        return getattr(getattr(self._metadata, "searchinfo", None), "username", None) or "?"

    def _partiel(self):
        """Suffixe d'une erreur survenue APRÈS l'émission d'événements.

        Une panne en cours de pagination (contexte expiré, réseau coupé) laissait
        les pages déjà reçues dans le résultat, à côté d'une erreur qui ne disait
        pas qu'il était incomplet : « 10 000 » s'affichait comme un compte juste."""
        n = getattr(self, "_emis", 0)
        return (f" — résultats PARTIELS : {n} événement(s) émis avant l'erreur, la "
                "suite manque") if n else ""

    def generate(self):
        self._emis = 0
        if self.refuse_arguments():
            return
        try:
            yield from self._run()
        except (ValueError, RuntimeError) as e:
            self._log.error("esearch: %s", e)
            self._err(f"esearch: {e}{self._partiel()}")
        except requests.exceptions.RequestException as e:
            # Le même type d'exception couvre DEUX interlocuteurs : Elasticsearch
            # (mode ad hoc) et splunkd/le proxy (tout profil).
            # Annoncer « Elasticsearch injoignable » pour un timeout sur
            # 127.0.0.1:8089 envoyait diagnostiquer le mauvais composant.
            cible = ("le proxy esearch (splunkd)" if self._via_proxy
                     else "Elasticsearch")
            self._log.error("esearch HTTP (%s): %s", cible, e)
            if self._via_proxy:
                self._err(f"esearch: {cible} injoignable ({e.__class__.__name__}: {e})"
                          + self._partiel())
            else:
                # Cause TLS traduite en phrase fixe ; le texte brut reste au journal.
                self._err("esearch: " + message_injoignable(e) + self._partiel())
        except Exception:
            self._log.error("esearch erreur inattendue:\n%s", traceback.format_exc())
            self._err("esearch: erreur interne (détail dans esearch.log)" + self._partiel())

    def _params(self):
        """Paramètres de recherche communs (hors connexion), avec bornes temps."""
        earliest, latest = self._time_bounds()
        return {
            "profile": self.profile, "index": self.index or "",
            "query": self.query, "limit": int(self.limit),
            # Sans lui, le proxy filtrait sur le timefield du PROFIL pendant que
            # `_time` suivait celui demandé : même SPL, résultat différent selon
            # que le profil est authentifié ou non.
            "timefield": self.timefield or "",
            "sort": self.sort or "none",
            "earliest": earliest, "latest": latest,
            "metadata": "1" if self.es_metadata else "",
            "source_include": self._source_include or "",
            "source_exclude": self._source_exclude or "",
            # Structure des filtres terms (lookup_mode=terms), texte JSON : elle
            # transite telle quelle vers le proxy, qui la revalide.
            "filtres": json.dumps(self._filtres) if self._filtres else "",
        }

    def _run(self):
        if self.compress is not None or self.compress_threshold is not None:
            raise ValueError("compress= et compress_threshold= ont été retirées en 1.14.0 "
                             "(sans effet mesurable) : les retirer de la recherche")
        # Conf lue par splunkd, avec le jeton de l'utilisateur (1.26.7, M6).
        cp = cfg.load_conf(logger, cfg.service_appelant(self._metadata.searchinfo))
        self._log = self._journal(cp)
        level = (cfg.conf_get(cp, "settings", "log_level", "INFO") or "INFO").upper()
        logger.setLevel(getattr(logging, level, logging.INFO))
        self._log.info("esearch: protocole=v%s user=%s profil=%s index=%s limit=%s",
                       getattr(self, "_protocol_version", "?"), self._utilisateur(),
                       self.profile, self.index, self.limit)
        if self.esql is not None:
            yield from self._run_esql(cp)
            return
        if self.lookup_stage is not None:
            raise ValueError("lookup_stage= ne s'emploie qu'avec esql= (avec query=, les lookups "
                             "s'appliquent toujours aux documents)")
        if self._filtres_demandes():
            # Avant le journal DEBUG : il doit montrer la requête réellement
            # envoyée, lookups résolues.
            self.query = self._requete_filtree(cp)
            if self.query is None:
                return
        # Bornée : une requête de plusieurs Mo écrirait une ligne de plusieurs Mo
        # dans un journal qui tourne à 5 Mo.
        self._log.debug("esearch: query=%s", tronque(self.query, 10000))
        if self._filtres:
            self._log.debug("esearch: filtres terms=%s",
                            tronque(json.dumps(self._filtres, ensure_ascii=False), 10000))
        # Refusée ici plutôt qu'au proxy : une requête hors bornes ne part pas.
        engine.valide_requete(self.query, *cfg.bornes_requete(cp, self._warn))
        # Budget du proxy : il plafonne la durée d'UN appel à `max_timeout_read`
        # (plus les attentes entre tentatives). Le client doit l'attendre, sinon
        # il abandonne avant lui et accuse splunkd d'être injoignable alors que
        # le travail se poursuit côté serveur.
        self._budget_proxy = cfg.conf_int(cp, "settings", "max_timeout_read", 300,
                                          minimum=1)

        # host/source/sourcetype venant d'ES : préfixés es_ si l'admin l'a
        # demandé, pour qu'Elasticsearch ne pilote pas les métadonnées Splunk.
        assainir_meta = cfg.as_bool(
            cfg.conf_get(cp, "settings", "sanitize_metadata_fields"), False)

        # Une seule boucle de pagination, deux transports. TOUT profil passe par
        # le proxy REST privilégié (1.16.0) : il contrôle le droit de l'appelant
        # (allowed_roles), lit le secret en système s'il y en a un, et sert
        # n'importe quelle app ou correlation search ES. Le chemin direct ne sert
        # plus que le mode ad hoc (es_host=, désactivé par défaut).
        if self._passe_par_proxy():
            pages, timefield = self._pages_proxy(cp), \
                self.timefield or cfg.profile_timefield(cp, self.profile)
        else:
            conn = cfg.resolve_connection(self, cp, self._no_secret)
            conn.headers["X-Opaque-Id"] = cfg.opaque_id(self._utilisateur())
            pages, timefield = self._pages_direct(conn), conn.timefield

        # gen_record, et non l'événement nu : splunklib fige les colonnes d'un
        # lot SCPv2 sur son PREMIER enregistrement, plus les champs déclarés
        # dans custom_fields. Sans cette déclaration, un champ absent du premier
        # événement d'un lot était jeté en silence pour tout le lot (jusqu'à
        # 50 000 événements, plusieurs pages) — perte de données sur tout index
        # aux documents hétérogènes. splunklib collecte le lot entier avant
        # d'écrire l'en-tête : les champs de tous ses événements y figurent.
        # Filtrage _source : le champ date est toujours ramené (il porte _time),
        # puis masqué au rendu si les filtres de l'utilisateur l'écartaient.
        filtres = {"source_include": self._source_include,
                   "source_exclude": self._source_exclude}
        masquer = engine.champ_date_masque(filtres, timefield)
        couvrants = engine.exclusions_couvrant_date(filtres, timefield)
        if couvrants:
            self._warn(f"esearch: _source_exclude « {', '.join(couvrants)} » écarte le "
                       f"champ date {timefield} : _time ne peut pas être posé. "
                       "Excluez des champs plus précis.")

        emis, total, sans_date = 0, None, 0
        for sources, t, metas, dates_es in pages:
            # Le total vient de la première page : les suivantes n'en portent
            # plus (track_total_hits=false, 1.26.4).
            total = total if total is not None else t
            for rang, source in enumerate(sources):
                meta = None
                if metas is not None:
                    meta = {"es_index": metas[rang][0], "es_id": metas[rang][1]}
                ev = build_event(source, timefield, assainir_meta, masquer, meta,
                                 dates_es[rang] if dates_es else None)
                sans_date += "_time" not in ev
                yield self.gen_record(**ev)
                emis += 1
                self._emis = emis
        if isinstance(total, dict) and total.get("value", 0) > emis:
            rel = "+" if total.get("relation") == "gte" else ""
            self._warn(f"esearch: résultats tronqués à {emis} "
                       f"(total côté Elasticsearch : {total['value']}{rel})")
        # Déjà dit plus haut quand _source_exclude écarte le champ date.
        if not couvrants:
            self._sans_date(sans_date, emis, timefield)
        self._log.info("esearch: %d événements émis", emis)

    def _sans_date(self, n, emis, timefield):
        """Brique 2 de la 1.27.0 : dit combien d'événements n'ont pas de `_time`,
        et seulement s'il y en a. Splunk les accepte, mais timechart, bin et la
        timeline les ignorent sans rien dire (mesuré : 3 comptés sur 6)."""
        if n and timefield:
            self._warn(f"esearch: {n} événement(s) sur {emis} sans date lisible dans "
                       f"{timefield} (champ absent, multivalué ou format non reconnu) : _time "
                       "non posé, timechart, bin et la timeline les ignorent")

    def _passe_par_proxy(self):
        """Vrai pour tout profil (proxy REST privilégié, 1.16.0), faux pour le
        mode ad hoc (es_host=) ; fixe le profil par défaut s'il manque."""
        if not (self.profile or not self.es_host):
            return False
        # Le chemin direct refuse ce mélange dans resolve_connection, qui
        # n'est pas appelé ici : sans ce contrôle, es_host/user/password/
        # apikey étaient ignorés EN SILENCE.
        if self.es_host or self.user or self.password or self.apikey:
            raise ValueError(
                "profile= est exclusif de es_host/user/password/apikey"
                if self.profile else
                "user/password/apikey ne s'emploient qu'avec es_host= (mode ad hoc)")
        self._via_proxy = True
        if not self.profile:
            self.profile = self._profil_par_defaut()
        return True

    def _run_esql(self, cp):
        """Requête ES|QL (esql=, 1.22.0) : une seule requête, sans pagination.
        Lookups (1.23.0) : appliqués aux documents (défaut, comme query=), ou
        insérés dans la requête (lookup_stage=result, marqueurs $lookup$…)."""
        for opt, val, aide in (
                ("query", self.query, "une recherche est soit Lucene (query=), soit ES|QL (esql=)"),
                ("index", self.index, "l'index se choisit dans la requête : FROM <index>"),
                ("_source_include", self._source_include, "colonnes : KEEP dans la requête"),
                ("_source_exclude", self._source_exclude, "colonnes : DROP dans la requête")):
            if val is not None:
                raise ValueError(f"{opt}= ne s'emploie pas avec esql= ({aide})")
        if self.es_metadata:
            raise ValueError("es_metadata= ne s'emploie pas avec esql= (métadonnées : "
                             "FROM <index> METADATA _index, _id, rendues es_index, es_id)")
        bornes = cfg.bornes_esql(cp, self._warn)
        # Refusée avant tout : une requête hors bornes ne coûte rien de plus.
        esql.valide(self.esql, *bornes)
        segs, marques = esql.marqueurs(self.esql)
        etape = (self.lookup_stage or "source").strip().lower()
        if etape not in ("source", "result"):
            raise ValueError(f"lookup_stage invalide : {court(self.lookup_stage, 40)} "
                             "(source ou result)")
        lookups = self._filtres_demandes()
        if marques and not lookups:
            raise ValueError(f"{', '.join(marques)} : aucun lookup à placer "
                             "(lookup_include= / lookup_exclude=)")
        if marques and self.lookup_stage is not None:
            raise ValueError("lookup_stage= et les marqueurs $lookup$… s'excluent : les marqueurs "
                             "placent déjà les lookups")
        self._budget_proxy = cfg.conf_int(cp, "settings", "max_timeout_read", 300,
                                          minimum=1)
        earliest, latest = self._time_bounds()
        params = {"profile": self.profile, "esql": self.esql, "limit": int(self.limit),
                  "timefield": self.timefield or "", "sort": self.sort or "none",
                  "earliest": earliest, "latest": latest, "esql_filtre": "", "filtres": ""}
        if self._passe_par_proxy():
            params["profile"] = self.profile
        texte = self.esql
        if lookups:
            texte = self._place_lookups(cp, params, segs, marques, etape)
            if texte is None:
                return
            params["esql"] = texte
            # Requête finale, lookups insérés compris : mêmes bornes.
            esql.valide(texte, *bornes)
            params["filtres"] = json.dumps(self._filtres) if self._filtres else ""
        self._log.debug("esearch: esql=%s", tronque(texte, 10000))
        r = self._appel_esql(params, cp)
        timefield = (self.timefield or cfg.profile_timefield(cp, self.profile)) \
            if self._via_proxy else r["timefield"]
        assainir_meta = cfg.as_bool(
            cfg.conf_get(cp, "settings", "sanitize_metadata_fields"), False)
        # Lignes sans date comptées seulement si la colonne du champ date est
        # rendue : un STATS … BY host, ou BY BUCKET(@timestamp, 1h), n'en a
        # légitimement pas. Une colonne « unsupported » a déjà son message
        # (esql.lignes).
        compter = bool(timefield) and any(
            c.get("name") == timefield and c.get("type") != "unsupported" for c in r["colonnes"])
        sans_date = 0
        for row in r["rows"]:
            ev = build_event(row, timefield, assainir_meta, meta=esql.meta(row))
            sans_date += compter and "_time" not in ev
            yield self.gen_record(**ev)
            self._emis += 1
        self._sans_date(sans_date, self._emis, timefield)
        self._log.info("esearch: %d ligne(s) ES|QL émise(s)", self._emis)

    def _appel_esql(self, params, cp, sonde=False):
        """Une requête ES|QL par le proxy (profil) ou en direct (ad hoc) :
        {"rows", "colonnes", "timefield"}. `sonde` : requête de lecture des
        types (`| LIMIT 0`), sans avertissement ni trace propres."""
        if self._via_proxy:
            base = dict(params, **self._transport_opts())
            resp = self._call_proxy(dict(base, action="esql"))
            self._recoit(resp, sonde, requete=True)
            if resp.get("en_cours"):
                resp = self._attend_asynchrone(base, resp, cp, sonde)
            return {"rows": resp.get("rows") or [], "colonnes": resp.get("colonnes") or [],
                    "timefield": None}
        conn = cfg.resolve_connection(self, cp, self._no_secret)
        conn.headers["X-Opaque-Id"] = cfg.opaque_id(self._utilisateur())
        r = esql.execute(conn, params,
                         timeouts=(float(self.timeout_connect), float(self.timeout_read)),
                         retry=int(self.retry_count), backoff=float(self.backoff_base),
                         logger=self._log, warn=(lambda m: None) if sonde else self._warn,
                         trace=self._requete_envoyee if (self.debug and not sonde) else None)
        return dict(r, timefield=conn.timefield)

    def _recoit(self, resp, sonde, requete):
        if not sonde:
            for w in resp.get("warnings", []):
                self._warn(w)
        self._trace_proxy(resp, requete=requete and not sonde)

    def _attend_asynchrone(self, base, resp, cp, sonde):
        """Profil en mode asynchrone (1.24.0) : interroge le proxy jusqu'à la
        fin de la requête, chaque appel attendant au plus esql_async_wait. Au-delà
        de esql_async_max, ou sur toute interruption, la requête est annulée
        (DELETE) au lieu de tourner jusqu'au bout côté Elasticsearch."""
        maxi = cfg.esql_async_max(cp, self._warn)
        debut = time.monotonic()
        jeton = None
        self._log.info("esearch: requête ES|QL asynchrone en cours")
        try:
            while resp.get("en_cours"):
                jeton = resp.get("jeton")
                if time.monotonic() - debut > maxi:
                    raise ValueError(f"requête ES|QL asynchrone arrêtée après {maxi} s (réglage "
                                     "esql_async_max) — restreindre la requête, ou relever le "
                                     "réglage")
                resp = self._call_proxy(dict(base, action="esql_suite", jeton=jeton))
                self._recoit(resp, sonde, requete=False)
            jeton = None
            return resp
        finally:
            if jeton:
                try:
                    self._call_proxy(dict(base, action="esql_annule", jeton=jeton))
                    self._log.info("esearch: requête ES|QL asynchrone annulée")
                except Exception as e:
                    self._log.warning("esearch: annulation ES|QL asynchrone en échec (%s) : "
                                      "le résultat expirera seul (esql_async_keep_alive)",
                                      e.__class__.__name__)

    def _types_colonnes(self, params, prefixe, cp):
        """{colonne: type ES|QL} à la fin de `prefixe` : la requête tronquée,
        `| LIMIT 0`, ne lit aucune donnée (mesuré)."""
        sonde = dict(params, esql=prefixe.rstrip() + "\n| LIMIT 0", limit=1, sort="none",
                     esql_filtre="", filtres="")
        return {c["name"]: c["type"] for c in self._appel_esql(sonde, cp, sonde=True)["colonnes"]}

    def _place_lookups(self, cp, params, segs, marques, etape):
        """Répartit les lookups : aux documents (filtre DSL, dans `params`), ou
        insérés dans la requête (segments WHERE). Rend le texte final, ou None
        si l'inclusion ne peut rien laisser passer."""
        mode = filtres.mode_lookup(self.lookup_mode)
        lus = self._lookups_lus(cp, mode)
        documents, inseres = [], []          # inseres : [(rang du marqueur ou None, lookups)]
        if marques:
            for sens, option in (("inclusion", "lookup_include"), ("exclusion", "lookup_exclude")):
                if any(x[1] == sens for x in lus) and not any(
                        sens in esql.MARQUEURS[m] for m in marques):
                    raise ValueError(f"{option}= : aucun marqueur ne le place — ajouter "
                                     f"${option}$ (ou $lookup$, qui place tous les lookups)")
            for m, k in marques.items():
                sous = [x for x in lus if x[1] in esql.MARQUEURS[m]]
                if not sous:
                    raise ValueError(f"{m} : aucun lookup correspondant "
                                     f"({'lookup_include=' if 'include' in m else 'lookup_exclude='})")
                if esql.zone_documents(segs, k):
                    documents += sous        # que des WHERE avant : filtre aux documents
                else:
                    inseres.append((k, sous))
        elif etape == "result":
            inseres.append((None, lus))
        else:
            documents = lus
        if documents:
            requete, self._filtres = self._compose_documents(documents, mode, "*")
            if requete is None:
                self._inclusion_vide()
                return None
            params["esql_filtre"] = "" if requete in ("*", "(*)") else requete
        if not inseres:
            return "|".join(s for s in segs if s.strip() not in esql.MARQUEURS)
        type_in, type_ex = self._types_lookups()
        maxi = cfg.esql_lookup_max(cp, self._warn)
        remplace, fin = {}, []
        for k, sous in inseres:
            avant = segs if k is None else segs[:k]
            prefixe = "|".join(s for s in avant if s.strip() not in esql.MARQUEURS)
            types = self._types_colonnes(params, prefixe, cp)
            exprs = []
            for nom, sens, lignes, cols in sous:
                e, n = esql_lookups.condition(lignes, cols, types, nom, mode)
                if n > maxi:
                    raise ValueError(f"lookup {court(nom)} : {n} valeurs à insérer dans la requête "
                                     f"ES|QL, maximum {maxi} (réglage esql_lookup_values_max) — "
                                     "lookup_stage=source (aux documents, sans cette limite)")
                exprs.append((sens, e))
            w = esql_lookups.wheres([e for sens, e in exprs if sens == "inclusion"], type_in,
                                    [e for sens, e in exprs if sens == "exclusion"], type_ex)
            if w is None:
                self._inclusion_vide()
                return None
            if k is None:
                fin = w
            else:
                remplace[k] = w
        morceaux = []
        for k, seg in enumerate(segs):
            if seg.strip() in esql.MARQUEURS:
                morceaux += [f" {w} " for w in remplace.get(k, [])]
            else:
                morceaux.append(seg)
        texte = "|".join(morceaux)
        if fin:
            texte += "\n| " + "\n| ".join(fin)
        return texte

    def _filtres_demandes(self):
        lookups = self.lookup_include is not None or self.lookup_exclude is not None
        for opt, lie in (("inclusion_type", self.lookup_include), ("exclusion_type", self.lookup_exclude)):
            if getattr(self, opt) is not None and lie is None:
                raise ValueError(f"{opt}= ne s'emploie qu'avec "
                                 f"{'lookup_include' if opt == 'inclusion_type' else 'lookup_exclude'}=")
        for opt in ("lookup_fields_keep", "lookup_fields_ignore", "lookup_mode", "lookup_stage"):
            if getattr(self, opt) is not None and not lookups:
                raise ValueError(f"{opt}= ne s'emploie qu'avec lookup_include= ou lookup_exclude=")
        return lookups

    def _lit_lookups(self, noms, max_octets):
        """Lignes de chaque lookup, en UNE recherche (`inputlookup append=t`),
        lancée avec le jeton de l'utilisateur dans l'app de la recherche : ses
        droits sur les lookups s'appliquent, comme pour | inputlookup."""
        si = self._metadata.searchinfo
        u = urlsplit(si.splunkd_uri)
        svc = client.Service(scheme=u.scheme, host=u.hostname, port=u.port,
                             token=si.session_key, owner="-", app=si.app)
        # export, et non oneshot : oneshot plafonne EN SILENCE à 50 000 lignes
        # ([restapi] maxresultrows) — mesuré, 50 000 lignes lues sur 65 537,
        # sans aucun message. Un filtre d'exclusion aurait exclu moins que prévu.
        # export diffuse toutes les lignes (65 537 sur 65 537, mesuré).
        flux = svc.jobs.export(filtres.recherche_lecture(noms), output_mode="json")
        lecteur = results.JSONResultsReader(flux)
        par_lookup, taille = [[] for _ in noms], 0
        for r in lecteur:
            if isinstance(r, dict) and getattr(lecteur, "is_preview", False):
                continue                    # résultats provisoires : non retenus
            if isinstance(r, dict):
                rang = int(r.pop("_esearch_lookup", -1))
                if 0 <= rang < len(noms):
                    par_lookup[rang].append(r)
                    # Arrêt dès que la requête dépasserait sa borne (1.17.1) :
                    # inutile de lire une lookup de plusieurs millions de lignes.
                    taille += sum(len(str(k)) + len(str(v)) + 8 for k, v in r.items())
                    if taille > max_octets:
                        raise ValueError("lookups trop volumineuses : la requête dépasserait "
                                         f"{max_octets} octets")
            elif getattr(r, "type", "") in ("ERROR", "FATAL"):
                # Une lookup absente ou non autorisée : les lignes des autres
                # arrivent quand même (append=t) — le filtre serait faux.
                raise ValueError(f"lookup : {r.message}")
        return par_lookup

    def _types_lookups(self):
        return (filtres.type_combinaison(self.inclusion_type, "inclusion_type"),
                filtres.type_combinaison(self.exclusion_type, "exclusion_type"))

    def _lookups_lus(self, cp, mode):
        """Lookups demandées, lues une seule fois : [(nom, sens, lignes, colonnes)]."""
        inclus = filtres.noms_lookups(self.lookup_include, "lookup_include")
        exclus = filtres.noms_lookups(self.lookup_exclude, "lookup_exclude")
        garder = filtres.liste(self.lookup_fields_keep)
        ignorer = (filtres.liste(cfg.conf_get(cp, "settings", "lookup_fields_ignore", ""))
                   + filtres.liste(self.lookup_fields_ignore))
        noms = inclus + exclus
        # Borne de lecture : celle de la requête en Lucene (query_max_bytes), celle
        # de la structure des filtres en mode terms.
        lignes = self._lit_lookups(noms, cfg.bornes_requete(cp)[0] if mode == "lucene"
                                   else filtres.FILTRES_MAX_OCTETS) if noms else []
        lus = []
        for rang, nom in enumerate(noms):
            cols = filtres.colonnes(lignes[rang], garder, ignorer)
            if lignes[rang] and not cols:
                raise ValueError(f"lookup {court(nom)} : aucune colonne retenue "
                                 "(lookup_fields_keep / lookup_fields_ignore)")
            sens = "inclusion" if rang < len(inclus) else "exclusion"
            self._log.info("esearch: lookup %s (%s) : %d ligne(s), colonnes %s", nom, sens,
                           len(lignes[rang]), ",".join(cols) or "-")
            lus.append((nom, sens, lignes[rang], cols))
        return lus

    def _compose_documents(self, lus, mode, requete):
        """(requête Lucene, filtres terms) qui appliquent les lookups `lus` aux
        documents ; requête None si l'inclusion ne peut rien laisser passer."""
        type_in, type_ex = self._types_lookups()
        exprs = [filtres.expression(lignes, cols) if mode == "lucene"
                 else filtres.liste_terms(lignes, cols, nom) for nom, _sens, lignes, cols in lus]
        inc = [e for (_n, sens, _l, _c), e in zip(lus, exprs) if sens == "inclusion"]
        exc = [e for (_n, sens, _l, _c), e in zip(lus, exprs) if sens == "exclusion"]
        if mode == "lucene":
            return filtres.compose(requete, inc, type_in, exc, type_ex), None
        # La requête reste celle de query= ; les lookups partent à côté, en
        # filtres terms (filter / must_not), revalidés par build_payload.
        f = filtres.compose_terms(inc, type_in, exc, type_ex)
        return (None if f is None else requete), (f or None)

    def _inclusion_vide(self):
        self._warn("esearch: aucune ligne d'inclusion utilisable (lookup vide) : aucun "
                   "résultat possible, Elasticsearch n'est pas interrogé")
        self._log.info("esearch: inclusion vide, Elasticsearch non interrogé")

    def _requete_filtree(self, cp):
        mode = filtres.mode_lookup(self.lookup_mode)
        requete, self._filtres = self._compose_documents(self._lookups_lus(cp, mode), mode,
                                                         self.query)
        if requete is None:
            self._inclusion_vide()
        return requete

    def _transport_opts(self):
        """Options de transport/réseau (identiques direct et proxy)."""
        return {
            "retry_count": int(self.retry_count),
            "backoff_base": float(self.backoff_base),
            "timeout_connect": int(self.timeout_connect),
            "timeout_read": int(self.timeout_read),
        }

    def _profil_par_defaut(self):
        """Profil d'une recherche sans profile= : le premier que l'appelant a le
        droit d'utiliser, dans l'ordre défini par l'administrateur (page
        Configuration, `[settings] profile_order`). Le proxy fait le tri — lui
        seul connaît les droits — et la commande annonce son choix : un
        résultat doit dire de quelle identité Elasticsearch il vient."""
        resp = self._call_proxy({"action": "profiles"})
        for w in resp.get("warnings", []):
            self._warn(w)
        self._trace_proxy(resp)
        dispo = resp.get("profiles") or []
        if not dispo:
            raise ValueError("aucun profil disponible pour vous : demandez à un "
                             "administrateur l'accès à un profil")
        self._warn(f"esearch: profil par défaut : {dispo[0]} (le premier de vos "
                   "profils dans l'ordre fixé par l'administrateur ; profile= pour "
                   "en choisir un autre)")
        self._log.info("esearch: profil par défaut retenu : %s", dispo[0])
        return dispo[0]

    def _pages_direct(self, conn):
        """Pages lues directement depuis Elasticsearch (mode ad hoc)."""
        for hits, total in engine.iter_pages(
                conn, self._params(),
                timeouts=(float(self.timeout_connect), float(self.timeout_read)),
                retry=int(self.retry_count), backoff=float(self.backoff_base),
                logger=self._log, warn=self._warn, keep_alive=conn.keep_alive,
                trace=self._requete_envoyee if self.debug else None):
            metas = [[h.get("_index"), h.get("_id")] for h in hits] if self.es_metadata else None
            yield ([h.get("_source", {}) for h in hits], total, metas,
                   engine.temps_es(hits, conn.timefield))

    @staticmethod
    def _temps(resp, n):
        """`_time` décodé par Elasticsearch, relayé par le proxy (1.26.4) : une
        liste de nombres (ou None) parallèle aux hits, sinon rien — `_time` se
        lit alors dans `_source`, comme avec un proxy antérieur."""
        temps = resp.get("temps")
        if not isinstance(temps, list) or len(temps) != n:
            return None
        return [t if isinstance(t, (int, float)) and not isinstance(t, bool)
                and math.isfinite(t) else None for t in temps]

    def _pages_proxy(self, cp):
        """Pages obtenues du proxy REST privilégié (tous les profils).

        Le curseur de pagination fait l'aller-retour : le proxy ne conserve rien
        entre deux appels, donc sa mémoire ne dépend pas du volume total. Le
        timeout de chaque appel couvre UNE page, ce pour quoi il est dimensionné.
        """
        base = dict(self._params(), **self._transport_opts())
        cursor, pages = None, 0
        while True:
            body = dict(base, action="page")
            if cursor:
                body["cursor"] = json.dumps(cursor)
            resp = self._call_proxy(body)
            for w in resp.get("warnings", []):
                self._warn(w)
            self._trace_proxy(resp)
            pages += 1
            hits, metas = resp.get("hits", []), None
            if self.es_metadata:
                metas = resp.get("meta")
                if not isinstance(metas, list) or len(metas) != len(hits):
                    raise RuntimeError("métadonnées absentes de la réponse du proxy (proxy "
                                       "d'une version antérieure ? redémarrer Splunk)")
            yield hits, resp.get("total"), metas, self._temps(resp, len(hits))
            cursor = resp.get("cursor")
            if not cursor:
                self._log.info("esearch: %d page(s) via proxy privilégié", pages)
                return

    def _trace_proxy(self, resp, requete=True):
        """Mode debug : lignes du proxy -> search.log, requête -> warning (pas
        celle d'une requête de lecture des types)."""
        if not self.debug:
            return
        for ligne in resp.get("journal") or []:
            self._echo(str(ligne))
        if requete and resp.get("requete"):
            self._requete_envoyee(str(resp["requete"]))

    def _call_proxy(self, body):
        self._log.info("esearch: action=%s profil=%s -> proxy REST",
                       body.get("action"), body.get("profile") or "(défaut)")
        if self.debug:
            # Le proxy marque ses propres lignes de la même façon : la recherche
            # se suit d'un processus à l'autre par le même marqueur.
            body = dict(body, debug="1", sid=self._sid() or "",
                        debug_tag=self.debug_tag or "")
        # Timeout de l'appel dérivé du timeout ES demandé, plus 60 s : les
        # attentes entre tentatives (≤ 31 s) et la marge d'aller-retour. Voir
        # _budget_proxy ci-dessus.
        return appel_proxy(self._metadata.searchinfo, body,
                           (int(self.timeout_connect),
                            max(int(self.timeout_read),
                                int(getattr(self, "_budget_proxy", 300))) + 60))

dispatch(ESearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
