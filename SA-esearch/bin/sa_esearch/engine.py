# -*- coding: utf-8 -*-
"""Construction du payload ES et exécution de la recherche.
Partagé par la commande esearch (chemin direct) et le handler REST proxy."""

import logging
import math
import re

from sa_esearch import filtres
from sa_esearch.client import ESClient
from sa_esearch.diagnostic import verifie_identite
from sa_esearch.log import REQUETE, apercu, requete_lisible


def _borne_temps(valeur):
    """Borne temporelle en float fini, ou 0 (« pas de borne »).

    Sur le chemin direct, les bornes viennent de Splunk (propres). Mais le proxy
    les reçoit en clair de l'appelant : `inf`/`1e400` levaient un OverflowError à
    la conversion `int()` (rendu en 500 « erreur interne »), et `nan` passait les
    comparaisons `> 0` sans y satisfaire — la fenêtre demandée devenait
    silencieusement « All time ». On ramène toute valeur non finie à « pas de
    borne », de façon explicite et identique sur les deux chemins.
    """
    try:
        f = float(valeur or 0)
    except (TypeError, ValueError):
        return 0.0
    return f if math.isfinite(f) else 0.0


def filtres_source(params):
    """Listes (inclusions, exclusions) de `_source_include`/`_source_exclude`."""
    def liste(cle):
        return [f.strip() for f in (params.get(cle) or "").split(",") if f.strip()]
    return liste("source_include"), liste("source_exclude")


def motif_couvre(motif, champ):
    """Vrai si le motif de filtrage `_source` d'ES retient `champ`.

    Sémantique d'Elasticsearch : `*` est le seul joker (il traverse les points),
    et un motif qui désigne un objet couvre tous ses sous-champs (`event` couvre
    `event.created`)."""
    rx = re.compile(re.escape(motif).replace(r"\*", ".*") + r"\Z")
    parts = champ.split(".")
    return any(rx.match(".".join(parts[:i])) for i in range(1, len(parts) + 1))


def champ_date_masque(params, timefield):
    """Vrai si les filtres de l'utilisateur n'auraient PAS ramené le champ date.

    build_payload le ramène quand même (il porte `_time`) ; le rendu doit alors
    le masquer, pour que le filtre s'applique exactement tel qu'écrit."""
    inc, exc = filtres_source(params)
    if not timefield:
        return False
    return bool((inc and not any(motif_couvre(m, timefield) for m in inc))
                or timefield in exc)


def exclusions_couvrant_date(params, timefield):
    """Exclusions par motif ou par objet parent qui écartent le champ date.

    Elles ne peuvent pas être levées sans réexposer d'autres champs exclus :
    `_time` ne peut alors pas être posé, et la commande doit le dire."""
    _inc, exc = filtres_source(params)
    return [m for m in exc if timefield and m != timefield and motif_couvre(m, timefield)]


# Valeurs de l'option `sort=` -> ordre Elasticsearch (None : aucun tri).
TRIS = {"none": None, "asc": "asc", "desc": "desc"}


def ordre_tri(params):
    """Ordre demandé par `sort=` : None (défaut, aucun tri), "asc" ou "desc".

    Validé ici, sur le chemin commun : le proxy reçoit ce paramètre en clair de
    n'importe quel porteur d'`esearch_run`."""
    brut = str(params.get("sort") or "none").strip().lower()
    if brut not in TRIS:
        raise ValueError(f"sort invalide : {apercu(brut)} (attendu : none, asc ou desc)")
    return TRIS[brut]


# Bornes de la requête (query=), contrôlées AVANT tout envoi, sur les deux
# chemins (la commande en ad hoc, le proxy pour tout profil — build_payload est
# leur point commun). Mesuré (1.17.1), un seul `| esearch` faisait TOMBER
# le nœud Elasticsearch, sans qu'Elasticsearch le refuse lui-même :
#   - parenthèses imbriquées sur ~3 000 niveaux : StackOverflowError, processus
#     arrêté (ES 8.17.4 et 7.17.24) ; 2 500 niveaux passaient. Le réglage
#     `indices.query.bool.max_nested_depth` (30) ne s'applique pas à query_string ;
#   - une phrase de 4 Mo : OutOfMemoryError sur un tas de 512 Mo (2 Mo passaient).
# Profondeur : 30, la valeur qu'Elasticsearch impose à ses propres requêtes
# booléennes. Taille : 1 Mio, très au-delà d'une requête humaine ou générée
# (au-delà d'environ 4 700 termes, ES refuse de toute façon : trop de clauses).
# Ce sont les DÉFAUTS : réglables depuis la 1.26.0 (`query_max_bytes`,
# `query_max_depth`, config.bornes_requete), un cluster de production n'ayant
# ni le tas ni la pile du cluster de mesure. La borne suit la connexion (`bornes()`).
REQUETE_MAX_OCTETS = 1024 * 1024
REQUETE_MAX_PROFONDEUR = 30


def bornes(conn):
    """(taille, imbrication) maximales de query= pour cette connexion."""
    return (getattr(conn, "query_max_bytes", REQUETE_MAX_OCTETS),
            getattr(conn, "query_max_depth", REQUETE_MAX_PROFONDEUR))


def profondeur_requete(texte):
    """Profondeur maximale de parenthèses d'une requête Lucene (query_string),
    hors phrases entre guillemets et caractères échappés (barre oblique inverse)."""
    profondeur = maxi = 0
    dans_phrase = echappe = False
    for c in texte:
        if echappe:
            echappe = False
        elif c == "\\":
            echappe = True
        elif c == '"':
            dans_phrase = not dans_phrase
        elif not dans_phrase:
            if c == "(":
                profondeur += 1
                maxi = max(maxi, profondeur)
            elif c == ")":
                profondeur = max(0, profondeur - 1)
    return maxi


def valide_requete(texte, max_octets=REQUETE_MAX_OCTETS, max_profondeur=REQUETE_MAX_PROFONDEUR):
    """Refuse (ValueError, donc 400 côté proxy) une requête qui dépasse les
    bornes, avec la mesure, la limite et le réglage qui la fixe."""
    taille = len((texte or "").encode("utf-8"))
    if taille > max_octets:
        raise ValueError(f"requête trop longue : {taille} octets, maximum {max_octets} "
                         "(réglage query_max_bytes ; au-delà, Elasticsearch peut manquer de "
                         "mémoire et s'arrêter) — découper la recherche, ou matérialiser la "
                         "liste de valeurs côté Elasticsearch")
    profondeur = profondeur_requete(texte or "")
    if profondeur > max_profondeur:
        raise ValueError(f"requête trop imbriquée : {profondeur} niveaux de parenthèses, "
                         f"maximum {max_profondeur} (réglage query_max_depth ; au-delà, "
                         "Elasticsearch peut s'arrêter) — simplifier les regroupements")
    return texte


# Seuil du compte exact des résultats : le défaut d'Elasticsearch.
TOTAL_EXACT_MIN = 10000

# Types du champ date (1.27.0), d'après `_field_caps`. Comportements mesurés sur
# ES 7.17, 8.17 et OpenSearch 3.9 : seuls date et
# date_nanos sont des dates pour Elasticsearch ; les autres types reçoivent la
# période en millisecondes, que chacun lit à sa façon.
DATES = {"date", "date_nanos"}
ENTIERS_COURTS = {"integer", "short", "byte"}
NOMBRES = {"long", "unsigned_long", "double", "float", "half_float", "scaled_float"} | ENTIERS_COURTS
TEXTES = {"keyword", "constant_keyword", "wildcard", "text", "match_only_text"}
ABSENT = "unmapped"
# Familles de tri d'Elasticsearch : deux familles dans les index visés font
# échouer le tri (« incompatible sort types »), un champ text aussi (pas de doc
# values). Le champ absent trie comme une date (unmapped_type de build_payload).
# Un type hors de cette table est laissé au jugement d'Elasticsearch.
FAMILLES_TRI = dict(
    {t: "entier" for t in DATES | {"long", ABSENT} | ENTIERS_COURTS},
    double="décimal", scaled_float="décimal", half_float="décimal", float="float",
    unsigned_long="unsigned_long", keyword="texte", constant_keyword="texte",
    wildcard="texte")
NON_TRIABLES = {"text", "match_only_text"}


def _noms(indices, n=3):
    """Index cités dans un message : les premiers, puis le compte des autres."""
    tete = ", ".join(indices[:n])
    return tete + (f" (+{len(indices) - n} autres)" if len(indices) > n else "")


def _par_type(types, retenus):
    return "; ".join(f"absent de {_noms(c['indices'])}" if t == ABSENT
                     else f"{t} dans {_noms(c['indices'])}"
                     for t, c in sorted(types.items()) if t in retenus)


def analyse_champ_date(types, champ, periode, ordre, warn):
    """Ce que les types du champ date (client.types_champ) changent à la
    recherche (1.27.0) : (date_es, secondes).

    - `date_es` : demander la date à Elasticsearch (docvalue_fields), seulement
      si le champ est date ou date_nanos avec doc values partout où il existe ;
    - `secondes` : index où le champ est numérique, auxquels la période est
      AUSSI appliquée en secondes (build_payload) ; None s'il n'y en a pas ;
    - avertit (`warn`) des index où la période ou le tri ne peuvent pas être
      justes : champ en texte, absent, entier court, d'un autre type ;
    - refuse (ValueError) un tri qu'Elasticsearch ne saurait pas faire.

    `types` None (sonde en échec) : (False, None), comportement d'avant 1.27.0."""
    if not types:
        return False, None
    reels = {t: c for t, c in types.items() if t != ABSENT}
    date_es = bool(reels) and all(t in DATES and c["aggregatable"] for t, c in reels.items())
    if ordre:
        familles = {FAMILLES_TRI[t] for t in types if t in FAMILLES_TRI}
        if len(familles) > 1 or NON_TRIABLES & set(types):
            raise ValueError(
                f"sort={ordre} impossible : le champ date {champ} n'a pas de type triable "
                f"commun aux index visés ({_par_type(types, set(types))}) — retirer sort=, "
                "ou viser des index où il a le même type")
    textes = TEXTES & set(types)
    if textes and (periode or ordre):
        quoi = " et ".join(m for m, oui in (("la période", periode), ("le tri", ordre)) if oui)
        verbe = "le comparent" if periode and ordre else "le compare"
        warn(f"esearch: champ date {champ} en texte ({_par_type(types, textes)}) : {quoi} "
             f"{verbe} comme du texte — résultats possiblement incomplets ou mal "
             "ordonnés ; le mapper en date dans Elasticsearch")
    if periode:
        if ABSENT in types:
            warn(f"esearch: champ date {champ} absent de {_noms(types[ABSENT]['indices'])} : "
                 "la période exclut tous leurs documents (« Toute période » les rend, "
                 "sans _time)")
        courts = ENTIERS_COURTS & set(types)
        if courts:
            warn(f"esearch: champ date {champ} en entier court ({_par_type(types, courts)}) : "
                 "trop petit pour une date en millisecondes, la période y fait échouer la "
                 "recherche ; le mapper en date ou en long")
        autres = set(types) - DATES - NOMBRES - TEXTES - {ABSENT}
        if autres:
            warn(f"esearch: champ date {champ} d'un type qui n'est pas une date "
                 f"({_par_type(types, autres)}) : la période ne s'y applique pas")
    secondes = sorted({i for t, c in types.items() if t in NOMBRES for i in c["indices"]})
    return date_es, (secondes or None) if periode else None


def _secondes(ms):
    """Borne en millisecondes -> texte décimal exact en secondes (epoch_second) :
    1791001800123 -> "1791001800.123", sans passer par un flottant."""
    return f"{ms // 1000}.{ms % 1000:03d}"


def build_payload(params, timefield, logger=None, bornes_requete=None, compte=True,
                  date_es=False, secondes=None):
    """Payload ES depuis les paramètres (query, bornes temps, filtrage champs).
    `bornes_requete` : (taille, imbrication) de la connexion, défauts sinon.
    `compte` : valeur de track_total_hits (True, un seuil, ou False).
    `date_es` : demander le champ date en epoch_millis (voir temps_es).
    `secondes` : index où le champ date est numérique (analyse_champ_date)."""
    must = [{"query_string": {"query": valide_requete(params["query"],
                                                      *(bornes_requete or ()))}}]
    # La période ne joue pas sur la pertinence : contexte filter (1.26.4, M3 de
    # la revue), sans calcul de score et mis en cache par Elasticsearch. Elle
    # était dans `must`, où elle ajoutait la même constante à chaque score :
    # mêmes documents, même ordre.
    filtre = []
    earliest = _borne_temps(params.get("earliest"))
    latest = _borne_temps(params.get("latest"))
    if earliest > 0 or latest > 0:
        # Sémantique de Splunk : earliest INCLUS, latest EXCLU, à la milliseconde.
        # Jusqu'en 1.13.1 : epoch_second, int() et lte — ES arrondit un lte à la
        # fin de la seconde, et la fenêtre réelle était [⌊earliest⌋, ⌊latest⌋+1 s[ :
        # deux recherches planifiées consécutives comptaient DEUX FOIS les
        # événements de la seconde frontière (mesuré contre un index
        # Splunk natif). round(…, 3) avant ceil : 1792143348.123 * 1000 vaut
        # 1792143348123.0001 en flottant, et ceil l'aurait poussé d'une ms.
        ts = {"format": "epoch_millis"}
        if earliest > 0:
            ts["gte"] = math.ceil(round(earliest * 1000, 3))
        if latest > 0:
            ts["lt"] = math.ceil(round(latest * 1000, 3))
        intervalle = {"range": {timefield: ts}}
        if secondes:
            # 1.27.0 : un champ date numérique en SECONDES ne recevait que la
            # période en millisecondes, et en sortait entièrement. Elle lui est
            # aussi appliquée en secondes : les deux plages ne se recouvrent pas
            # (s < 1e11 <= ms), l'union est exacte. Réservée aux index numériques
            # (sur un keyword, elle comparerait du texte) ; `format` la rend
            # analysable sur tout type, Elasticsearch l'analysant aussi dans les
            # index que `_index` écarte (mesuré). Absente sinon : la requête reste
            # celle d'avant, à l'octet près.
            sec = {"format": "epoch_second"}
            for borne in ("gte", "lt"):
                if borne in ts:
                    sec[borne] = _secondes(ts[borne])
            intervalle = {"bool": {"should": [intervalle, {"bool": {"filter": [
                {"terms": {"_index": list(secondes)}}, {"range": {timefield: sec}}]}}],
                "minimum_should_match": 1}}
        filtre.append(intervalle)
        if logger:
            logger.info("esearch: range %s %s%s", timefield, ts,
                        f" (+ secondes : {len(secondes)} index)" if secondes else "")
    booleen = {"must": must}
    # Filtres de lookup en mode terms (lookup_mode=terms) : structure revalidée
    # ici, sur les deux chemins, puis traduite en filter / must_not.
    lookups, exclure = filtres.dsl_filtres(filtres.valide_filtres(params.get("filtres")))
    filtre += lookups
    if filtre:
        booleen["filter"] = filtre
    if exclure:
        booleen["must_not"] = exclure
    payload = {"query": {"bool": booleen}, "track_total_hits": compte}
    if date_es and timefield:
        payload["docvalue_fields"] = [{"field": timefield, "format": "epoch_millis"}]

    # Sans tri (défaut), Elasticsearch rend les premiers documents STOCKÉS : avec
    # `limit` inférieur au total, ce ne sont ni les plus récents ni les plus
    # anciens. `sort=desc|asc` trie sur le champ date ; `unmapped_type` évite
    # qu'un index du motif dépourvu de ce champ fasse échouer la recherche.
    ordre = ordre_tri(params)
    if ordre and timefield:
        payload["sort"] = [{timefield: {"order": ordre, "unmapped_type": "date"}}]

    sf = {}
    inc, exc = filtres_source(params)
    if timefield and (inc or exc):
        # Le champ date porte `_time` : il est TOUJOURS ramené, quitte à être
        # masqué au rendu (champ_date_masque). Sans cela, un simple
        # _source_include="host,status" rendait des événements sans `_time`,
        # et tout le temporel en aval (timechart, bin, timeline) cassait.
        if inc and not any(motif_couvre(m, timefield) for m in inc):
            inc = inc + [timefield]
        exc = [m for m in exc if m != timefield]
    if inc:
        sf["includes"] = inc
    if exc:
        sf["excludes"] = exc
    if sf:
        payload["_source"] = sf
    return payload


def _tls_warning(conn, warn):
    """Avertit (une fois) quand la vérification TLS est désactivée."""
    if conn.verify is False:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        warn("esearch: vérification TLS désactivée (verify_certs=false) — "
             "à réserver aux environnements de test")


def list_indices(conn, pattern=None, timeouts=(5, 30), retry=3, backoff=0.5,
                 logger=None, warn=None):
    """Cibles interrogeables du cluster (index, alias, data streams).

    `pattern` restreint le périmètre ; à défaut on utilise `index_pattern` du
    profil (esearch.conf), sinon `*`. Sert à alimenter le menu déroulant de la
    page Query ; emprunte exactement le même chemin de connexion que la
    recherche (donc le proxy pour les profils authentifiés)."""
    warn = warn or (lambda m: None)
    _tls_warning(conn, warn)
    client = ESClient(conn, timeout=timeouts, retry_count=retry, backoff=backoff,
                      logger=logger, warn=warn)
    try:
        verifie_identite(client, conn, warn)
        return client.list_indices(pattern or getattr(conn, "index_pattern", "") or "*")
    finally:
        client.close()


PAGE_MAX = 10000          # index.max_result_window : taille de page ES


def plafond(conn, params, warn, premiere_page=True):
    """Limite effective après application du plafond max_limit."""
    limit_total = int(params["limit"])
    if limit_total > conn.max_limit:
        if premiere_page:
            warn(f"esearch: limit={limit_total} plafonné à max_limit={conn.max_limit} "
                 f"(configurable dans esearch.conf)")
        limit_total = conn.max_limit
    return limit_total


def _page(client, conn, params, cursor, limit_total, keep_alive, logger, trace=None):
    """Une page via un client déjà ouvert. Cœur partagé par les deux chemins.

    Première page : la requête envoyée est écrite au journal en DEBUG
    (extra=REQUETE : la seule ligne d'une recherche debug=t en portée `query`)
    et passée à `trace`, qui l'affiche à l'utilisateur."""
    emis = int((cursor or {}).get("n", 0))
    restant = max(0, limit_total - emis)
    if restant <= 0:
        return {"hits": [], "cursor": None, "total": client.last_total, "emis": emis}

    # Le total ne sert qu'à l'avertissement « résultats tronqués » : demandé en
    # première page seulement, et compté exactement jusqu'au plus grand de
    # limit + 1 et du défaut d'Elasticsearch (10 000) — au-delà, « N+ »
    # (relation gte). Jusqu'en 1.26.3 : compte exact à chaque page, qui empêche
    # Elasticsearch de s'arrêter tôt sur un gros index (M2 de la revue).
    compte = max(limit_total + 1, TOTAL_EXACT_MIN) if cursor is None else False
    # `_time` décodé par Elasticsearch (1.26.4, M4 de la revue), qui connaît le
    # format du mapping — l'app ne lisait que l'ISO 8601 et les époques. Depuis
    # 1.27.0, la même sonde dit aussi les index où le champ date n'est pas une
    # date (avertissements, période en secondes, tri refusé). Décidé en première
    # page, puis porté par le curseur (le proxy ne garde rien).
    if cursor is None:
        periode = _borne_temps(params.get("earliest")) > 0 or _borne_temps(params.get("latest")) > 0
        date_es, secondes = analyse_champ_date(
            client.types_champ(params.get("index") or "", conn.timefield), conn.timefield,
            periode, ordre_tri(params), client.warn)
    else:
        date_es, secondes = cursor.get("dv") is True, cursor.get("s") or None
    payload = build_payload(params, conn.timefield, logger if cursor is None else None,
                            bornes(conn), compte, date_es, secondes)
    es_cursor = {k: v for k, v in (cursor or {}).items() if k not in ("n", "dv", "s")} or None
    if cursor is None and (trace or (logger and logger.isEnabledFor(logging.DEBUG))):
        texte = requete_lisible("POST", client.url_recherche(params.get("index") or ""),
                                dict(payload, size=min(restant, PAGE_MAX)),
                                getattr(conn, "debug_terms_max", 100))
        if logger:
            logger.debug("esearch: requête envoyée %s", texte, extra=REQUETE)
        if trace:
            trace(texte)
    hits, suivant = client.search_page(
        params.get("index") or "", payload, min(restant, PAGE_MAX),
        es_cursor, conn.pagination, keep_alive,
        # tout tient en une page -> pas de contexte de pagination ouvert
        unique=(cursor is None and restant <= PAGE_MAX))
    # La taille de page d'un scroll est FIGÉE à sa création : les pages suivantes
    # ignorent le `size` demandé et peuvent donc dépasser ce qui reste à émettre.
    # On tronque ici — sinon `limit` et le plafond `max_limit` sont dépassés.
    if len(hits) > restant:
        hits = hits[:restant]
    emis += len(hits)
    # limite atteinte : on libère le contexte ES au lieu de le laisser expirer
    if suivant and emis >= limit_total:
        client.close_cursor(suivant)
        suivant = None
    if suivant:
        suivant = dict(suivant, n=emis, dv=date_es)
        if secondes:
            suivant["s"] = secondes
    return {"hits": hits, "cursor": suivant, "total": client.last_total, "emis": emis}


def temps_es(hits, timefield):
    """`_time` décodé par Elasticsearch pour chaque hit (epoch secondes), ou None
    là où il manque : champ date non demandé, absent du document, non mappé dans
    son index, ou multivalué (Elasticsearch trie alors les valeurs, et le
    document ne dit plus laquelle est la sienne). Le rendu lit alors `_source`,
    comme jusqu'en 1.26.3."""
    sortie = []
    for h in hits:
        v = (h.get("fields") or {}).get(timefield) if timefield else None
        try:
            t = float(v[0]) / 1000.0 if isinstance(v, list) and len(v) == 1 else None
        except (TypeError, ValueError):
            t = None
        sortie.append(t if t is not None and math.isfinite(t) else None)
    return sortie


def fetch_page(conn, params, cursor=None, timeouts=(5, 30), retry=3, backoff=0.5,
               logger=None, warn=None,
               keep_alive="2m", trace=None):
    """UNE page, sans rien conserver entre deux appels.

    C'est la primitive qu'utilise le proxy REST : l'état de pagination est
    entièrement porté par le curseur, que l'appelant lui renvoie. Le proxy reste
    donc sans état et sa mémoire ne dépend plus du volume total demandé.
    """
    warn = warn or (lambda m: None)
    limit_total = plafond(conn, params, warn, premiere_page=(cursor is None))
    if cursor is None:
        _tls_warning(conn, warn)
    client = ESClient(conn, timeout=timeouts, retry_count=retry, backoff=backoff,
                      logger=logger, warn=warn)
    try:
        if cursor is None and getattr(conn, "detect_version", False):
            client.server_info()
        if cursor is None:
            verifie_identite(client, conn, warn)
        return _page(client, conn, params, cursor, limit_total, keep_alive, logger, trace)
    finally:
        client.close()


def iter_pages(conn, params, timeouts=(5, 30), retry=3, backoff=0.5,
               logger=None, warn=None,
               keep_alive="2m", trace=None):
    """Génère les pages (liste de hits) en réutilisant une seule session HTTP.

    Même primitive que `fetch_page`, mais bouclée localement : c'est le chemin
    des profils sans secret. Le contexte ES est libéré même sur interruption.
    """
    warn = warn or (lambda m: None)
    limit_total = plafond(conn, params, warn)
    _tls_warning(conn, warn)
    client = ESClient(conn, timeout=timeouts, retry_count=retry, backoff=backoff,
                      logger=logger, warn=warn)
    if getattr(conn, "detect_version", False):
        client.server_info()   # détection passive (opt-in : [settings] detect_version)
    verifie_identite(client, conn, warn)
    cursor = None
    try:
        while True:
            r = _page(client, conn, params, cursor, limit_total, keep_alive, logger, trace)
            if r["hits"]:
                yield r["hits"], r["total"]
            cursor = r["cursor"]
            if not cursor:
                return
    finally:
        client.close_cursor(cursor)   # interruption Splunk : pas de contexte orphelin
        client.close()


def iter_hits(conn, params, **kw):
    """Génère les hits ES bruts (dicts avec `_source`), page par page.
    `warn(msg)` reçoit les avertissements (clamp max_limit, shards, TLS off)."""
    logger = kw.get("logger")
    count = 0
    for hits, _ in iter_pages(conn, params, **kw):
        for hit in hits:
            yield hit
            count += 1
    if logger:
        logger.info("esearch: %d hits ES", count)
