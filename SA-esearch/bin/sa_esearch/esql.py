# -*- coding: utf-8 -*-
"""Requêtes ES|QL (`| esearch esql="…"`, 1.22.0).

Partagé par la commande (mode ad hoc) et le proxy REST (tout profil), comme
engine.py l'est pour query=. Mesures : OPERATIONS.md § 10.15.

  - la requête de l'utilisateur part TELLE QUELLE, à deux ajouts près, en fin :
    `| SORT <champ de temps>` si sort= est précisé, puis `| LIMIT n+1` ;
  - le sélecteur de période et les lookups (lookup_include= / lookup_exclude=)
    partent à côté, dans `filter` (requête DSL appliquée aux documents avant la
    requête ES|QL) : même sémantique que query=, mesurée de 8.11 à 9.5 ;
  - une seule requête, synchrone : pas de pagination en ES|QL. Le cluster rend
    au plus 10 000 lignes (esql.query.result_truncation_max_size) et coupe EN
    SILENCE au-delà (mesuré de 8.11 à 9.5) : la coupe est annoncée ici.
"""

import math

from sa_esearch import filtres
from sa_esearch.client import ESClient
from sa_esearch.diagnostic import verifie_identite
from sa_esearch.engine import (
    _borne_temps,
    _tls_warning,
    ordre_tri,
    plafond,
    valide_requete,
)
from sa_esearch.engine import bornes as engine_bornes
from sa_esearch.log import REQUETE, apercu, court, requete_lisible

# Bornes par défaut ([settings] esql_max_bytes / esql_max_depth, section
# « ES|QL » de la page Configuration). Mesuré (tas de 512 Mo) : une requête ES|QL
# a arrêté le nœud dès 10 Ko (5 000 parenthèses, 8.17.4) et 48 Ko (2 000 LIKE,
# 8.17.4) ; Lucene tenait jusqu'à 2 Mo. ES|QL refuse lui-même au-delà d'une
# profondeur d'expression de 400 (≈ 198 parenthèses), mais sous charge l'arrêt
# survient avant ce refus : l'app refuse plus tôt, avant tout envoi.
ESQL_MAX_OCTETS = 65536
ESQL_MAX_PROFONDEUR = 100
# Plafond de lignes d'une réponse ES|QL par défaut (réglable côté cluster).
PLAFOND_CLUSTER = 10000


def _code(texte):
    """Positions des caractères « de code » d'une requête ES|QL, lue comme ES
    la découpe : hors chaînes "…" (avec \\" et \\\\) et \"\"\"…\"\"\", hors
    identifiants entre backticks (`` doublé), hors commentaires // et /* */."""
    i, n = 0, len(texte)
    while i < n:
        c = texte[i]
        if texte.startswith('"""', i):
            j = texte.find('"""', i + 3)
            i = n if j < 0 else j + 3
        elif c == '"':
            i += 1
            while i < n and texte[i] != '"':
                i += 2 if texte[i] == "\\" else 1
            i += 1
        elif c == "`":
            i += 1
            while i < n:
                if texte.startswith("``", i):
                    i += 2
                elif texte[i] == "`":
                    break
                else:
                    i += 1
            i += 1
        elif texte.startswith("//", i):
            j = texte.find("\n", i)
            i = n if j < 0 else j
        elif texte.startswith("/*", i):
            j = texte.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            yield i
            i += 1


def lexemes(texte):
    """(profondeur maximale de parenthèses, positions des apostrophes), hors
    chaînes, identifiants et commentaires : leur contenu ne compte ni pour la
    profondeur ni comme apostrophe."""
    profondeur = maxi = 0
    apostrophes = []
    for i in _code(texte):
        c = texte[i]
        if c == "'":
            apostrophes.append(i)
        elif c == "(":
            profondeur += 1
            maxi = max(maxi, profondeur)
        elif c == ")":
            profondeur = max(0, profondeur - 1)
    return maxi, apostrophes


def segments(texte):
    """Contenus des segments de la requête, séparés par les `|` de code (pas
    ceux d'une chaîne ou d'un commentaire) : `"|".join(segments(t)) == t`."""
    coupes = [i for i in _code(texte) if texte[i] == "|"]
    bornes = [-1] + coupes + [len(texte)]
    return [texte[a + 1:b] for a, b in zip(bornes, bornes[1:])]


# Marqueurs de placement des lookups (1.23.0) : un segment entier de la requête,
# remplacé par l'app. `$` n'est pas de la syntaxe ES|QL : un marqueur oublié ne
# passe jamais en silence.
MARQUEURS = {"$lookup$": ("inclusion", "exclusion"),
             "$lookup_include$": ("inclusion",),
             "$lookup_exclude$": ("exclusion",)}


def marqueurs(texte):
    """{marqueur: rang du segment} de la requête, ou ValueError si un marqueur
    est mal placé (pas seul dans son segment, en tête, répété, ou `$lookup$`
    mêlé aux deux autres)."""
    segs = segments(texte)
    trouves = {}
    debut = 0
    for k, seg in enumerate(segs):
        s = seg.strip()
        if s in MARQUEURS:
            if k == 0:
                raise ValueError(f"{s} ne peut pas précéder FROM : il se place après un |")
            if s in trouves:
                raise ValueError(f"{s} figure plusieurs fois dans la requête (un seul par requête)")
            trouves[s] = k
        else:
            code = set(_code(texte[debut:debut + len(seg)]))
            if any(seg.startswith("$lookup", i) for i in code):
                raise ValueError("marqueur de lookup mal placé : il occupe un segment entier, "
                                 "entre deux | ou en fin de requête (… | $lookup$ | …)")
        debut += len(seg) + 1
    if "$lookup$" in trouves and len(trouves) > 1:
        raise ValueError("$lookup$ place tous les lookups : ne pas l'employer avec "
                         "$lookup_include$ / $lookup_exclude$")
    return segs, trouves


def zone_documents(segs, k):
    """Vrai si seuls `FROM` puis des `WHERE` précèdent le segment k : un filtre
    placé là équivaut au filtre appliqué aux documents (un ET se place
    n'importe où parmi des WHERE), avec sa sémantique exacte."""
    mots = [s.split(None, 1)[0].upper() if s.split() else "" for s in segs[:k]
            if s.strip() not in MARQUEURS]
    return bool(mots) and mots[0] == "FROM" and all(m == "WHERE" for m in mots[1:])


def valide(texte, max_octets=ESQL_MAX_OCTETS, max_profondeur=ESQL_MAX_PROFONDEUR):
    """Refuse (ValueError) une requête ES|QL hors bornes ou écrite avec des
    apostrophes, AVANT tout envoi : la commande le fait, et le proxy aussi pour
    tout profil (avant la lecture du secret)."""
    if not (texte or "").strip():
        raise ValueError("esql= est vide")
    taille = len(texte.encode("utf-8"))
    if taille > max_octets:
        raise ValueError(f"requête ES|QL trop longue : {taille} octets, maximum {max_octets} "
                         "(réglage esql_max_bytes : au-delà, Elasticsearch peut manquer de "
                         "mémoire et s'arrêter)")
    profondeur, apostrophes = lexemes(texte)
    if apostrophes:
        p = apostrophes[0]
        raise ValueError(
            f"requête ES|QL : apostrophe en position {p + 1} "
            f"({apercu(texte[max(0, p - 15):p + 15], 40)}) — en ES|QL, les chaînes "
            "s'écrivent entre guillemets doubles : \"web-01\" (\\\"web-01\\\" dans une "
            "recherche SPL) ; une apostrophe DANS une chaîne entre guillemets est permise")
    if profondeur > max_profondeur:
        raise ValueError(f"requête ES|QL trop imbriquée : {profondeur} niveaux de parenthèses, "
                         f"maximum {max_profondeur} (réglage esql_max_depth)")
    return texte


def chaine(valeur):
    """Littéral chaîne ES|QL. Sa grammaire n'a que \\t \\n \\r \\" \\\\ comme
    échappements et accepte tout autre caractère tel quel : json.dumps, qui
    écrit \\u0001, est refusé (« token recognition error », mesuré)."""
    t = str(valeur)
    for a, b in (("\\", "\\\\"), ('"', '\\"'), ("\n", "\\n"), ("\r", "\\r"), ("\t", "\\t")):
        t = t.replace(a, b)
    return '"' + t + '"'


def identifiant(nom):
    """Nom de champ écrit en identifiant ES|QL : entre backticks, `` doublé."""
    return "`" + str(nom).replace("`", "``") + "`"


def corps(params, timefield, limit_total, bornes_requete=None):
    """Corps envoyé à POST /_query : {query, filter}.

    `limit_total + 1` lignes demandées : en recevoir une de plus prouve que le
    résultat est coupé par limit= (ou max_limit), sans le deviner."""
    texte = params["esql"]
    ordre = ordre_tri(params)
    if ordre:
        if not timefield:
            raise ValueError("sort= : aucun champ de temps (timefield) pour trier")
        texte += f"\n| SORT {identifiant(timefield)} {ordre.upper()}"
    texte += f"\n| LIMIT {int(limit_total) + 1}"

    filtre, exclure = [], []
    earliest = _borne_temps(params.get("earliest"))
    latest = _borne_temps(params.get("latest"))
    if (earliest > 0 or latest > 0) and timefield:
        # Même fenêtre que query= (engine.build_payload) : earliest inclus,
        # latest exclu, à la milliseconde.
        ts = {"format": "epoch_millis"}
        if earliest > 0:
            ts["gte"] = math.ceil(round(earliest * 1000, 3))
        if latest > 0:
            ts["lt"] = math.ceil(round(latest * 1000, 3))
        filtre.append({"range": {timefield: ts}})
    # Lookups en mode lucene : l'expression des lookups, appliquée en
    # query_string aux documents (exactement comme query=), bornée comme lui.
    expression = params.get("esql_filtre") or ""
    if expression:
        filtre.append({"query_string": {"query": valide_requete(expression,
                                                                *(bornes_requete or ()))}})
    # Lookups en mode terms : même structure, revalidée, que pour query=.
    f_terms, e_terms = filtres.dsl_filtres(filtres.valide_filtres(params.get("filtres")))
    filtre += f_terms
    exclure += e_terms

    c = {"query": texte}
    if filtre or exclure:
        booleen = {}
        if filtre:
            booleen["filter"] = filtre
        if exclure:
            booleen["must_not"] = exclure
        c["filter"] = {"bool": booleen}
    return c


def lignes(data, masquer_keyword=True, warn=None):
    """Colonnes/valeurs d'une réponse ES|QL -> une ligne (dict) par résultat.

    - valeur nulle : champ absent (comme un champ absent de _source) ;
    - liste : champ multivalué Splunk (transform.flatten) ;
    - `X.keyword` masqué si `X` est aussi rendu (réglage esql_hide_keyword,
      comme Discover de Kibana par défaut) : même valeur, en double ;
    - type « unsupported » : valeurs nulles, signalé une fois. Deux causes :
      un type qu'ES|QL ne lit pas sur ce cluster (date_nanos avant 8.17,
      flattened avant 9.5…), ou un champ de types différents selon les index
      visés (date ici, long là ; mesuré sur 8.17 avec `FROM *`), que lève une
      conversion explicite (`TO_DATETIME(x)`, `x::datetime`, mesurée sur 8.17).
      Jusqu'en 1.26.7, le message ne citait que la première."""
    warn = warn or (lambda m: None)
    colonnes = data.get("columns") or []
    noms = [c.get("name") for c in colonnes]
    presents = set(noms)
    garder = [i for i, nom in enumerate(noms)
              if not (masquer_keyword and nom.endswith(".keyword")
                      and nom[:-len(".keyword")] in presents)]
    non_pris = [n for n, c in zip(noms, colonnes) if c.get("type") == "unsupported"]
    if non_pris:
        warn(f"esearch: colonne(s) {court(', '.join(non_pris), 200)} : valeurs vides — type "
             "non pris en charge par ES|QL sur ce cluster (date_nanos à partir "
             "d'Elasticsearch 8.17, flattened à partir de 9.5, nested jamais), ou type "
             "différent selon les index visés : convertir, ex. EVAL x = TO_DATETIME(x)")
    for valeurs in data.get("values") or []:
        yield {noms[i]: valeurs[i] for i in garder
               if i < len(valeurs) and valeurs[i] is not None}


# Colonnes METADATA (`FROM … METADATA _index, _id`) -> champs de l'app (1.25.0),
# sous les noms de es_metadata=true en Lucene. Préfixées `_`, Splunk les cachait.
META = {"_index": "es_index", "_id": "es_id", "_version": "es_version",
        "_score": "es_score", "_ignored": "es_ignored", "_index_mode": "es_index_mode"}


def meta(ligne):
    """Retire de `ligne` ses colonnes METADATA et les rend sous leur nom es_*
    (None s'il n'y en a pas)."""
    return {META[k]: ligne.pop(k) for k in list(ligne) if k in META} or None


def _client(conn, timeouts, retry, backoff, logger, warn):
    return ESClient(conn, timeout=timeouts, retry_count=retry, backoff=backoff,
                    logger=logger, warn=warn)


# Types de colonne ES|QL du champ date qui faussent la période ou le tri.
_TEXTES_ESQL = {"keyword", "text"}
_NOMBRES_ESQL = {"long", "integer", "double", "unsigned_long"}


def type_date(data, timefield, params, warn):
    """Brique 1 de la 1.27.0, en ES|QL : d'après le type de la colonne du champ
    date dans la réponse (les index du FROM ne sont pas analysés). Rien si la
    colonne manque (STATS, KEEP : légitime), si c'est une date, ou si elle est
    « unsupported » (message de lignes())."""
    t = next((c.get("type") for c in data.get("columns") or []
              if c.get("name") == timefield), None) if timefield else None
    periode = _borne_temps(params.get("earliest")) > 0 or _borne_temps(params.get("latest")) > 0
    ordre = ordre_tri(params)
    if t in _TEXTES_ESQL and (periode or ordre):
        quoi = " et ".join(m for m, oui in (("la période", periode), ("le tri", ordre)) if oui)
        verbe = "le comparent" if periode and ordre else "le compare"
        warn(f"esearch: champ date {timefield} en texte ({t}) : {quoi} {verbe} comme du "
             "texte — résultats possiblement incomplets ou mal ordonnés ; le mapper en date "
             "dans Elasticsearch")
    elif t in _NOMBRES_ESQL and periode:
        warn(f"esearch: champ date {timefield} en nombre ({t}) : la période lui est appliquée "
             "en millisecondes, des dates en secondes en sont exclues (query= les prend en "
             "compte, pas esql=)")
    elif t and periode and t not in ("date", "date_nanos", "unsupported"):
        warn(f"esearch: champ date {timefield} de type {t} : ce n'est pas une date, la "
             "période ne s'y applique pas")


def _resultat(data, avertissements, conn, params, logger, warn):
    """Réponse ES|QL finie -> {"rows", "coupe", "colonnes"}, coupe annoncée."""
    limit_total = plafond(conn, params, lambda m: None)
    for a in avertissements:
        warn(f"esearch: Elasticsearch : {court(a, 300)}")
    type_date(data, conn.timefield, params, warn)
    rows = list(lignes(data, getattr(conn, "esql_hide_keyword", True), warn))
    coupe = False
    if len(rows) > limit_total:
        rows = rows[:limit_total]
        coupe = True
        warn(f"esearch: résultat coupé à {limit_total} lignes (limit= ou max_limit) : "
             "la requête ES|QL en rend davantage")
    elif len(rows) >= PLAFOND_CLUSTER and len(rows) < limit_total:
        coupe = True
        warn(f"esearch: {len(rows)} lignes : plafond ES|QL du cluster probablement atteint "
             "(esql.query.result_truncation_max_size, 10 000 par défaut) — le résultat peut "
             "être incomplet ; agréger (STATS) ou restreindre la requête")
    if logger:
        logger.info("esearch: ES|QL %d ligne(s)%s", len(rows), " (coupé)" if coupe else "")
    colonnes = [{"name": c.get("name"), "type": c.get("type")} for c in data.get("columns") or []]
    return {"rows": rows, "coupe": coupe, "colonnes": colonnes}


def _tri(conn, params):
    return conn.timefield if ordre_tri(params) else None


def execute(conn, params, timeouts=(5, 30), retry=3, backoff=0.5, logger=None,
            warn=None, trace=None):
    """UNE requête ES|QL : {"rows", "coupe", "colonnes"} ; ou, profil en mode
    asynchrone et requête pas finie dans esql_async_wait, {"en_cours": True,
    "id": …} — la suite par `suite()`, l'abandon par `annule()`.

    Synchrone : durée bornée par le délai de lecture ; un client qui coupe la
    connexion fait annuler la requête par Elasticsearch (mesuré, < 0,2 s, de
    8.11 à 9.5)."""
    warn = warn or (lambda m: None)
    limit_total = plafond(conn, params, warn)
    _tls_warning(conn, warn)
    c = corps(params, conn.timefield, limit_total, engine_bornes(conn))
    valide(c["query"], getattr(conn, "esql_max_bytes", ESQL_MAX_OCTETS),
           getattr(conn, "esql_max_depth", ESQL_MAX_PROFONDEUR))
    asynchrone = getattr(conn, "esql_mode", "sync") == "async"
    client = _client(conn, timeouts, retry, backoff, logger, warn)
    try:
        if getattr(conn, "detect_version", False):
            client.server_info()
        verifie_identite(client, conn, warn)
        if trace or (logger and logger.isEnabledFor(10)):
            texte = requete_lisible("POST", client.base + ("/_query/async" if asynchrone
                                                             else "/_query"), c,
                                    getattr(conn, "debug_terms_max", 100))
            if logger:
                logger.debug("esearch: requête envoyée %s", texte, extra=REQUETE)
            if trace:
                trace(texte)
        if asynchrone:
            data, avertissements = client.esql_async(c, conn.esql_async_wait,
                                                     conn.esql_async_keep_alive,
                                                     _tri(conn, params))
        else:
            data, avertissements = client.esql(c, tri_ajoute=_tri(conn, params))
    finally:
        client.close()
    if asynchrone and data.get("is_running"):
        for a in avertissements:
            warn(f"esearch: Elasticsearch : {court(a, 300)}")
        if logger:
            logger.info("esearch: ES|QL asynchrone en cours (%s)", court(data.get("id"), 40))
        return {"en_cours": True, "id": data.get("id")}
    return _resultat(data, avertissements, conn, params, logger, warn)


def suite(conn, ident, params, timeouts=(5, 30), retry=3, backoff=0.5, logger=None,
          warn=None):
    """Suite d'une requête asynchrone : même forme que execute()."""
    warn = warn or (lambda m: None)
    client = _client(conn, timeouts, retry, backoff, logger, warn)
    try:
        data, avertissements = client.esql_suite(ident, conn.esql_async_wait,
                                                 _tri(conn, params))
        if not data.get("is_running"):
            # Résultat lu : libéré tout de suite, sans attendre l'échéance.
            client.esql_annule(ident)
    finally:
        client.close()
    if data.get("is_running"):
        return {"en_cours": True, "id": ident}
    return _resultat(data, avertissements, conn, params, logger, warn)


def annule(conn, ident, timeouts=(5, 30), logger=None):
    """Arrête une requête asynchrone et libère son résultat (best-effort)."""
    client = _client(conn, timeouts, 0, 0, logger, None)
    try:
        client.esql_annule(ident)
    finally:
        client.close()
