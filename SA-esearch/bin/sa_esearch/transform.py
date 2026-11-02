# -*- coding: utf-8 -*-
"""Transformation d'un document Elasticsearch en événement Splunk.

Les données ES sont traitées comme entrée NON FIABLE (index potentiellement
alimenté par un tiers, ou ES compromis). Deux protections :
  - `flatten` borne la profondeur de récursion (anti-DoS) ;
  - `build_event` neutralise les champs réservés Splunk fournis par ES
    (`_time`, `_raw`, `__mv_*`, champs internes) pour empêcher qu'une donnée
    contrôle l'heure de l'événement, la valeur brute, l'encodage multivaleur
    ou les métadonnées internes.
"""

import json
import math
import re

# Profondeur d'imbrication max avant de sérialiser le sous-arbre en JSON.
# (ES limite par défaut le mapping à 20 niveaux ; 50 est large et borne la pile.)
MAX_DEPTH = 50

# Champs que l'app/Splunk possèdent : s'ils viennent d'ES, ils sont préfixés
# `es_` pour préserver la donnée sans écraser l'interne. `_time`/`_raw` sont
# gérés explicitement par build_event.
_RESERVED = frozenset((
    "_time", "_raw", "_indextime", "_cd", "_bkt", "_si", "_serial",
    "_subsecond", "_kv", "_meta", "_sourcetype", "_confstr", "_path",
    # Champs de CLASSIFICATION de sécurité : eventtype et tag pilotent le CIM et
    # les correlation searches de Splunk ES (cœur de cible de l'app). Laissés
    # passer, un document ES forgé injectait une fausse classification. Toujours
    # préfixés `es_` — contrairement à host/source/sourcetype (ci-dessous), un
    # document ES n'a aucune raison légitime d'imposer ces deux-là.
    "eventtype", "tag",
))

# Métadonnées Splunk que l'app laisse passer par défaut : un document ES
# contenant `host` fixe alors le host de l'événement. Historique (v1.3.1), et
# souvent VOULU quand le document décrit bien la machine d'origine. Mais c'est
# une métadonnée qu'exploitent le CIM et les correlation searches : l'option
# [settings] sanitize_metadata_fields permet de les préfixer `es_` comme les
# autres champs réservés, pour que rien venant d'ES ne pilote ces champs.
_METADATA = frozenset(("host", "source", "sourcetype"))


def to_epoch(value):
    """Valeur de champ date (ISO8601, epoch s ou ms) -> epoch seconds, sinon None."""
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        f = None
    if f is not None:
        if not math.isfinite(f):
            return None
        # Unité déduite de l'ordre de grandeur (1.26.4, M4 de la revue). Jusqu'en
        # 1.26.3, seuil unique à 1e12 : des millisecondes antérieures à 2001
        # passaient pour des secondes, et micro- et nanosecondes étaient fausses.
        # Sous 1e11 : secondes (jusqu'en l'an 5138) ; puis ms (depuis 1973), µs, ns.
        a = abs(f)
        return f / 1e9 if a >= 1e17 else f / 1e6 if a >= 1e14 else f / 1e3 if a >= 1e11 else f
    try:
        from datetime import datetime, timezone
        texte = str(value).strip().replace("Z", "+00:00")
        # Fraction de seconde ramenée à 6 chiffres : fromisoformat (Python 3.9,
        # celui de Splunk 9) n'en lit que 3 ou 6, et un champ date_nanos en rend 9
        # (ES|QL 8.17+, et _source) — _time n'était alors pas posé.
        texte = re.sub(r"(\.\d{1,9})(?=[+-]\d\d:\d\d$|$)",
                       lambda m: (m.group(1) + "00000")[:7], texte)
        dt = datetime.fromisoformat(texte)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def _comme_raw(valeur):
    """Élément scalaire écrit comme dans `_raw` (JSON), qui fait foi.

    Sans cela, un même booléen avait trois graphies : `1`/`0` dans un champ
    simple (conversion de splunklib), `True`/`False` dans un champ multivaleur
    (`str()` Python), `true`/`false` dans `_raw` — et `| search actif=true` ne
    trouvait rien. Un `null` dans une liste sortait de même en `None`."""
    if isinstance(valeur, bool):
        return "true" if valeur else "false"
    return valeur


def flatten(obj, prefix="", out=None, depth=0):
    """Aplatit les objets imbriqués en dot-notation ; listes de scalaires ->
    multivaleur ; listes d'objets -> JSON. Au-delà de MAX_DEPTH niveaux, le
    sous-arbre est sérialisé en JSON (protège la pile d'un doc ES malveillant)."""
    if out is None:
        out = {}

    def pose(cle, valeur):
        # Un document ES peut contenir À LA FOIS un objet imbriqué `a: {b: 1}`
        # et un champ littéral `a.b: 2` : les deux s'aplatissent en `a.b` et
        # l'un écrasait l'autre EN SILENCE (le survivant dépendait de l'ordre
        # des clés). On conserve les deux en suffixant les suivants.
        if cle not in out:
            out[cle] = valeur
            return
        n = 2
        while f"{cle}#{n}" in out:
            n += 1
        out[f"{cle}#{n}"] = valeur

    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            if depth >= MAX_DEPTH:
                pose(key, json.dumps(v, ensure_ascii=False))
            else:
                flatten(v, key + ".", out, depth + 1)
        elif isinstance(v, list):
            if all(not isinstance(i, (dict, list)) for i in v):
                pose(key, [i if isinstance(i, str) else json.dumps(i) for i in v])
            else:
                pose(key, json.dumps(v, ensure_ascii=False))
        else:
            pose(key, _comme_raw(v))
    return out


def _sanitize(fields, reserves=_RESERVED):
    """Renomme les champs réservés Splunk issus d'ES en `es_<champ>` :
    - préfixe `__mv_` (collision avec l'encodage multivaleur du transport) ;
    - `_time`/`_raw` et autres champs internes (usurpation de métadonnées).
    La donnée est préservée, jamais silencieusement contrôlée par ES."""
    clean = {}
    for k, v in fields.items():
        if k in reserves or k.startswith(("__mv_", "_mv_")):
            nk = "es_" + k
            # éviter d'écraser un champ es_<k> déjà présent
            while nk in fields or nk in clean:
                nk = "es_" + nk
            clean[nk] = v
        else:
            clean[k] = v
    return clean


def _valeur_datee(source, timefield):
    """Valeur du champ date, chemin pointé compris (`event.created`).

    `source.get(timefield)` ne voyait qu'une clé de premier niveau : un
    `timefield = a.b` filtrait correctement côté Elasticsearch — qui, lui,
    comprend la notation pointée — mais ne posait jamais `_time`, et tous les
    événements prenaient l'heure de la recherche. On essaie donc la clé telle
    quelle (un document PEUT contenir littéralement « a.b »), puis la descente.
    """
    if not timefield:
        return None
    if timefield in source:
        return source[timefield]
    courant = source
    for part in timefield.split("."):
        if not isinstance(courant, dict) or part not in courant:
            return None
        courant = courant[part]
    return courant


def _sans_champ(source, chemin):
    """Copie de `source` privée du champ `chemin` (clé littérale ou chemin
    pointé) ; un objet que le retrait vide disparaît avec lui."""
    if chemin in source:
        return {k: v for k, v in source.items() if k != chemin}
    tete, _, reste = chemin.partition(".")
    if not reste or not isinstance(source.get(tete), dict):
        return source
    sous = _sans_champ(source[tete], reste)
    copie = dict(source)
    if sous:
        copie[tete] = sous
    else:
        del copie[tete]
    return copie


def build_event(source, timefield, sanitize_metadata=False, masquer_champ_date=False, meta=None,
                epoch_es=None):
    """Événement Splunk : champs aplatis (assainis) + _raw + _time.

    `sanitize_metadata` étend l'assainissement à `host`/`source`/`sourcetype`
    (préfixés `es_`) : Elasticsearch ne pilote alors plus ces métadonnées.

    `_time` est TOUJOURS dérivé du champ date choisi (jamais d'une valeur ES
    arbitraire). Si le champ date est absent/non parsable, `_time` n'est pas
    posé, et il reste VIDE : Splunk ne lui donne aucune valeur, et timechart,
    bin et la timeline ignorent l'événement (mesuré sur 9.3.14). La commande
    compte ces événements et le dit (1.27.0).

    `masquer_champ_date` : le champ date a été ramené pour poser `_time` alors
    que les filtres `_source` de l'utilisateur l'écartaient ; il est retiré des
    champs ET de `_raw` une fois `_time` dérivé, pour que le filtre s'applique
    exactement tel qu'écrit.

    `meta` (es_metadata=true, 1.25.0) : champs posés par l'app (`es_index`,
    `es_id`). Ils lui appartiennent comme `_time` : un champ du document du même
    nom est préservé, préfixé `es_` comme les autres champs réservés.

    Résilient par document : un `_source` pathologique (trop imbriqué ->
    RecursionError sur flatten/json) produit un événement marqueur au lieu
    d'abattre toute la recherche.

    `epoch_es` : la même date décodée par Elasticsearch (engine.temps_es), qui
    prime sur la lecture de `_source` (1.26.4)."""
    epoch = epoch_es if epoch_es is not None else to_epoch(_valeur_datee(source, timefield))
    try:
        if masquer_champ_date and timefield:
            source = _sans_champ(source, timefield)
        reserves = (_RESERVED | _METADATA) if sanitize_metadata else _RESERVED
        if meta:
            reserves = reserves | frozenset(meta)
        event = _sanitize(flatten(source), reserves)
        raw = json.dumps(source, ensure_ascii=False)
    except RecursionError:
        return {"_raw": "[document Elasticsearch trop imbriqué — ignoré]",
                "esearch_error": "recursion_depth"}
    except Exception as e:
        return {"_raw": "[document Elasticsearch illisible]",
                "esearch_error": type(e).__name__}
    event["_raw"] = raw
    if meta:
        event.update(meta)
    if epoch is not None:
        event["_time"] = epoch
    return event
