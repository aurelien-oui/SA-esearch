# -*- coding: utf-8 -*-
"""Lookups insérés dans une requête ES|QL (1.23.0) : `lookup_stage=result`, ou
marqueur `$lookup$` / `$lookup_include$` / `$lookup_exclude$` placé après un
EVAL, un STATS…

Au début de la requête (défaut), les lookups filtrent les DOCUMENTS (filtre
DSL, sa_esearch/esql.py), exactement comme pour query=. Ici, ils filtrent les
COLONNES de la requête à l'endroit choisi : même logique que query= (une ligne
de lookup = ET de ses colonnes renseignées, cellule vide = pas de condition,
cellule multivaluée = l'une de ses valeurs, lignes reliées par OU), écrite en
ES|QL. Mesures :

  - `col IN (…)` perd les lignes multivaluées selon les AUTRES documents de
    l'index (instable) : chaque cellule est donc testée par intersection,
    `MV_COUNT(MV_DEDUPE(MV_APPEND(col, L))) < MV_COUNT(MV_DEDUPE(col))
    + MV_COUNT(MV_DEDUPE(L))`, juste sur les multivaluées, en UNE expression
    quel que soit le nombre de valeurs (MV_APPEND : Elasticsearch 8.15) ;
  - MV_APPEND exige le même type des deux côtés : la liste de valeurs (texte)
    est convertie au type de la colonne, lu au préalable (`| LIMIT 0`) ;
  - colonne `text` : comparaison insensible à la casse, `COALESCE(TO_LOWER(c),
    c)` contre les valeurs d'origine ET en minuscules — une valeur multivaluée
    n'est mise en minuscules qu'à partir de 8.19 / 9.1, et reste comparée à
    l'identique avant, sans jamais être perdue ;
  - jokers `*` : un LIKE par motif (colonnes texte seulement) ; un LIKE sur une
    valeur multivaluée n'est pas fiable (documenté) ;
  - inclusion `COALESCE(L, false)`, exclusion `NOT COALESCE(L, false)` : une
    valeur absente ne correspond pas, et une exclusion la garde ;
  - chaque condition dans son propre `WHERE` quand la combinaison le permet :
    Elasticsearch plafonne la profondeur d'expression (400) PAR expression.
"""

from sa_esearch import filtres
from sa_esearch.esql import chaine, identifiant
from sa_esearch.log import apercu, court

# Type ES|QL de la colonne -> conversion de la liste de valeurs (texte).
CONVERSIONS = {"keyword": None, "text": None, "integer": "TO_INTEGER", "long": "TO_LONG",
               "unsigned_long": "TO_UNSIGNED_LONG", "double": "TO_DOUBLE", "ip": "TO_IP",
               "date": "TO_DATETIME", "boolean": "TO_BOOLEAN", "version": "TO_VERSION"}
TEXTUELS = ("keyword", "text")


def _liste(valeurs, conversion):
    texte = "[" + ", ".join(chaine(v) for v in valeurs) + "]"
    return f"{conversion}({texte})" if conversion else texte


def _intersection(expr, valeurs, conversion):
    liste = _liste(valeurs, conversion)
    return (f"MV_COUNT(MV_DEDUPE(MV_APPEND({expr}, {liste}))) < "
            f"MV_COUNT(MV_DEDUPE({expr})) + MV_COUNT(MV_DEDUPE({liste}))")


def _like(jetons):
    """Motif LIKE : `*` joker ; étoile, `?` et barre littéraux échappés."""
    motif = "".join("*" if t == "joker" else ("\\" + c if c in "*?\\" else c) for t, c in jetons)
    return chaine(motif)


def _test_colonne(col, type_, valeurs, nom):
    """Conditions « la colonne contient l'une des valeurs » (exactes ou à
    joker), et le nombre de valeurs employées."""
    if type_ not in CONVERSIONS:
        raise ValueError(f"lookup {court(nom)} : la colonne {col} est de type {type_} à cet "
                         "endroit de la requête, non pris en charge par un lookup inséré "
                         "(lookup_stage=source pour filtrer les documents)")
    texte = type_ == "text"
    ref = identifiant(col)
    exactes, motifs = [], []
    for v in valeurs:
        j = filtres.jetons(v)
        if any(t == "joker" for t, _ in j):
            if type_ not in TEXTUELS:
                raise ValueError(f"lookup {court(nom)} : valeur à joker {apercu(v)} sur la colonne "
                                 f"{col}, de type {type_} — jokers réservés aux colonnes texte")
            motifs.append([(t, c.lower()) for t, c in j] if texte else j)
        else:
            exactes.append("".join(c for _, c in j))
    if texte:
        exactes += [x.lower() for x in exactes]
    exactes = list(dict.fromkeys(exactes))
    conditions = []
    if exactes:
        expr = f"COALESCE(TO_LOWER({ref}), {ref})" if texte else ref
        conditions.append(_intersection(expr, exactes, CONVERSIONS[type_]))
    cible = f"TO_LOWER({ref})" if texte else ref
    conditions += [f"{cible} LIKE {_like(j)}" for j in motifs]
    return conditions, len(exactes) + len(motifs)


def _ou(conditions):
    return conditions[0] if len(conditions) == 1 else "(" + " OR ".join(conditions) + ")"


def condition(lignes, cols, types, nom, mode="lucene"):
    """(expression ES|QL de la lookup, nombre de valeurs), ou (None, 0) si
    aucune ligne n'a de valeur (une lookup vide ne correspond à rien).

    `types` : {colonne: type ES|QL} à l'endroit de l'insertion."""
    absentes = [c for c in cols if c not in types]
    if absentes:
        raise ValueError(f"lookup {court(nom)} : colonne(s) {court(', '.join(absentes), 120)} "
                         "absente(s) de la requête à cet endroit (colonnes présentes : "
                         f"{court(', '.join(types), 200)})")
    if mode == "terms":
        # Mêmes règles qu'au début : une colonne, valeurs exactes.
        filtres.liste_terms(lignes, cols, nom)
    seules, multiples = {}, []
    for ligne in lignes:
        cellules = {}
        for c in cols:
            v = ligne.get(c)
            valeurs = [x for x in (v if isinstance(v, list) else [v]) if x not in (None, "")]
            if valeurs:
                cellules[c] = valeurs
        if len(cellules) == 1:
            (c, valeurs), = cellules.items()
            seules.setdefault(c, []).extend(valeurs)
        elif cellules:
            multiples.append(cellules)
    termes, total = [], 0
    # Lignes à une seule colonne renseignée : regroupées par colonne, une
    # intersection pour toutes leurs valeurs.
    for c, valeurs in seules.items():
        conditions, n = _test_colonne(c, types[c], list(dict.fromkeys(valeurs)), nom)
        termes += conditions
        total += n
    # Lignes à plusieurs colonnes : ET de leurs cellules, les paires restent liées.
    for cellules in multiples:
        conjonction = []
        for c, valeurs in cellules.items():
            conditions, n = _test_colonne(c, types[c], valeurs, nom)
            conjonction.append(_ou(conditions))
            total += n
        termes.append("(" + " AND ".join(conjonction) + ")")
    if not termes:
        return None, 0
    return _ou(termes), total


def wheres(inclus, type_inclusion, exclus, type_exclusion):
    """Segments `WHERE …` (sans `|`), ou None si l'inclusion ne peut rien
    laisser passer. Mêmes règles que filtres.compose() pour les lookups vides
    (expression None)."""
    segs = []
    if inclus:
        if type_inclusion == "and":
            if any(e is None for e in inclus):
                return None
            segs += [f"WHERE COALESCE({e}, false)" for e in inclus]
        else:
            utiles = [e for e in inclus if e is not None]
            if not utiles:
                return None
            segs.append("WHERE COALESCE(" + " OR ".join(utiles) + ", false)")
    if exclus:
        if type_exclusion == "and":
            segs += [f"WHERE NOT COALESCE({e}, false)" for e in exclus if e is not None]
        elif all(e is not None for e in exclus):
            segs.append("WHERE NOT COALESCE(" + " AND ".join(exclus) + ", false)")
    return segs
