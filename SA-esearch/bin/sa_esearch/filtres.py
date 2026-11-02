# -*- coding: utf-8 -*-
"""Filtres d'inclusion et d'exclusion par lookup Splunk (1.18.0).

    | esearch query="action:query" lookup_include="inc.csv" lookup_exclude="exc_kv"

Chaque lookup devient une expression Lucene : le OU de ses lignes, chaque ligne
le ET de ses colonnes renseignées, chaque valeur une phrase échappée
(`host:"uc1"`), pour que le contenu d'une lookup ne puisse jamais changer la
structure de la requête (`OR`, `)`, espace, guillemet : vérifié, la voie
« sous-recherche + format » coupait la requête à la première valeur à espace).

Jokers : `*` dans une valeur est un joker, comme dans une lookup Splunk
WILDCARD ; `\\*` le neutralise (étoile littérale) et `\\\\` donne une barre
oblique inverse littérale devant un joker. `?` reste littéral (Splunk ne le
traite pas en joker, Lucene si : on suit Splunk). Toute autre barre oblique
inverse est littérale (`DOMAINE\\compte`). Splunk n'a aucun échappement dans
ses lookups ; cette règle est celle de l'app, traduite en échappement Lucene.

Combinaison (défaut : and, documentée) :
    inclusion_type=and   ->  AND L1 AND L2          or ->  AND (L1 OR L2)
    exclusion_type=and   ->  AND NOT L1 AND NOT L2  or ->  AND NOT (L1 AND L2)
L'opérateur relie les CONDITIONS : « être dans L » pour une inclusion, « ne pas
être dans L » pour une exclusion ; (NOT L1) OR (NOT L2) s'écrit NOT (L1 AND L2).
"""
import fnmatch
import json
import re

from sa_esearch.log import apercu, court

NOM = re.compile(r"^[A-Za-z0-9_.-]+$")
CHAMP = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_.@-]*$")
TYPES = ("and", "or")
# Colonnes jamais utilisées : internes à Splunk (`_key` du KV store, `_time`…).
TOUJOURS_IGNOREES = ("_*",)
# Caractères à échapper dans un terme Lucene (query_string), espaces compris.
_SPECIAUX_LUCENE = set('+-=&|><!(){}[]^"~*?:\\/ \t\n\r')


def liste(texte):
    """Liste séparée par des virgules, espaces autour ignorés."""
    return [x.strip() for x in (texte or "").split(",") if x.strip()]


def noms_lookups(texte, option):
    noms = liste(texte)
    for n in noms:
        if not NOM.match(n):
            raise ValueError(f"{option} : nom de lookup invalide : {apercu(n)} (lettres, chiffres, _ . -)")
    return noms


def type_combinaison(valeur, option):
    v = (valeur or "and").strip().lower()
    if v not in TYPES:
        raise ValueError(f"{option} invalide : {apercu(valeur)} (and ou or)")
    return v


def colonnes(lignes, garder, ignorer):
    """Colonnes retenues : celles des lignes, réduites à `garder` s'il est
    donné, moins `ignorer` (motifs `*` admis) et les colonnes internes."""
    vues = []
    for ligne in lignes:
        for c in ligne:
            if c not in vues:
                vues.append(c)
    if garder:
        vues = [c for c in vues if c in garder]
    motifs = list(TOUJOURS_IGNOREES) + list(ignorer or [])
    vues = [c for c in vues if not any(fnmatch.fnmatchcase(c, m) for m in motifs)]
    for c in vues:
        if not CHAMP.match(c):
            raise ValueError(f"colonne {apercu(c)} inutilisable comme champ Elasticsearch : "
                             "l'écarter avec lookup_fields_ignore")
    return vues


def jetons(brute):
    """Jetons d'une valeur de lookup : ("lit", caractère) ou ("joker", "*").
    Règle de l'app (docstring du module) : `*` joker, `\\*` étoile littérale,
    `\\\\` barre littérale, tout autre caractère littéral. Partagée par Lucene
    (valeur_lucene) et ES|QL (esql_lookups)."""
    v = str(brute)
    jetons_, i = [], 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v) and v[i + 1] in "*\\":
            jetons_.append(("lit", v[i + 1]))
            i += 2
            continue
        jetons_.append(("joker", "*") if c == "*" else ("lit", c))
        i += 1
    return jetons_


def valeur_lucene(brute):
    """`champ:` + cette expression : phrase exacte, ou terme à joker."""
    j = jetons(brute)
    if not any(t == "joker" for t, _ in j):
        texte = "".join(c for _, c in j)
        return '"' + texte.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return "".join("*" if t == "joker" else ("\\" + c if c in _SPECIAUX_LUCENE else c)
                   for t, c in j)


def expression(lignes, cols):
    """Expression Lucene d'une lookup, ou None si aucune ligne n'a de valeur :
    une lookup sans ligne utile ne correspond à rien."""
    termes = []
    for ligne in lignes:
        parties = []
        for c in cols:
            v = ligne.get(c)
            valeurs = [x for x in (v if isinstance(v, list) else [v]) if x not in (None, "")]
            if len(valeurs) == 1:
                parties.append(f"{c}:{valeur_lucene(valeurs[0])}")
            elif valeurs:
                parties.append("(" + " OR ".join(f"{c}:{valeur_lucene(x)}" for x in valeurs) + ")")
        if parties:
            termes.append("(" + " AND ".join(parties) + ")")
    if not termes:
        return None
    return "(" + " OR ".join(termes) + ")"


def compose(requete, inclus, type_inclusion, exclus, type_exclusion):
    """Requête finale, ou None si l'inclusion ne peut rien laisser passer.

    `inclus` / `exclus` : expressions des lookups, None pour une lookup vide
    (qui ne correspond à rien)."""
    morceaux = [f"({requete})"]
    if inclus:
        if type_inclusion == "and":
            if any(e is None for e in inclus):
                return None                  # ET avec une lookup vide : rien
            morceaux += [f"AND {e}" for e in inclus]
        else:
            utiles = [e for e in inclus if e is not None]
            if not utiles:
                return None
            morceaux.append(f"AND {utiles[0]}" if len(utiles) == 1
                            else "AND (" + " OR ".join(utiles) + ")")
    if exclus:
        if type_exclusion == "and":
            morceaux += [f"AND NOT {e}" for e in exclus if e is not None]
        elif all(e is not None for e in exclus):
            # (NOT L1) OR (NOT L2) = NOT (L1 AND L2) ; une lookup vide rend le
            # ET faux, donc l'exclusion entière sans effet.
            morceaux.append(f"AND NOT {exclus[0]}" if len(exclus) == 1
                            else "AND NOT (" + " AND ".join(exclus) + ")")
    return " ".join(morceaux)


def recherche_lecture(noms):
    """Une seule recherche pour toutes les lookups (`inputlookup append=t`) :
    chaque ligne porte le rang de sa lookup dans `_esearch_lookup`."""
    parties = []
    for rang, nom in enumerate(noms):
        parties.append(f'| inputlookup{" append=t" if rang else ""} "{nom}" '
                       f"| eval _esearch_lookup=coalesce(_esearch_lookup, {rang})")
    return " ".join(parties) + " | fields * _esearch_lookup"


# --------------------------------------------------------------------------
# Mode terms (lookup_mode=terms, 1.19.0) : chaque lookup devient un filtre
# Elasticsearch `terms` sur SA colonne, au lieu d'une expression Lucene. Un
# filtre terms compte pour une seule clause : jusqu'à `index.max_terms_count`
# valeurs (65 536 par défaut, mesuré) au lieu d'environ 4 600 termes Lucene.
# Valeur exacte, non analysée : à réserver aux champs `keyword`. Une colonne par
# lookup, pas de joker.
#
# La commande transmet une structure CONTRAINTE, jamais du DSL libre :
#   {"inclusion": {"type": "and", "listes": [{"champ": "host", "valeurs": [...]}]},
#    "exclusion": {"type": "and", "listes": [...]}}
# build_payload la revalide (chemin direct comme proxy) et la traduit en DSL.

MODES = ("lucene", "terms")
# Taille maximale de la structure sérialisée : bien au-dessus de 65 536 valeurs
# courtes, sous le `http.max_content_length` d'Elasticsearch (100 Mo).
FILTRES_MAX_OCTETS = 32 * 1024 * 1024


def mode_lookup(valeur):
    v = (valeur or "lucene").strip().lower()
    if v not in MODES:
        raise ValueError(f"lookup_mode invalide : {apercu(valeur)} (lucene ou terms)")
    return v


def _valeur_exacte(brute, nom):
    """Valeur littérale d'une cellule (règles d'échappement du mode Lucene) ;
    un joker non échappé est refusé : un filtre terms n'en connaît pas."""
    v, sortie, i = str(brute), [], 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v) and v[i + 1] in "*\\":
            sortie.append(v[i + 1])
            i += 2
            continue
        if c == "*":
            raise ValueError(f"lookup {court(nom)} : valeur à joker {apercu(v)} — lookup_mode=terms ne "
                             "connaît que des valeurs exactes (lookup_mode=lucene pour les jokers)")
        sortie.append(c)
        i += 1
    return "".join(sortie)


def liste_terms(lignes, cols, nom):
    """{"champ", "valeurs"} d'une lookup, ou None si elle n'a aucune valeur."""
    if not lignes:
        return None                 # lookup vide : ses colonnes sont inconnues
    if len(cols) != 1:
        raise ValueError(f"lookup {court(nom)} : lookup_mode=terms exige UNE colonne, celle-ci en "
                         f"retient {len(cols)} ({', '.join(cols) or 'aucune'}) — choisir avec "
                         "lookup_fields_keep ou lookup_fields_ignore")
    champ, vues, valeurs = cols[0], set(), []
    for ligne in lignes:
        v = ligne.get(champ)
        for x in (v if isinstance(v, list) else [v]):
            if x in (None, ""):
                continue
            x = _valeur_exacte(x, nom)
            if x not in vues:
                vues.add(x)
                valeurs.append(x)
    return {"champ": champ, "valeurs": valeurs} if valeurs else None


def compose_terms(inclus, type_inclusion, exclus, type_exclusion):
    """Structure des filtres (mêmes règles que compose() pour les lookups
    vides), {} s'il n'y a rien à filtrer, ou None si l'inclusion ne peut rien
    laisser passer."""
    filtres = {}
    if inclus:
        if type_inclusion == "and":
            if any(x is None for x in inclus):
                return None
            utiles = inclus
        else:
            utiles = [x for x in inclus if x is not None]
            if not utiles:
                return None
        filtres["inclusion"] = {"type": type_inclusion, "listes": utiles}
    if exclus:
        if type_exclusion == "and":
            utiles = [x for x in exclus if x is not None]
        else:
            utiles = exclus if all(x is not None for x in exclus) else []
        if utiles:
            filtres["exclusion"] = {"type": type_exclusion, "listes": utiles}
    return filtres


def valide_filtres(brut):
    """Structure des filtres reçue (texte JSON ou dict), revalidée : elle peut
    venir d'un appel direct du proxy. Rend le dict, ou None s'il n'y en a pas."""
    if brut in (None, "", {}):
        return None
    texte = brut if isinstance(brut, str) else json.dumps(brut)
    if len(texte.encode("utf-8")) > FILTRES_MAX_OCTETS:
        raise ValueError(f"filtres de lookup trop volumineux : plus de {FILTRES_MAX_OCTETS} octets")
    try:
        f = json.loads(texte)
    except ValueError:
        raise ValueError("filtres de lookup illisibles")
    if not isinstance(f, dict) or not set(f) <= {"inclusion", "exclusion"}:
        raise ValueError("filtres de lookup invalides")
    for sens, groupe in f.items():
        if (not isinstance(groupe, dict) or set(groupe) != {"type", "listes"}
                or groupe["type"] not in TYPES or not isinstance(groupe["listes"], list)
                or not groupe["listes"]):
            raise ValueError(f"filtres de lookup invalides ({sens})")
        for liste_ in groupe["listes"]:
            if (not isinstance(liste_, dict) or set(liste_) != {"champ", "valeurs"}
                    or not isinstance(liste_["champ"], str) or not CHAMP.match(liste_["champ"])
                    or not isinstance(liste_["valeurs"], list) or not liste_["valeurs"]
                    or not all(isinstance(v, str) for v in liste_["valeurs"])):
                raise ValueError(f"filtres de lookup invalides ({sens})")
    return f or None


def dsl_filtres(f):
    """Clauses DSL (filter, must_not) d'une structure validée."""
    def terms(liste_):
        return {"terms": {liste_["champ"]: liste_["valeurs"]}}
    filtre, exclure = [], []
    inc = (f or {}).get("inclusion")
    if inc:
        clauses = [terms(x) for x in inc["listes"]]
        if inc["type"] == "and" or len(clauses) == 1:
            filtre += clauses
        else:
            filtre.append({"bool": {"should": clauses, "minimum_should_match": 1}})
    exc = (f or {}).get("exclusion")
    if exc:
        clauses = [terms(x) for x in exc["listes"]]
        if exc["type"] == "and" or len(clauses) == 1:
            exclure += clauses              # retiré s'il est dans l'une d'elles
        else:
            exclure.append({"bool": {"filter": clauses}})   # retiré s'il est dans toutes
    return filtre, exclure
