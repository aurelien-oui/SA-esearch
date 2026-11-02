# -*- coding: utf-8 -*-
"""Diagnostics de connexion et d'authentification, partagés par les deux chemins.

Principe : ne JAMAIS recopier le texte brut d'une exception vers l'utilisateur
(il peut contenir un en-tête, un chemin interne, un morceau de secret). On
reconnaît des causes connues dans ce texte et on rend une phrase FIXE ; le
détail complet reste dans esearch.log, pour l'administrateur.
"""
import re

# Alertes du SERVEUR à propos du certificat client. Elles ne suffisent pas à
# dire s'il était absent ou refusé : ES 8 répond « handshake failure » à un
# certificat absent, ES 7 « bad certificate » — l'alerte qu'ES 8 envoie à un
# certificat refusé. L'app, elle, sait si elle en a présenté un (esearch_cert,
# posé par le client HTTP) : la phrase en dépend.
_CERT_CLIENT = object()
_CERT_CLIENT_PHRASES = {
    False: ("Elasticsearch exige un certificat client (mTLS) et le profil n'en "
            "présente pas : renseigner client_cert et client_key"),
    True: ("Elasticsearch a refusé le certificat client présenté (expiré, ou "
           "signé par une CA qu'il ne reconnaît pas)"),
    None: ("Elasticsearch a refusé la poignée de main TLS : certificat client "
           "absent alors qu'il est exigé (mTLS), expiré, ou d'une CA non reconnue"),
}

# (fragments cherchés dans le texte de l'exception, phrase rendue). L'ordre
# compte : les échecs de VÉRIFICATION du certificat serveur avant les alertes
# envoyées par le serveur à propos du certificat CLIENT.
_CAUSES_TLS = (
    (("certificate has expired",),
     "le certificat du serveur Elasticsearch a expiré"),
    (("certificate is not yet valid",),
     ("le certificat du serveur Elasticsearch n'est pas encore valide "
      "(horloge du search head ou du serveur ?)")),
    (("unable to get local issuer certificate", "self signed certificate",
      "self-signed certificate", "unable to verify the first certificate"),
     ("le certificat du serveur n'est pas reconnu : sa CA, ou une CA "
      "intermédiaire, manque dans ca_file")),
    (("doesn't match", "hostname mismatch", "Hostname mismatch"),
     "le nom d'hôte d'es_host ne figure pas dans le certificat du serveur"),
    (("CERTIFICATE_UNKNOWN", "certificate unknown", "BAD_CERTIFICATE",
      "bad certificate", "unknown ca", "UNKNOWN_CA", "CERTIFICATE_EXPIRED",
      "alert certificate expired", "HANDSHAKE_FAILURE", "handshake failure",
      "certificate required", "CERTIFICATE_REQUIRED"),
     _CERT_CLIENT),
    (("protocol version", "PROTOCOL_VERSION", "unsupported protocol",
      "UNSUPPORTED_PROTOCOL"),
     ("aucune version de TLS commune — le serveur exige probablement TLS 1.3, "
      "que le Python de Splunk 9.x ne parle pas")),
    (("wrong version number", "WRONG_VERSION_NUMBER"),
     ("le serveur ne répond pas en TLS à cette adresse (es_host en https:// "
      "vers un port HTTP ?)")),
    (("RemoteDisconnected", "Remote end closed connection"),
     ("le serveur a fermé la connexion sans répondre (es_host en http:// alors "
      "que le serveur attend du TLS ?)")),
)


def cause_connexion(exc):
    """Phrase fixe décrivant la cause d'une panne de connexion, ou None."""
    texte = repr(exc) + " " + str(exc)
    for fragments, phrase in _CAUSES_TLS:
        if any(f in texte for f in fragments):
            if phrase is _CERT_CLIENT:
                return _CERT_CLIENT_PHRASES[getattr(exc, "esearch_cert", None)]
            return phrase
    return None


def message_injoignable(exc, prefixe="Elasticsearch injoignable"):
    """Message utilisateur d'une panne de connexion à Elasticsearch."""
    cause = cause_connexion(exc)
    if cause:
        return (f"{prefixe} ({exc.__class__.__name__}) — {cause} "
                "(détail dans esearch.log)")
    return (f"{prefixe} ({exc.__class__.__name__}) — vérifiez es_host, le "
            "réseau et les certificats du profil")


def erreur_proxy(statut, corps_json, texte):
    """Message utilisateur d'un refus ou d'une erreur du proxy REST.

    Le proxy répond toujours {"error": "..."} : ce message prime, 403 compris
    (profil réservé à d'autres rôles). Un 403 SANS ce corps vient de splunkd
    lui-même, avant le proxy : la capability esearch_run manque. Le message du
    proxy est rendu entier, et non le JSON brut tronqué à 200 caractères — la
    troncature coupait l'alerte de fin de message et affichait des \\uXXXX."""
    detail = ""
    if isinstance(corps_json, dict):
        detail = corps_json.get("error") or ""
    if detail:
        return detail
    if statut == 403:
        return ("accès au proxy esearch refusé : la capability 'esearch_run' est "
                "requise pour ce rôle (voir OPERATIONS.md §Accès global)")
    return f"proxy esearch HTTP {statut}: {texte[:200]}"


# Texte d'erreur d'Elasticsearch repris à l'écran et au journal : borné. Un
# refus de requête recopie la requête ENTIÈRE (« Failed to parse query [<toute
# la requête>] ») : mesuré, un message de 130 000 caractères pour 8 192 termes,
# affiché tel quel et écrit en une ligne dans esearch.log.
RAISON_MAX = 300


def tronque(texte, maxi=RAISON_MAX):
    texte = str(texte)
    return texte if len(texte) <= maxi else f"{texte[:maxi]}… ({len(texte)} caractères au total)"


def _causes(erreur):
    """Toutes les causes d'une erreur Elasticsearch : root_cause, la chaîne
    caused_by, et celle de la première shard en échec."""
    vus, pile = [], [erreur]
    if isinstance(erreur, dict):
        pile += list(erreur.get("root_cause") or [])
        pile += [f.get("reason") for f in (erreur.get("failed_shards") or [])[:1]]
    while pile:
        e = pile.pop(0)
        if isinstance(e, dict):
            vus.append(e)
            pile.append(e.get("caused_by"))
    return vus


def raison_es(corps, texte_brut=""):
    """Phrase d'un refus d'Elasticsearch, d'après la cause RÉELLE.

    La `reason` de premier niveau ne dit pas pourquoi : « Failed to parse query
    [<requête>] » vaut pour une faute de syntaxe comme pour une requête trop
    large, et la cause n'est que dans `caused_by`. Mesuré (ES 8.17.4) :
    `too_many_clauses` (parse) et `too_many_nested_clauses` (rewrite), qui
    donnent le plafond effectif — calculé par Elasticsearch d'après son tas, il
    diffère du réglage affiché (4 681 contre 4 096 pour un tas de 512 Mo)."""
    erreur = corps.get("error") if isinstance(corps, dict) else None
    if not isinstance(erreur, dict):
        return tronque(erreur or texte_brut)
    causes = _causes(erreur)
    types = {c.get("type") for c in causes}
    if types & {"too_many_clauses", "too_many_nested_clauses"}:
        plafond = ""
        for c in causes:
            m = re.search(r"maxClauseCount is set to (\d+)", c.get("reason") or "")
            if m:
                plafond = f" (plafond de ce cluster : {m.group(1)} clauses)"
                break
        return ("requête trop large : trop de clauses" + plafond + ". Un terme sans "
                "champ est cherché dans CHAQUE champ de l'index et compte pour autant "
                "de clauses : préfixer les termes de leur champ (champ:valeur), ou "
                "réduire le nombre de termes")
    # OpenSearch borne la longueur d'une query_string (réglage
    # search.query.max_query_string_length, 32 000 par défaut ; mesuré sur
    # OpenSearch 3.9.0, 1.26.1) et le dit dans une parse_exception : ce n'est pas
    # une faute de syntaxe, la requête est simplement trop longue pour ce cluster.
    for c in causes:
        m = re.search(r"length exceeds max allowed length (\d+) \(([\w.]+)\); actual length: (\d+)",
                      c.get("reason") or "")
        if m:
            return (f"requête trop longue pour ce cluster : {m.group(3)} caractères, maximum "
                    f"{m.group(1)} (réglage du cluster {m.group(2)}) — préfixer les termes de "
                    "leur champ, réduire la liste de valeurs (lookup_mode=terms pour une "
                    "lookup), ou relever ce réglage côté cluster")
    syntaxe = [c for c in causes if c.get("type") == "parse_exception"]
    if syntaxe:
        # La plus profonde dit où (« Encountered "<EOF>" at line 1, column 9. ») ;
        # sa première ligne suffit, la suite liste les jetons attendus.
        detail = (syntaxe[-1].get("reason") or "").splitlines()[0]
        return "syntaxe de requête invalide : " + tronque(detail)
    racine = (erreur.get("root_cause") or [erreur])[0]
    return tronque(racine.get("reason") if isinstance(racine, dict) else racine)


def raison_esql(corps, texte_brut="", tri_ajoute=None):
    """Phrase d'un refus d'Elasticsearch à une requête ES|QL, lue d'après le
    TYPE de l'erreur, jamais son texte seul (il change d'une version à l'autre :
    « Found 1 problem » disparaît en 9.4, mesuré).

    `tri_ajoute` : champ de temps du `SORT` ajouté par sort= ; une colonne
    inconnue qui porte son nom vient alors de là, et non de l'utilisateur."""
    erreur = corps.get("error") if isinstance(corps, dict) else None
    if not isinstance(erreur, dict):
        return tronque(erreur or texte_brut)
    causes = _causes(erreur)
    racine = (erreur.get("root_cause") or [erreur])[0]
    racine = racine if isinstance(racine, dict) else {"reason": str(racine)}
    genre = racine.get("type") or erreur.get("type") or ""
    detail = re.sub(r"^Found \d+ problems?\s*", "", str(racine.get("reason") or "")).strip()
    tous = " ".join(str(c.get("reason") or "") for c in causes) + " " + detail
    if "maximum expression depth" in tous:
        m = re.search(r"allowed \((\d+)\)", tous)
        return ("requête ES|QL trop complexe : Elasticsearch plafonne la profondeur des "
                f"expressions à {m.group(1) if m else 'une valeur fixe'} (conditions OR "
                "enchaînées, parenthèses ; lookups insérés : lignes à plusieurs colonnes, "
                "motifs à joker) — simplifier, remplacer une suite de OR par IN, ou "
                "lookup_stage=source")
    if "statement is too large" in tous:
        return ("requête ES|QL trop grande pour le parseur d'Elasticsearch — la réduire "
                "(listes, imbrication)")
    if genre == "circuit_breaking_exception" or "circuit_breaking_exception" in tous:
        return ("mémoire insuffisante côté Elasticsearch (disjoncteur) : la requête ES|QL en "
                "demande trop — restreindre la période ou les index, agréger plus tôt")
    if "Unknown function [MV_APPEND]" in tous:
        return ("lookups insérés dans la requête (lookup_stage=result, ou marqueur après "
                "EVAL/STATS) : Elasticsearch 8.15 minimum (fonction MV_APPEND) — "
                "lookup_stage=source, ou un marqueur avant tout EVAL/STATS")
    if genre == "verification_exception":
        if tri_ajoute and re.search(r"Unknown column \[" + re.escape(tri_ajoute) + r"\]", detail):
            return (f"sort= : la colonne {tri_ajoute} n'existe plus en fin de requête (KEEP, "
                    "STATS…) — la garder dans la requête, ou retirer sort=")
        # Brique 4 de la 1.27.0 : champ date de types différents selon les index
        # (date ici, keyword là) — ES|QL refuse alors de le trier (mesuré de
        # 8.14 à 9.5), et de l'employer tel quel ailleurs dans la requête.
        m = re.search(r"Cannot use field \[" + re.escape(tri_ajoute or "") +
                      r"\] due to ambiguities[^:]*:\s*([^\n]*)", detail) if tri_ajoute else None
        if m:
            return (f"sort= impossible : le champ date {tri_ajoute} n'a pas le même type dans "
                    f"tous les index visés ({tronque(m.group(1), 300)}) — retirer sort= (et "
                    "toute autre utilisation du champ tel quel dans la requête)")
        return "requête ES|QL refusée : " + tronque(detail.splitlines()[0] if detail else genre)
    if genre == "parsing_exception":
        return "syntaxe ES|QL invalide : " + tronque(detail.splitlines()[0] if detail else genre)
    return raison_es(corps, texte_brut)


def precision_contexte(statut, raison):
    """Précision d'un 404 « contexte de recherche introuvable » (PIT ou scroll).

    Elasticsearch libère un contexte de pagination resté inutilisé plus de
    `page_keep_alive` : sous charge (cluster lent, proxy saturé), l'intervalle
    entre deux pages peut le dépasser. Son message (« No search context found
    for id [1248] ») ne le dit pas."""
    if statut == 404 and ("search context" in raison or "search_context_missing" in raison):
        return (" — le contexte de pagination a expiré entre deux pages (délai "
                "[settings] page_keep_alive dépassé : cluster ou proxy trop lent) ; "
                "relancer, ou augmenter page_keep_alive")
    return ""


def precision_refus(headers, statut, cert=None):
    """Précision ajoutée à un refus d'Elasticsearch, selon le mode d'auth.

    Le 401 d'Elasticsearch ne dit pas POURQUOI une clé API est refusée ; le
    cas le plus fréquent est une clé collée au mauvais format (`id:api_key`,
    tel qu'affiché aussi par Kibana, au lieu de la valeur `encoded`). On le
    reconnaît sans jamais réénoncer la clé."""
    if statut != 401:
        return ""
    entete = (headers or {}).get("Authorization", "")
    if not entete and cert:
        # Profil SANS secret mais avec certificat client : l'identité doit venir
        # du certificat (domaine PKI). Le 401 d'ES dit alors « missing
        # authentication credentials », ce qui égare : le certificat a bien été
        # présenté, c'est le domaine PKI qui ne l'a pas retenu.
        return (" — authentification par certificat client refusée : vérifier "
                "que le domaine PKI d'Elasticsearch est activé (licence "
                "Platinum/Enterprise ou d'essai) et qu'il reconnaît la CA de ce "
                "certificat")
    if not entete.startswith("ApiKey "):
        return ""
    cle = entete[len("ApiKey "):].strip()
    if ":" in cle:
        return (" — la clé API du profil est au format « id:api_key » : "
                "Elasticsearch attend la valeur « encoded » (base64 de "
                "« id:api_key »), telle que la renvoie l'API _security/api_key")
    return (" — clé API refusée : vérifier qu'elle n'est ni expirée ni "
            "révoquée, et que le secret du profil est bien la valeur « encoded »")


# Domaine retenu par Elasticsearch, selon le mode d'auth du profil.
_ATTENDU = {"ApiKey": "clé API", "Basic": "identifiant/mot de passe"}


def verifie_identite(client, conn, warn):
    """Avertit si Elasticsearch n'a PAS authentifié la requête par le moyen
    configuré dans le profil.

    Cas réel : clé API révoquée ou expirée + certificat client du mTLS associé
    à un rôle par le domaine PKI → Elasticsearch « retombe » sur le certificat
    et la recherche aboutit, sous une autre identité. Révoquer la clé ne
    coupait donc rien, sans que personne ne le voie.

    Coût : un `GET /_security/_authenticate`, seulement pour les profils qui
    combinent certificat client ET clé API ou mot de passe — les seuls où ce
    repli est possible. N'échoue jamais la recherche."""
    entete = (getattr(conn, "headers", None) or {}).get("Authorization", "")
    mode = entete.split(" ", 1)[0]
    if mode not in _ATTENDU or not getattr(conn, "cert", None):
        return
    info = client.identite()
    if not info:
        return
    realm = (info.get("authentication_realm") or {}).get("type", "")
    type_auth = info.get("authentication_type", "")
    if mode == "ApiKey":
        ecart = type_auth != "api_key" and realm != "_es_api_key"
    else:
        ecart = realm == "pki"
    if ecart:
        warn(f"esearch: Elasticsearch n'a pas retenu la {_ATTENDU[mode]} du "
             f"profil : la requête est authentifiée par le certificat client "
             f"(domaine {realm or type_auth or '?'}, utilisateur "
             f"« {info.get('username', '?')} »). La {_ATTENDU[mode]} est "
             "peut-être révoquée ou expirée — voir OPERATIONS.md § 7.")
