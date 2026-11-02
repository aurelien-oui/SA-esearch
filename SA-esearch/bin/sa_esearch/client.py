# -*- coding: utf-8 -*-
"""Client HTTP Elasticsearch : session, recherche et pagination.

Pagination (quand limit dépasse un batch de 10 000) :
  - pit    : Point-In-Time + search_after trié sur _shard_doc (recommandé,
             l'API scroll est dépréciée depuis ES 7.10)
  - scroll : ancienne API, conservée pour compat (vieux ES / OpenSearch)
  - auto   : tente PIT, bascule sur scroll si l'ouverture du PIT échoue
Toutes les requêtes (y compris les DELETE de cleanup) sont authentifiées,
et le cleanup est garanti par un finally même si Splunk interrompt la
recherche (GeneratorExit).
"""

import json
import re
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sa_esearch import APP_NAME, __version__
from sa_esearch.diagnostic import (
    precision_contexte,
    precision_refus,
    raison_es,
    raison_esql,
)
from sa_esearch.log import apercu

# Le nom d'index arrive de la SPL et était inséré BRUT dans l'URL : un
# utilisateur pouvait donc sortir de la forme /<index>/_search et viser un autre
# endpoint Elasticsearch — y compris destructif — avec les identifiants du
# profil. Exemple qui supprimait réellement des documents :
#   | esearch profile=p index="idx/_delete_by_query?conflicts=proceed&filter_path="
# On refuse tout ce qui permet de changer de chemin ou d'ajouter des paramètres,
# puis on encode le reste. Les caractères conservés couvrent les noms et motifs
# d'index légitimes (jokers, listes, dates, alias distants).
_INDEX_INTERDIT = re.compile(r"[/?#&%\\\s]")
_INDEX_SAFE = "*,-_.:+@"


def valide_index(index):
    """Nom ou motif d'index sûr à insérer dans une URL, ou ValueError."""
    if not index:
        return ""
    if _INDEX_INTERDIT.search(index) or ".." in index:
        raise ValueError(
            "index invalide : %s (les caractères / ? # & %% \\ et les espaces "
            "sont interdits — ils permettraient de viser un autre endpoint "
            "Elasticsearch)" % apercu(index))
    return quote(index, safe=_INDEX_SAFE)


# Avertissements d'Elasticsearch : en-tête HTTP Warning, `299 Elasticsearch-x.y.z
# "texte"`, plusieurs fusionnés par des virgules.
_AVERTISSEMENT = re.compile(r'\d{3} \S+ "((?:[^"\\]|\\.)*)"')


def avertissements(entete):
    """Textes des avertissements d'un en-tête Warning (liste, éventuellement vide)."""
    textes = []
    for m in _AVERTISSEMENT.findall(entete or ""):
        try:
            textes.append(json.loads(f'"{m}"'))
        except ValueError:
            textes.append(m)
    return textes


# Mode asynchrone (profil esql_mode=async) : Elasticsearch 8.13 minimum. Avant, et
# sur 7.x ou OpenSearch, POST /_query/async répond 400 « no handler found » ou
# « Invalid index name [_query] » (mesuré) — sans que la réponse dise si ES|QL
# synchrone, lui, existe (8.11 et 8.12 l'ont).
ASYNC_INDISPONIBLE = ("mode ES|QL asynchrone indisponible sur ce cluster : Elasticsearch 8.13 "
                      "minimum (ES|QL synchrone : 8.11 ; ni Elasticsearch 7.x ni OpenSearch) "
                      "— repasser le profil en mode synchrone (esql_mode)")

# ES|QL absent du cluster : Elasticsearch 7.x et ≤ 8.10, OpenSearch répondent
# 405 sur POST /_query (« Incorrect HTTP method for uri [/_query] »), mesuré.
ESQL_INDISPONIBLE = ("ES|QL indisponible sur ce cluster : Elasticsearch 8.11 minimum (8.14 "
                     "recommandé) ; ni Elasticsearch 7.x ni OpenSearch ne le proposent — "
                     "query= (Lucene) fonctionne sur tous")


# Taille d'une réponse d'Elasticsearch (1.25.1) : sans plafond, un serveur hostile
# (compromis, ou usurpé : HTTP en clair, verify_certs=false, CA compromise)
# épuisait la mémoire du processus qui lit — pour un profil, le proxy, partagé.
# Mesuré avec requests/urllib3 vendorisés : 298 Ko de gzip -> 300 Mo en mémoire ;
# en `gzip, gzip`, ~1 Ko suffit. Aucune version d'urllib3 ne plafonne la taille
# décompressée. Défaut 256 Mo : une page de
# 10 000 documents de 26 Ko en moyenne (journaux ordinaires : ~3 Mo la page).
MAX_REPONSE_MO = 256
# Lecture par morceaux de 16 Ko COMPRESSÉS : urllib3 décompresse chaque morceau
# d'un coup, le dépassement du plafond est donc borné à ~16 Mo (gzip simple, taux
# maximal ~1000). Un encodage chaîné échappe à toute borne de ce genre (un
# morceau peut valoir des Go) : il est refusé avant lecture.
_MORCEAU = 16 * 1024


class ReponseTropVolumineuse(RuntimeError):
    """Réponse au-delà du plafond, ou encodage refusé. Distincte de RuntimeError :
    le repli PIT -> scroll ne doit pas relancer une requête de même taille."""


def _tri_pit(payload):
    """Tri d'une page PIT : celui demandé (champ date), départagé par
    `_shard_doc` — qui garantit un `search_after` sans doublon ni trou même
    entre documents de même horodatage. Sans tri demandé : `_shard_doc` seul."""
    return list(payload.get("sort") or []) + [{"_shard_doc": "asc"}]


class ESClient:

    def __init__(self, conn, timeout=(5, 30), retry_count=3, backoff=0.5,
                 logger=None, warn=None):
        self.base = conn.es_host
        self.auth = conn.auth
        self.verify = conn.verify
        # Réponses demandées compressées : c'est là qu'est le volume (une page de
        # 10 000 documents : ~3 Mo en clair, ~0,3 Mo en gzip). Le cluster ne
        # compresse que si `http.compression` est active — désactivée par défaut
        # en HTTPS (OPERATIONS § 7bis).
        # User-Agent (1.25.0) : l'app et sa version, visibles dans les journaux et
        # l'audit d'Elasticsearch, à côté de X-Opaque-Id (l'utilisateur Splunk).
        self.headers = {"Content-Type": "application/json",
                        "Accept-Encoding": "gzip",
                        "User-Agent": f"{APP_NAME}/{__version__}"}
        self.headers.update(conn.headers)
        self.timeout = timeout
        self.log = logger
        self.warn = warn or (lambda msg: None)
        self.last_total = None          # hits.total de la 1re réponse
        self._motif = None              # index de la 1re page, le temps de la contrôler

        self._essais, self._attente = int(retry_count), float(backoff)
        self.max_reponse = int(getattr(conn, "max_response_mb", MAX_REPONSE_MO)) * 1024 * 1024
        self.session = self._session()
        if getattr(conn, "cert", None):          # mTLS : cert client pour toutes les requêtes
            self.session.cert = conn.cert
        # Reprises (1.26.0) : connexion impossible (rien n'est parti) et 429/503
        # (Elasticsearch momentanément saturé ou indisponible) seulement. JAMAIS
        # (read=0) quand la recherche est partie sans réponse — connexion fermée
        # pendant le traitement, délai de lecture dépassé — ni sur 500/502/504 :
        # elle a pu faire tomber le nœud, et la rejouer — derrière un répartiteur,
        # sur le nœud suivant — pourrait les abattre l'un après l'autre. Jusqu'en
        # 1.25.1, ces cas étaient rejoués jusqu'à retry_count fois (mesuré).
        # Même règle qu'ES|QL depuis la 1.22.0.
        retries = Retry(total=int(retry_count), connect=int(retry_count), read=0,
                        status=int(retry_count), backoff_factor=float(backoff),
                        status_forcelist=[429, 503],
                        allowed_methods=frozenset(["GET", "POST"]))
        self.session.mount("http://", HTTPAdapter(max_retries=retries))
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def _session(self):
        """Session requests dont TOUTE réponse est lue par _borne_reponse :
        corps en flux (`stream`), puis lu sous plafond par le hook `response`,
        avant que quiconque y touche (`.json()`, `.text` restent inchangés)."""
        s = requests.Session()
        # Rien de l'environnement de splunkd (1.26.0) : ni HTTP(S)_PROXY, ni
        # REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE (qui remplaçaient le bundle certifi
        # d'un profil vérifié sans ca_file), ni ~/.netrc (dont l'identifiant
        # partait vers un profil SANS authentification). Seule la configuration
        # visible dans la page Configuration s'applique.
        s.trust_env = False
        s.stream = True
        s.hooks["response"].append(self._borne_reponse)
        return s

    def _borne_reponse(self, resp, *args, **kwargs):
        encodage = [e.strip().lower() for e in
                    (resp.headers.get("Content-Encoding") or "").split(",") if e.strip()]
        if len(encodage) > 1 or (encodage and encodage[0] not in ("gzip", "deflate", "identity")):
            resp.close()
            raise ReponseTropVolumineuse(
                "réponse d'Elasticsearch refusée : encodage "
                f"« {apercu(resp.headers.get('Content-Encoding'), 60)} » (gzip seul attendu ; "
                "un encodage chaîné peut épuiser la mémoire du search head)")
        morceaux, lu = [], 0
        for morceau in resp.iter_content(_MORCEAU):
            lu += len(morceau)
            if lu > self.max_reponse:
                resp.close()
                raise ReponseTropVolumineuse(
                    f"réponse d'Elasticsearch trop volumineuse : plus de "
                    f"{self.max_reponse // (1024 * 1024)} Mo une fois décompressée "
                    "(réglage max_response_mb) — réduire la page (limit=, "
                    "_source_include=, KEEP en ES|QL) ou relever le réglage")
            morceaux.append(morceau)
        resp._content = b"".join(morceaux)
        return resp

    # ------------------------------------------------------------------
    # allow_redirects=False sur TOUTES les requêtes : un Elasticsearch légitime
    # ne répond pas par un 3xx sur ses endpoints d'API. Suivie, la redirection
    # faisait émettre au search head une requête vers une URL choisie par le
    # cluster — une SSRF aveugle (sonder des hôtes internes). requests retire
    # l'auth au changement d'hôte (pas de fuite de secret), mais la requête
    # partait quand même. Démontré avec un faux ES renvoyant 302. Le 3xx
    # est désormais rendu tel quel et traité en erreur HTTP par _check.
    def server_info(self):
        """Détection PASSIVE (log seulement) : version + distribution du
        cluster via `GET /`. N'échoue jamais la recherche ; ne change pas le
        comportement (le choix de pagination reste `auto` avec repli).
        Utile au diagnostic lors des montées de version ES/OpenSearch."""
        try:
            resp = self.session.get(self.base + "/", headers=self.headers,
                                    auth=self.auth, timeout=self.timeout,
                                    verify=self.verify, allow_redirects=False)
            v = resp.json().get("version", {})
            number = v.get("number", "?")
            distro = v.get("distribution", "elasticsearch")
            flavor = v.get("build_flavor", "")
            if self.log:
                self.log.info("esearch: cluster %s %s%s", distro, number,
                              f" ({flavor})" if flavor else "")
            return number, distro
        except Exception as e:
            if self.log:
                self.log.info("esearch: détection de version ES impossible (%s)", e)
            return None, None

    def identite(self):
        """`GET /_security/_authenticate` : identité RÉELLEMENT retenue par
        Elasticsearch (domaine, type d'authentification), ou None. N'échoue
        jamais : un cluster sans sécurité ou un droit manquant rend None."""
        try:
            resp = self.session.get(self.base + "/_security/_authenticate",
                                    headers=self.headers, auth=self.auth,
                                    timeout=self.timeout, verify=self.verify,
                                    allow_redirects=False)
            return resp.json() if resp.status_code == 200 else None
        except Exception as e:
            if self.log:
                self.log.info("esearch: identité ES non vérifiable (%s)", e.__class__.__name__)
            return None

    def types_champ(self, index, champ):
        """Types de `champ` dans les index de `index` (`_field_caps`, privilège
        `read`) : {type: {"indices": [...], "aggregatable": bool}}, le champ
        absent sous le type « unmapped » (1.27.0).

        `include_unmapped` (Elasticsearch 7.2+, OpenSearch) nomme les index où
        le champ manque ; refusé, on redemande sans lui (pas de « unmapped »).
        N'échoue jamais : None si la sonde échoue, et l'appelant garde le
        comportement d'avant la 1.27.0."""
        if not champ:
            return None
        sur = valide_index(index)
        url = (f"{self.base}{'/' + sur if sur else ''}/_field_caps"
               f"?fields={quote(champ, safe='')}")
        for suffixe in ("&include_unmapped=true", ""):
            try:
                data = self._get(url + suffixe)
                break
            except Exception as e:
                # Seul un 400 (paramètre inconnu d'un cluster ancien) justifie
                # la seconde demande ; toute autre panne la ferait échouer pareil.
                if suffixe and str(e).startswith("Elasticsearch HTTP 400"):
                    continue
                if self.log:
                    self.log.info("esearch: type du champ date non vérifiable (%s)",
                                  e.__class__.__name__)
                return None
        # Sans conflit de types, Elasticsearch ne nomme pas les index d'un type :
        # ce sont alors tous ceux de la réponse.
        tous = [i for i in data.get("indices") or [] if isinstance(i, str)]
        caps = (data.get("fields") or {}).get(champ) or {}
        return {t: {"indices": [i for i in c.get("indices") or tous if isinstance(i, str)],
                    "aggregatable": bool(c.get("aggregatable"))}
                for t, c in caps.items() if isinstance(c, dict)}

    def close(self):
        self.session.close()
        if getattr(self, "_session_esql", None):
            self._session_esql.close()

    # ------------------------------------------------------------------
    def _session_requetes_esql(self):
        """Session des appels ES|QL : SANS nouvelle tentative sur délai de
        lecture — une requête ES|QL coûteuse coupée par le délai est annulée par
        ES (mesuré), la rejouer en relancerait le coût. Nouvelles tentatives
        seulement sur connexion impossible et sur 503 (cluster momentanément
        indisponible) ; pas sur 429 : en ES|QL, c'est d'ordinaire le disjoncteur
        mémoire, qu'une nouvelle tentative ne ferait que déclencher à nouveau."""
        if getattr(self, "_session_esql", None) is None:
            s = self._session()
            if getattr(self.session, "cert", None):
                s.cert = self.session.cert
            essais = Retry(total=self._essais, connect=self._essais, read=0,
                           status=self._essais, backoff_factor=self._attente,
                           status_forcelist=[503],
                           allowed_methods=frozenset(["POST", "GET", "DELETE"]))
            s.mount("http://", HTTPAdapter(max_retries=essais))
            s.mount("https://", HTTPAdapter(max_retries=essais))
            self._session_esql = s
        return self._session_esql

    def _appel_esql(self, methode, chemin, corps=None, tri_ajoute=None, asynchrone=False):
        try:
            resp = self._session_requetes_esql().request(
                methode, f"{self.base}{chemin}",
                data=None if corps is None else json.dumps(corps).encode("utf-8"),
                headers=self.headers, auth=self.auth, timeout=self.timeout,
                verify=self.verify, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise self._marque(e)
        if resp.status_code == 405 and not asynchrone:
            raise RuntimeError(ESQL_INDISPONIBLE)
        if asynchrone and resp.status_code in (400, 404, 405) and (
                "no handler found for uri [/_query/async" in resp.text
                or "Invalid index name [_query]" in resp.text
                or "Incorrect HTTP method for uri [/_query" in resp.text):
            raise RuntimeError(ASYNC_INDISPONIBLE)
        if asynchrone and resp.status_code == 404:
            raise RuntimeError("requête ES|QL asynchrone introuvable : expirée (réglage "
                               "esql_async_keep_alive) ou déjà supprimée")
        if resp.status_code >= 300:
            try:
                corps_err = resp.json()
            except ValueError:
                corps_err = None
            raise RuntimeError(f"Elasticsearch HTTP {resp.status_code}: "
                               + raison_esql(corps_err, resp.text, tri_ajoute)
                               + precision_refus(self.headers, resp.status_code,
                                                 getattr(self.session, "cert", None)))
        if self.log:
            self.log.info("esearch: %s %s%s (ES|QL)", methode, self.base, chemin.split("?")[0])
        return self._json_reponse(resp), avertissements(resp.headers.get("Warning"))

    def esql(self, corps, tri_ajoute=None):
        """POST /_query : (réponse, avertissements d'Elasticsearch)."""
        return self._appel_esql("POST", "/_query", corps, tri_ajoute)

    def esql_async(self, corps, attente, conservation, tri_ajoute=None):
        """POST /_query/async (Elasticsearch 8.13+). Une requête finie dans
        `attente` rend son résultat sans rien conserver (keep_on_completion
        false) ; sinon, un `id`, et le résultat est gardé `conservation`."""
        return self._appel_esql("POST", "/_query/async",
                                dict(corps, wait_for_completion_timeout=attente,
                                     keep_alive=conservation, keep_on_completion=False),
                                tri_ajoute, asynchrone=True)

    def esql_suite(self, ident, attente, tri_ajoute=None):
        """GET /_query/async/<id> : attend au plus `attente` la fin de la requête."""
        return self._appel_esql("GET", f"/_query/async/{quote(ident, safe='')}"
                                f"?wait_for_completion_timeout={quote(attente)}",
                                tri_ajoute=tri_ajoute, asynchrone=True)

    def esql_annule(self, ident):
        """DELETE /_query/async/<id> : annule la requête si elle tourne (mesuré,
        tâches arrêtées en moins d'une seconde) et libère son résultat.
        Best-effort : à défaut, il expire au bout de esql_async_keep_alive."""
        try:
            self._session_requetes_esql().delete(
                f"{self.base}/_query/async/{quote(ident, safe='')}", headers=self.headers,
                auth=self.auth, timeout=self.timeout, verify=self.verify, allow_redirects=False)
        except Exception as e:
            if self.log:
                self.log.warning("esearch: annulation ES|QL asynchrone en échec : %s", e)

    # ------------------------------------------------------------------
    def list_indices(self, pattern="*"):
        """Cibles interrogeables correspondant à `pattern` : index concrets,
        alias et data streams, triés et dédoublonnés.

        `_resolve/index` (ES 7.9+) renvoie les trois familles en un appel ;
        repli sur `_cat/indices` (index concrets seulement) pour les clusters
        plus anciens ou les distributions qui ne l'exposent pas — même logique
        de repli que la pagination PIT -> scroll.
        """
        pattern = pattern or "*"
        try:
            data = self._get(f"{self.base}/_resolve/index/{valide_index(pattern)}")
            names = [e.get("name") for key in ("indices", "aliases", "data_streams")
                     for e in data.get(key, []) if e.get("name")]
            if self.log:
                self.log.info("esindices: %d cible(s) via _resolve/index", len(names))
        except (RuntimeError, requests.exceptions.RequestException) as e:
            if self.log:
                self.log.info("esindices: _resolve indisponible (%s), repli _cat/indices", e)
            data = self._get(f"{self.base}/_cat/indices/"
                             f"{valide_index(pattern)}?format=json&h=index")
            names = [e.get("index") for e in data if e.get("index")]
        # Les index système (.security, .kibana...) ne sont pas des cibles utiles
        return sorted({n for n in names if not n.startswith(".")})

    def _marque(self, exc):
        """Joint à une panne réseau le fait qu'un certificat client a été
        présenté ou non : l'alerte TLS d'Elasticsearch ne suffit pas à le dire
        (ES 8 répond « handshake failure » à un certificat absent, ES 7 « bad
        certificate », la même alerte qu'à un certificat refusé)."""
        exc.esearch_cert = bool(getattr(self.session, "cert", None))
        return exc

    def _get(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, auth=self.auth,
                                    timeout=self.timeout, verify=self.verify,
                                    allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise self._marque(e)
        self._check(resp)
        return self._json_reponse(resp)

    def _post(self, url, payload):
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        try:
            resp = self.session.post(url, data=body, headers=self.headers, auth=self.auth,
                                     timeout=self.timeout, verify=self.verify,
                                     allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise self._marque(e)
        self._check(resp)
        return self._json_reponse(resp)

    def _delete(self, url, payload):
        # cleanup best-effort : authentifié, mais une erreur ne casse pas la recherche
        try:
            self.session.delete(url, json=payload, headers=self.headers,
                                auth=self.auth, timeout=self.timeout,
                                verify=self.verify, allow_redirects=False)
        except Exception as e:
            if self.log:
                self.log.warning("esearch: échec cleanup %s: %s", url, e)

    @staticmethod
    def _json_reponse(resp):
        """Corps JSON de la réponse, ou RuntimeError clair.

        Un ES (ou un intermédiaire) qui renvoie autre chose que du JSON — page
        d'erreur HTML d'un proxy, réponse tronquée, contenu forgé — faisait
        remonter le message BRUT du parseur (« Expecting property name… »), qui
        ressemble à une erreur de la requête de l'utilisateur alors que la faute
        est côté serveur. On le nomme pour ce qu'il est."""
        try:
            return resp.json()
        except ValueError:
            apercu = resp.text[:120].replace("\n", " ")
            raise RuntimeError(
                "réponse Elasticsearch illisible (JSON attendu) : %r" % apercu)

    def _check(self, resp):
        if resp.status_code >= 300:
            try:
                corps = resp.json()
            except ValueError:
                corps = None
            reason = raison_es(corps, resp.text)
            # Point unique où un refus est décodé : la précision (clé API au
            # mauvais format, révoquée…) y est ajoutée pour tous les appels.
            raise RuntimeError(f"Elasticsearch HTTP {resp.status_code}: {reason}"
                               + precision_refus(self.headers, resp.status_code,
                                                 getattr(self.session, "cert", None))
                               + precision_contexte(resp.status_code, str(reason)))

    def _track(self, data):
        shards = data.get("_shards", {})
        # Motif sans aucun index derrière : Elasticsearch répond 200, 0 shard,
        # 0 résultat — qu'il n'existe pas OU que l'identité du profil n'y ait pas
        # droit (un joker filtre en silence ce qui n'est pas autorisé ; seul un
        # nom explicite refusé vaut 403). Mesuré sur un cluster sécurisé. Sans ce
        # message, l'analyste lit « 0 résultat » comme « rien ne s'est passé ».
        # Contrôlé sur la 1re page seulement. Un motif mixte (autorisé + refusé)
        # garde des shards : indétectable ici.
        if self._motif is not None:
            if shards.get("total") == 0:
                self.warn(f"esearch: aucun index ne correspond à '{self._motif}' — il "
                          "n'existe pas, ou l'identité Elasticsearch du profil n'y a "
                          "pas accès")
            self._motif = None
        if shards.get("failed", 0):
            self.warn(f"esearch: résultats partiels — {shards['failed']}"
                      f"/{shards.get('total')} shard(s) en échec côté Elasticsearch")
        total = data.get("hits", {}).get("total")
        if self.last_total is None and isinstance(total, dict):
            self.last_total = total

    # ------------------------------------------------------------------
    def url_recherche(self, index):
        """URL de la recherche sur `index` (celle de la première page)."""
        sur = valide_index(index)
        return f"{self.base}/{sur}/_search" if sur else f"{self.base}/_search"

    def search_page(self, index, payload, size, cursor=None, pagination="auto",
                    keep_alive="2m", unique=False):
        """UNE page de hits, plus le curseur permettant d'obtenir la suivante.

        Primitive unique de pagination : la commande l'utilise directement
        (profils sans secret) et le proxy REST l'utilise pour le compte des
        profils authentifiés. Le curseur est un dict de types JSON, donc
        SÉRIALISABLE : il peut transiter entre les deux, ce qui permet aux deux
        chemins de partager exactement la même boucle.

        Curseur : {"pit": <id>, "after": [...]} ou {"scroll": <id>}.
        Retourne (hits, curseur_suivant) ; le curseur vaut None sur la dernière
        page, et le contexte Elasticsearch est alors déjà libéré.
        """
        sur = valide_index(index)
        index_path = f"/{sur}" if sur else ""
        p = dict(payload, size=size)
        self._motif = (index or "*") if cursor is None else None

        # Cas majoritaire : tout tient dans une page. Recherche simple, donc
        # AUCUN contexte de pagination ouvert côté Elasticsearch.
        if cursor is None and unique:
            data = self._post(f"{self.base}{index_path}/_search", p)
            self._track(data)
            if self.log:
                self.log.info("esearch: POST %s/_search (une page, size=%d)",
                              self.base + index_path, size)
            return data.get("hits", {}).get("hits", [])[:size], None

        if cursor:
            if cursor.get("pit"):
                q = dict(p, pit={"id": cursor["pit"], "keep_alive": keep_alive},
                         sort=_tri_pit(p), search_after=cursor["after"])
                return self._page_pit(self._post(f"{self.base}/_search", q),
                                      cursor["pit"], size)
            return self._page_scroll(
                self._post(f"{self.base}/_search/scroll",
                           {"scroll": keep_alive, "scroll_id": cursor["scroll"]}),
                cursor["scroll"], size)

        # ---- première page ----
        if pagination not in ("auto", "pit"):
            return self._scroll_ouvrir(index_path, p, keep_alive)

        # Ouverture PIT + première page AVANT tout retour : une incompatibilité
        # de version (PIT absent, tri _shard_doc non supporté sur ES 7.10/7.11
        # ou OpenSearch) est donc détectée ici et bascule proprement sur scroll.
        pit_id = None
        try:
            pit_id = self._post(
                f"{self.base}{index_path or '/*'}/_pit?keep_alive={keep_alive}", None)["id"]
            q = dict(p, pit={"id": pit_id, "keep_alive": keep_alive},
                     sort=_tri_pit(p))
            data = self._post(f"{self.base}/_search", q)
        except (RuntimeError, requests.exceptions.RequestException,
                KeyError, TypeError) as e:
            # KeyError/TypeError : réponse de forme inattendue (distribution
            # tierce, proxy interposé) — on bascule au lieu de planter.
            if pit_id:
                self._delete(f"{self.base}/_pit", {"id": pit_id})
            if pagination == "pit" or isinstance(e, ReponseTropVolumineuse):
                raise
            if self.log:
                self.log.info("esearch: PIT indisponible (%s), repli scroll", e)
            return self._scroll_ouvrir(index_path, p, keep_alive)
        return self._page_pit(data, pit_id, size)

    def close_cursor(self, cursor):
        """Libère le contexte Elasticsearch d'un curseur abandonné (limite
        atteinte, recherche interrompue). Best-effort : à défaut, le contexte
        expire de lui-même au bout de keep_alive."""
        if not cursor:
            return
        if cursor.get("pit"):
            self._delete(f"{self.base}/_pit", {"id": cursor["pit"]})
        elif cursor.get("scroll"):
            self._delete(f"{self.base}/_search/scroll",
                         {"scroll_id": [cursor["scroll"]]})

    # ------------------------------------------------------------------
    def _scroll_ouvrir(self, index_path, payload, keep_alive):
        # Un scroll exige le compte exact : un seuil ou false y est refusé
        # (« disabling [track_total_hits] is not allowed in a scroll context »,
        # mesuré sur ES 7.17 et 8.17).
        if "track_total_hits" in payload:
            payload = dict(payload, track_total_hits=True)
        data = self._post(f"{self.base}{index_path}/_search?scroll={keep_alive}", payload)
        if self.log:
            self.log.info("esearch: pagination scroll (batch=%d)", payload.get("size", 0))
        return self._page_scroll(data, data.get("_scroll_id"), payload.get("size"))

    def _page_pit(self, data, pit_id, size):
        self._track(data)
        hits = data.get("hits", {}).get("hits", [])
        pit_id = data.get("pit_id", pit_id)
        # une page incomplète signale la fin : on libère tout de suite
        if len(hits) < size or not hits:
            self._delete(f"{self.base}/_pit", {"id": pit_id})
            return hits, None
        return hits, {"pit": pit_id, "after": hits[-1].get("sort")}

    def _page_scroll(self, data, scroll_id, size):
        self._track(data)
        hits = data.get("hits", {}).get("hits", [])
        scroll_id = data.get("_scroll_id", scroll_id)
        if len(hits) < size or not hits:
            if scroll_id:
                self._delete(f"{self.base}/_search/scroll", {"scroll_id": [scroll_id]})
            return hits, None
        return hits, {"scroll": scroll_id}
