# esearch for Elasticsearch (SA-esearch)

Commande SPL `| esearch` : interroge Elasticsearch en direct (sans indexation)
et retourne les documents comme événements Splunk (`_time`, `_raw`, champs
aplatis, multivaleurs).

## Documentation

| Pour… | Document |
|---|---|
| **Utiliser** `\| esearch` (analyste) | ce README (ci-dessous) + `README/esearch.conf.spec` |
| **Administrer / exploiter** (install, secrets, RBAC, mTLS, SHC, matérialisation, dépannage) | [OPERATIONS.md](OPERATIONS.md) |
| **Compatibilité des versions** (Splunk / ES / OpenSearch) | [COMPATIBILITY.md](COMPATIBILITY.md) |

## Usage recommandé (production) : profils + secrets chiffrés

1. Déclarer un profil dans `local/esearch.conf` :

Un `#` ne commente qu'en **début de ligne** : placé après une valeur, il en fait
partie (comme partout dans les `.conf` de Splunk).

```ini
[profile:prod]
es_host = https://es.example.com:9200
verify_certs = true
# certificats sous $SPLUNK_HOME/etc/auth/esearch/, jamais dans le répertoire de l'app
ca_file = $SPLUNK_HOME/etc/auth/esearch/ca.pem
# auth_type : none | basic | apikey
auth_type = apikey
timefield = @timestamp
# qui peut l'utiliser : admin | * | rôle1,rôle2 (OPERATIONS.md § 5)
allowed_roles = *
```

2. Stocker le secret (chiffré par Splunk, jamais dans un .conf) :

```bash
curl -k -u admin https://localhost:8089/servicesNS/nobody/SA-esearch/storage/passwords \
     -d name=apikey -d realm=esearch:prod -d password='<LA_CLE>'
# auth_type=basic : -d name=<username> et renseigner username= dans le profil
```

3. Chercher :

```
| esearch profile=prod index="logs-*" query="status:500 AND host:web-*" limit=1000
| esearch index="logs-*" query="status:500"      (profil par défaut de l'utilisateur)
| esprofiles                                     (profils qui vous sont ouverts)
```

Chaque profil peut être réservé à des rôles Splunk (`allowed_roles`). Sans
`profile=`, la recherche prend le premier profil autorisé dans l'ordre fixé par
l'administrateur, et l'annonce (OPERATIONS.md § 5).

Le time picker Splunk est appliqué côté ES (filtre `range` sur `timefield`),
avec la sémantique de Splunk : `earliest` inclus, `latest` **exclu**, à la
milliseconde.

## Mode ad hoc (environnements de test uniquement)

```
| esearch es_host="http://127.0.0.1:9200" index="logs-*" query="*" limit=100
```

À désactiver en production : `[settings] allow_adhoc_host = false`.
Les options `user=`/`password=`/`apikey=` en SPL sont **dépréciées** (visibles
dans l'historique et `_audit`) — un warning est émis.

## Options

| Option | Défaut | Description |
|---|---|---|
| profile | profil par défaut | profil de connexion déclaré dans esearch.conf ; sans lui (ni es_host=), le premier profil autorisé dans l'ordre de priorité |
| es_host | — | URL ES ad hoc (si allow_adhoc_host) |
| index | tous | index/pattern ES (sans objet avec `esql=` : l'index se choisit dans `FROM`) |
| query | requis, sauf avec `esql=` | requête Lucene (query_string). Bornée par défaut à 1 Mio et 30 niveaux de parenthèses (réglables : `query_max_bytes`, `query_max_depth`) ; le plafond de clauses du cluster s'applique aussi (OPERATIONS § 10.13) |
| esql | — | requête **ES\|QL** (Elasticsearch 8.11 minimum), à la place de `query=` : envoyée telle quelle, période et lookups appliqués à côté. Chaînes entre guillemets doubles (`\"…\"` en SPL). Voir « Requêtes ES\|QL » |
| limit | 100 | nb max d'événements (plafonné par max_limit) |
| timefield | @timestamp | champ date (filtre temporel + _time) |
| sort | none | tri sur le champ date : `none` (ordre de stockage), `asc` (du plus ancien au plus récent), `desc` (du plus récent au plus ancien). Voir ci-dessous |
| earliest / latest | sélecteur de temps | période écrite dans la commande, **prioritaire sur le sélecteur** : relatif Splunk (`-1h@h`, `@d`, `now`), époque, ISO 8601 ou `MM/JJ/AAAA:HH:MM:SS`. Voir « Période dans la commande » |
| es_metadata | false | `true` : ajoute à chaque événement `es_index` et `es_id` (index et identifiant du document). Lucene seulement ; en ES\|QL, `METADATA _index, _id` |
| _source_include / _source_exclude | — | filtrage des champs, séparés par virgules (motifs `*` admis). Le champ date est toujours ramené pour poser `_time`, puis masqué s'il n'est pas demandé |
| retry_count / backoff_base | 3 / 0.5 | reprises : connexion impossible, réponses 429 et 503 seulement — jamais une recherche partie sans réponse (délai dépassé, nœud tombé), ni 500/502/504 |
| timeout_connect / timeout_read | 5 / 30 | timeouts (s) |
| debug | false | `true` : mode debug de **cette** recherche — la requête réellement envoyée à Elasticsearch (méthode, URL, corps JSON) est montrée en warning (sauf recherche planifiée) et journalisée ; selon `[settings] debug_search_scope`, seule cette requête (`query`, défaut) ou toutes les lignes de la recherche (`all`). Voir « Exploitation » |
| debug_tag | — | facultatif, avec `debug=true` : nom libre ajouté au marqueur (`[debug sid=<sid> debug_tag=<nom>]`) pour retrouver la recherche dans le journal. 1 à 64 caractères : lettres, chiffres, `_ . : -`. Vide = pas d'étiquette |
| lookup_include | — | lookups Splunk (CSV ou définition, KV store compris) dont les lignes **restreignent** la recherche, séparées par des virgules. Voir « Filtres par lookup » |
| lookup_exclude | — | lookups dont les lignes sont **retirées** de la recherche |
| inclusion_type | and | `and` : un document doit correspondre à chaque lookup d'inclusion ; `or` : à l'une d'elles |
| exclusion_type | and | `and` : est retiré tout document présent dans l'une des lookups d'exclusion ; `or` : seulement s'il est dans toutes |
| lookup_fields_keep | toutes | colonnes de lookup utilisées comme filtre, séparées par des virgules |
| lookup_fields_ignore | — | colonnes écartées, motifs `*` admis ; s'ajoute au réglage global `lookup_fields_ignore` et aux colonnes `_*`, toujours écartées |
| lookup_stage | source | avec `esql=` seulement : `source` applique les lookups aux documents, avant la requête (comme `query=`) ; `result` les insère en fin de requête, sur les colonnes du résultat. Les marqueurs `$lookup$`, `$lookup_include$`, `$lookup_exclude$` les placent à un endroit précis. Voir « Lookups dans une requête ES\|QL » |
| lookup_mode | lucene | `lucene` : lookups traduites en Lucene ajouté à `query=` ; `terms` : un filtre Elasticsearch `terms` par lookup, pour les grandes listes (jusqu'à 65 536 valeurs par lookup). Voir « Mode terms » |

Réglages globaux (`esearch.conf [settings]`), rangés comme les cartes de la
page Configuration :

- résultats et pagination : `max_limit` (défaut 50000), `default_limit`,
  `pagination`, `page_keep_alive` ;
- protections du cluster et du search head : `query_max_bytes`,
  `query_max_depth` (bornes de `query=`), `esql_max_bytes`, `esql_max_depth`,
  `esql_lookup_values_max`, `max_response_mb` (plafond d'une réponse
  d'Elasticsearch, 256 Mo décompressés), `max_timeout_read` ;
- ES|QL : `esql_hide_keyword`, `esql_async_wait`, `esql_async_keep_alive`,
  `esql_async_max` ;
- lookups et données : `lookup_fields_ignore`, `sanitize_metadata_fields` ;
- mode ad hoc : `allow_adhoc_host`, `verify_certs` (TLS du mode ad hoc
  seulement ; chaque profil a le sien) ;
- journal et debug : `log_level`, `debug_search_scope`, `debug_terms_max`,
  `detect_version` ;
- `profile_order` (ordre des profils, profil par défaut), réglé depuis l'onglet
  Profils.

Rôle et défaut de chacun : page *Aide administrateur* ; spec complète :
`README/esearch.conf.spec`.

## Filtres par lookup : `lookup_include=` / `lookup_exclude=`

```
| esearch index="logs-*" query="action:query" lookup_include="inclusion_lookup.csv" lookup_exclude="exclusion_lookup_kvs"
```

Avec `inclusion_lookup.csv` = (uc1, user1), (uc1, user2) et `exclusion_lookup_kvs`
= (uc1, user2), (uc2, user2) sur les colonnes `host` et `user`, la requête
envoyée à Elasticsearch est :

```
(action:query) AND ((host:"uc1" AND user:"user1") OR (host:"uc1" AND user:"user2")) AND NOT ((host:"uc1" AND user:"user2") OR (host:"uc2" AND user:"user2"))
```

- **Une lookup** devient le OU de ses lignes, chaque ligne le ET de ses
  colonnes renseignées (une cellule vide n'impose rien) ; une valeur
  multiple, le OU de ses valeurs.
- **Plusieurs lookups** (`lookup_include="a.csv, b.csv"`) : par défaut, **tout
  en ET**. En inclusion, un document doit correspondre à chacune
  (`inclusion_type=or` : à l'une d'elles). En exclusion, est retiré tout
  document présent dans l'une d'elles (`exclusion_type=or` : seulement s'il est
  dans toutes). L'opérateur relie les conditions « être dans L » et « ne pas
  être dans L » : `(NOT L1) AND (NOT L2)`, ou `(NOT L1) OR (NOT L2)`.
- **Valeurs exactes**, sauf le joker `*` : chaque valeur est envoyée comme une
  phrase échappée, et ni un espace, ni un guillemet, ni `OR` ou `)` dans une
  lookup ne change la requête. `*` est un joker (`uc*`) ; `\*` le neutralise
  (étoile littérale) ; `\\` donne une barre oblique inverse littérale devant un
  joker (`DOMAINE\\*`) ; toute autre barre oblique est littérale
  (`DOMAINE\compte`) ; `?` est littéral. Détail : OPERATIONS § 10.14.
- **Colonnes** : toutes, sauf `_*` (internes à Splunk, dont le `_key` du KV
  store), le réglage global `lookup_fields_ignore` (page *Configuration*) et
  l'option `lookup_fields_ignore=` ; `lookup_fields_keep=` restreint d'abord.
  Une colonne en trop (un commentaire) est un filtre comme les autres : elle
  empêche toute correspondance.
- **Droits** : les lookups sont lues avec les droits de l'utilisateur, dans
  l'app où il cherche, comme par `| inputlookup` ; toutes en une seule
  recherche Splunk (`inputlookup append=t`).
- **Lookup vide** : en inclusion `and`, aucun résultat possible, Elasticsearch
  n'est pas interrogé (avertissement) ; en exclusion, sans effet. **Lookup
  absente ou interdite** : la recherche échoue en la nommant, aucun filtre
  partiel.
- `debug=true` journalise la requête **réellement envoyée**, lookups résolues.
  Les bornes de la requête (1 Mio, plafond de clauses du cluster) s'appliquent
  au résultat : au-delà d'environ 4 600 valeurs, Elasticsearch refuse (« trop
  de clauses ») — pour les grandes listes, le mode `terms` ci-dessous.

### Mode terms : `lookup_mode=terms`, pour les grandes listes

```
| esearch index="logs-*" query="action:query" lookup_include="hosts.csv, comptes.csv" lookup_exclude="faux_positifs_kv" lookup_mode=terms
```

Chaque lookup devient un **filtre `terms`** d'Elasticsearch sur sa colonne, à
côté de `query=` au lieu de s'y ajouter en Lucene. Un filtre `terms` compte pour
**une seule clause** : une lookup peut porter jusqu'à **65 536 valeurs**
(`index.max_terms_count`, défaut d'Elasticsearch, mesuré) au lieu d'environ
4 600 termes en Lucene. La requête envoyée pour l'exemple :

```
{"bool": {"must":     [{"query_string": {"query": "action:query"}}],
          "filter":   [{"terms": {"host": [...]}}, {"terms": {"user": [...]}}],
          "must_not": [{"terms": {"user": [...]}}]}}
```

**Compatible, vérifié** (mêmes résultats que le mode Lucene, et que le
résultat calculé à part, pour les quatre combinaisons) :

- **plusieurs lookups d'inclusion et d'exclusion**, mêmes règles qu'en Lucene :
  `inclusion_type=and` (défaut, chaque filtre s'applique) ou `or` (l'un d'eux
  suffit) ; `exclusion_type=and` (défaut, est retiré ce qui est dans l'une) ou
  `or` (seulement ce qui est dans toutes) ;
- **`query=`** : elle reste entière (`must`) et les lookups s'y ajoutent en
  filtres ; `query="*"` pour ne filtrer que par les lookups ;
- lookups CSV et KV store, droits de l'utilisateur, lookups vides, réglage
  global et options `lookup_fields_keep` / `lookup_fields_ignore` : comme en
  Lucene.

**Contraintes** (refusées en le disant) :

- **une colonne par lookup** : `lookup_fields_keep` / `lookup_fields_ignore`
  pour la choisir. Une lookup à plusieurs colonnes dont chaque ligne est une
  combinaison (hôte ET compte) reste en mode Lucene ;
- **pas de joker** : `*` est refusé (`\*` reste une étoile littérale) ;
- **valeur exacte, non analysée** : à réserver aux champs `keyword`. Mesuré
  sur un champ `text` : la valeur entière « GET request processed id=0 » ne
  trouve rien (la phrase Lucene trouve le document), « GET » non plus ; seul
  le mot tel qu'Elasticsearch l'a découpé et mis en minuscules (« get »)
  correspond ;
- au-delà de 65 536 valeurs dans une lookup, Elasticsearch refuse (message
  qui le dit) ; la structure des filtres est bornée à 32 Mio.

`debug=true` journalise `query=` puis les filtres (`esearch: filtres terms=…`,
bornés à 10 000 caractères).

| | `lookup_mode=lucene` (défaut) | `lookup_mode=terms` |
|---|---|---|
| Taille | ≈ 4 600 valeurs au total (plafond de clauses) | 65 536 valeurs par lookup |
| Colonnes | plusieurs (une ligne = ET de ses colonnes) | une par lookup |
| Jokers `*` | oui | non |
| Champs `text` | phrase analysée | valeur exacte (`keyword`) |
| Journal DEBUG | une chaîne Lucene | `query=` + filtres JSON |

## Requêtes ES|QL : `esql=`

Pour **agréger côté Elasticsearch** et ne ramener que le résultat, plutôt que
des millions de documents à compter dans Splunk :

```spl
| esearch profile=prod esql="FROM logs-* | WHERE http.response.status_code >= 500 | STATS erreurs = COUNT(*) BY host.name | SORT erreurs DESC"
| esearch profile=prod esql="FROM logs-* | WHERE host.name == \"web-01\" | KEEP @timestamp, message" limit=1000 sort=desc
```

**Ce que l'app ajoute à la requête, et rien d'autre** (visible avec
`debug=true`, qui montre la requête réellement envoyée) :
- en fin : `| SORT <champ de temps> ASC|DESC` **seulement si** `sort=asc|desc`
  est précisé, puis `| LIMIT n+1` (`n` = `limit=`, plafonné par `max_limit`) ;
- à côté, dans `filter` (appliqué aux documents avant la requête) : la
  **période du sélecteur** (champ `timefield`, comme pour `query=`) et les
  **lookups** `lookup_include=` / `lookup_exclude=`, avec exactement leur
  sémantique de `query=` (modes `lucene` et `terms`) — ou, au choix, insérés
  dans la requête (ci-dessous). `earliest=` / `latest=` remplacent la
  période du sélecteur, comme pour `query=`.

**Guillemets.** En ES|QL, une chaîne s'écrit entre guillemets doubles ; dans
une recherche SPL, chacun s'écrit `\"`. Une apostrophe hors chaîne est refusée
avant envoi, avec sa position. Une apostrophe *dans* une chaîne est permise :
`WHERE m == \"oui s'il te plait\"`. Ce que reçoit la commande, mesuré (vrai
aussi pour `query=`) :

| Écrit en SPL, dans `esql="…"` | Reçu |
|---|---|
| `\"` | `"` |
| `\\` | `\` (un antislash dans une chaîne ES\|QL s'écrit donc `\\\\` en SPL) |
| `` ` ``, `[ ]`, `\|`, `$` | intacts (en tableau de bord, `$x$` reste un token) |

**Résultats.**
- **Une seule requête, pas de pagination** : Elasticsearch rend au plus
  **10 000 lignes** (réglage du cluster `esql.query.result_truncation_max_size`)
  et coupe **sans le dire** ; l'app l'annonce, ainsi que la coupe par `limit=`.
  Pour des volumes, agréger (`STATS`) ou utiliser `query=`, paginé sans perte.
- `_time` vient de la colonne du champ de temps si elle est encore là en fin de
  requête ; après un `STATS`, il n'y a pas de `_time` (tableau Splunk).
- Colonnes `METADATA` (`FROM … METADATA _index, _id`) : rendues `es_index`,
  `es_id`, `es_version`… (Splunk cacherait `_index` et `_id`).
- Une colonne `X.keyword` qui double une colonne `X` (champ texte à
  sous-champ keyword) est **masquée**, comme dans Discover de Kibana ; réglage
  `esql_hide_keyword`, surchargeable par profil.
- Champs multivalués : rendus en champs multivalués Splunk, mais ES|QL les rend
  **triés et dédoublonnés** (`query=` garde l'ordre et les doublons du document).
- Champs `nested` : **jamais rendus** par ES|QL (aucune version, colonne
  absente) ; `query=` les rend.
- Types que la version du cluster ne sait pas lire (`date_nanos` avant 8.17,
  `flattened` avant 9.5) : valeurs vides, signalées.

**Bornes** (carte « Protections du cluster et du search head » des réglages, contrôlées avant tout envoi par la
commande et par le proxy) : 64 Ko (`esql_max_bytes`, ajouts de l'app compris)
et 100 niveaux de parenthèses (`esql_max_depth`). Mesuré : une requête ES|QL a
arrêté un nœud Elasticsearch dès 10 Ko (OPERATIONS § 10.15).

**Mode asynchrone, par profil** (`esql_mode = async`, page
Configuration) : pour les requêtes plus longues que le délai de lecture
(`max_timeout_read`). La requête part en `POST /_query/async`. La commande
interroge ensuite le proxy jusqu'à la fin, chaque appel attendant au plus
`esql_async_wait` (10 s). Au-delà de `esql_async_max` (1 800 s), la requête est
**annulée** côté Elasticsearch et la recherche le dit. L'identifiant de la
requête ne circule que dans un jeton signé par le proxy, lié à l'utilisateur et
au profil. Elasticsearch **8.13** minimum : avant, refus explicite (« repasser le
profil en mode synchrone »). Une recherche arrêtée dans Splunk sans annulation
laisse son résultat expirer au bout de `esql_async_keep_alive` (5 min).

**Page Query** : choix du langage, Lucene ou ES|QL. Le champ « Requête
ES|QL » remplace alors Index et Requête, et les guillemets s'y tapent tels
quels. Changer de langage ne relance rien avant « Soumettre ». Le tableau
ES|QL n'affiche pas `_raw`, qui répéterait chaque ligne en JSON.

**Aide dans la barre de recherche** (`searchbnf.conf`) : en tapant
`| esearch`, `| esindices` ou `| esprofiles`, Splunk affiche la description de
la commande et un exemple ; toutes les options y figurent.

**Pages d'aide de l'app** :
- **Aide** (tous) : principe, chaque argument de `| esearch`, profils, limites,
  debug ;
- **Aide administrateur** (lecteurs de la page Configuration seulement) : chaque
  champ de profil et chaque réglage de la page Configuration, aides au dépannage
  (que baisser si un nœud tombe…), versions d'Elasticsearch et de Splunk.

**Versions** : ES|QL existe à partir d'**Elasticsearch 8.11** (8.14 :
version stable d'Elasticsearch). Ni Elasticsearch 7.x ni OpenSearch ne le
proposent : la recherche le dit (« ES|QL indisponible sur ce cluster… »), sans
interroger la version du cluster. Détail par version : COMPATIBILITY.md.

**Erreurs** : syntaxe et vérification d'ES|QL rendues lisibles (ligne et
colonne de la faute) ; `sort=` sur une colonne que la requête a retirée (`KEEP`,
`STATS`) ; disjoncteur mémoire d'Elasticsearch ; profondeur d'expression
plafonnée par Elasticsearch (400 : remplacer une suite de `OR` par `IN`). Les
avertissements d'Elasticsearch (conversion en échec…) sont relayés.

### Lookups dans une requête ES|QL

Par défaut, les lookups filtrent les **documents**, avant la requête, avec
exactement leur sémantique de `query=`. Pour filtrer le **résultat** de la
requête (après un `STATS`, un `EVAL`…), deux moyens :

```spl
| esearch profile=prod esql="FROM logs-* | STATS n = COUNT(*) BY host.name" lookup_include=hotes_sensibles.csv lookup_stage=result
| esearch profile=prod esql="FROM logs-* | $lookup_include$ | STATS n = COUNT(*) BY host.name, user.name | $lookup_exclude$" lookup_include=hotes.csv lookup_exclude=comptes_service.csv
```

- `lookup_stage=result` : tous les lookups en fin de requête, avant le `SORT`
  et le `LIMIT` ajoutés par l'app ;
- marqueurs, chacun seul dans un segment de la requête (entre deux `|`, ou en
  fin) : `$lookup$` place tous les lookups, `$lookup_include$` et
  `$lookup_exclude$` les inclusions et les exclusions à deux endroits. Avec des
  marqueurs, chaque sens de lookup présent doit avoir le sien, et
  `lookup_stage=` ne s'emploie pas. Un marqueur précédé seulement de `FROM` et de
  `WHERE` filtre les documents, comme le défaut. Dans un tableau de bord écrit à
  la main, écrire `$$lookup$$` (sinon Simple XML y voit un token).

**Même logique que `query=`** : une ligne de lookup = ET de ses colonnes
renseignées (les paires restent liées), cellule vide = pas de condition,
cellule multivaluée = l'une de ses valeurs, lignes reliées par OU ;
`inclusion_type` / `exclusion_type` inchangés ; une exclusion garde les lignes
où la colonne est vide. Les colonnes du lookup doivent exister à l'endroit de
l'insertion (leur type est lu par une requête `| LIMIT 0`, sans données).

**Différences avec le filtre des documents**, toutes mesurées :
- colonne `text` : comparaison **insensible à la casse** sur la **valeur
  entière** (Lucene, lui, cherche une phrase dans le texte) ;
- dates : la valeur du lookup doit être une date complète
  (`2026-10-22T10:00:00Z`) ; `2026-10-22` ne désigne pas la journée ;
- jokers `*` : colonnes texte seulement ; un joker sur une valeur multivaluée
  n'est pas fiable ;
- au plus `esql_lookup_values_max` valeurs par lookup (1 000 par défaut), et
  la profondeur d'expression d'Elasticsearch (400) limite les lignes à
  plusieurs colonnes et les jokers : au-delà, refus explicite qui renvoie à
  `lookup_stage=source`.

**Versions** : Elasticsearch **8.15** minimum (fonction `MV_APPEND`, qui rend
le test juste sur les valeurs multivaluées) ; avant, refus explicite. Casse
ignorée sur une valeur **multivaluée** : 8.19 et 9.1 ; avant, elle est
comparée à l'identique (jamais perdue).

## Période dans la commande : `earliest=` / `latest=`

Pour qu'une recherche porte sa propre période, indépendamment du sélecteur :
panneaux d'un tableau de bord sur des fenêtres différentes, sous-recherches,
recherches planifiées.

```spl
| esearch index="logs-*" query="*" earliest=-1h@h latest=@h
| esearch esql="FROM logs-* | STATS n = COUNT(*)" earliest=-1d@d latest=@d
| esearch index="logs-*" query="*" earliest="10/01/2026:00:00:00" latest="10/02/2026:00:00:00"
```

**Même sémantique qu'une recherche Splunk** (mesurée) : dès qu'une borne
est écrite, le sélecteur est ignoré ; `earliest=` seul va jusqu'à `now`,
`latest=` seul part du début des temps. Aucune fenêtre implicite.

**Résolution par Splunk**, pas par l'app : chaque valeur part à splunkd
(`search/timeparser`) avec les droits de l'utilisateur. Son **fuseau horaire**
s'applique donc aux arrondis (`@d`) et aux dates absolues, et le `now` est celui
de la recherche, comme pour le sélecteur. Formes acceptées : relatif (`-1h@h`,
`@d`, `-1d@d+2h`, `now`), époque (`1700000000`, `0`), ISO 8601
(`2026-10-01T00:00:00`) et le format des modificateurs Splunk
(`MM/JJ/AAAA:HH:MM:SS`). Refusés, en le disant : le temps réel (`rt-5m`), une
valeur vide ou inconnue de Splunk, une fenêtre vide ou inversée (pas de
permutation silencieuse).

## Métadonnées : `es_metadata=`

`es_metadata=true` ajoute à chaque événement **`es_index`** (index réel, même
interrogé par alias ou data stream) et **`es_id`** (identifiant du document) :
pour dédoublonner (`| dedup es_id`) ou retrouver le document dans Kibana.
L'option est désactivée par défaut : deux champs de plus par événement.

Ces deux noms appartiennent alors à l'app, comme `_time` : un champ du document
nommé `es_index` est préservé sous `es_es_index`, comme tout champ réservé
(préfixe `es_`). En ES|QL, demander les métadonnées dans la requête
(`FROM logs-* METADATA _index, _id`) : les colonnes sortent sous les mêmes noms
(`es_index`, `es_id`, et `es_version`, `es_score`… pour les autres). La
syntaxe dépend de la version d'Elasticsearch (mesuré) : en **8.11 et 8.12**,
entre crochets, `FROM logs-* [METADATA _index, _id]` ; en 8.17, les deux formes ;
en **9.5**, sans crochets seulement. L'erreur de syntaxe d'Elasticsearch est
relayée telle quelle.
`es_metadata=true` avec `esql=` est refusé et renvoie vers `METADATA`.

## Ordre des résultats : `sort=`

Par défaut (`sort=none`), Elasticsearch rend les documents **dans l'ordre où il
les a stockés** : quand `limit` est inférieur au nombre de correspondances, les
événements rendus ne sont ni les plus récents ni les plus anciens, et ils ne
sont pas triés. C'est le mode le plus économe, adapté aux extractions complètes.

Pour « les N derniers événements » — dernier état par hôte, dernières erreurs —
demander le tri côté Elasticsearch :

```spl
| esearch profile=prod index="logs-*" query="status:500" limit=100 sort=desc
```

Un `| sort - _time` ajouté ensuite dans Splunk ne le remplace pas : il ne fait
que réordonner les N événements déjà choisis par Elasticsearch. Et `query=` ne
peut pas trier (la syntaxe Lucene n'a pas de tri).

Le tri porte sur le champ date (`timefield`). Il doit être triable, et du même
type de tri dans tous les index visés. Sinon, la recherche est **refusée avant
l'envoi** (« sort=desc impossible »), avec les types et les index en cause.
Exemples : un champ `text`, ou une date ici et un `keyword` là. Dates,
entiers et index sans le champ se trient ensemble ; ces derniers viennent en
fin. Sans `sort=`, la même recherche part normalement. Coût mesuré sur
5 millions de documents : quelques millisecondes par page, ×2 au pire sur une
pagination PIT de 50 000.

### Champ date d'un autre type que `date`

Elasticsearch n'impose pas de type au champ date, sauf dans un data stream. Quand
le champ est en nombre, en texte ou absent dans un index visé, l'app le détecte
(sonde `_field_caps`, qui lit les mappings sans parcourir les données) et le dit :
- **nombre** : la période est appliquée en millisecondes **et en secondes**
  (`query=`) ; les dates en secondes sont donc rendues ;
- **texte** (`keyword`) : la période et le tri le comparent comme du texte,
  avertissement ;
- **absent** : la période exclut ses documents, avertissement ; « Toute
  période » les rend, sans `_time` ;
- **événements sans `_time`** : leur nombre est annoncé, seulement s'il y en a,
  car `timechart` et `bin` les ignorent.

Pour un champ date natif (`date`, `date_nanos`), rien de tout cela : la requête
reste une simple plage en millisecondes. En ES|QL, l'avertissement vient du type de la
colonne rendue. Détail et limites : OPERATIONS § 10.18.

## Booléens

Les booléens sont rendus **comme dans `_raw`**, qui fait foi : `true` /
`false`, y compris dans un champ multivaleur (`null` y reste `null`). Filtrer
avec `| search actif=true`.

## Requêtes temporelles Lucene (dans query=)

```
@timestamp:[now-24h TO now]
@timestamp:[2025-01-01T00:00:00Z TO 2025-01-02T00:00:00Z]
NOT @timestamp:[2025-01-01 TO 2025-01-10]
```

Lucene ne supporte pas `<`/`>` seuls : toujours utiliser `TO`.

## Requête live ou matérialisation ?

`| esearch` interroge Elasticsearch **à chaque exécution**. C'est ce qu'on veut
pour de l'exploration ponctuelle. Dès qu'une requête devient **récurrente**
(dashboard, enrichissement, correlation search) ou **volumineuse**, il vaut mieux
la **matérialiser** : une recherche planifiée interroge ES périodiquement et
écrit dans un KV Store ou un summary index, que tout le monde lit ensuite
localement.

```spl
| esearch profile=prod index="logs-*" query="status:500" limit=50000
| outputlookup esearch_cache
```

Une requête par intervalle au lieu d'une par utilisateur : charge ES constante,
mémoire bornée, dashboards qui survivent à une indisponibilité du cluster. Seule
contrepartie, la fraîcheur des données. Modèles fournis (désactivés) dans
`savedsearches.conf` — voir OPERATIONS.md §9bis.

## Exploitation

- Log : `$SPLUNK_HOME/var/log/splunk/esearch.log` (rotatif, sans secrets,
  indexé dans `_internal`), en trois sourcetypes : `esearch:log`
  (lignes ordinaires), `esearch:log:debug` (DEBUG du niveau global),
  `esearch:log:debug_search` (recherches `debug=true`) ; champs `niveau`,
  `composant`, `debug_sid`, `debug_tag`. Contenu détaillé : OPERATIONS § 9,
  « Journal de l'app ».
- **Mode debug d'une seule recherche** : `debug=true`, et en option
  `debug_tag=<nom>` ; dans la page Query, le choix *Debug* :
  ```
  | esearch profile="prod" index="logs-*" query="status:500" debug=true debug_tag=incident-42
  ```
  - **La requête réellement envoyée** à Elasticsearch — `POST <hôte>/<index>/_search`
    et son corps JSON (requête, fenêtre de temps, tri, champs, filtres `terms`)
    — est montrée en **warning**, partout où s'affichent les messages d'une
    recherche ; dans la page Query, dans un panneau sous les résultats, corps
    indenté. Les listes `terms` sont coupées à `[settings] debug_terms_max`
    éléments (100 par défaut, page *Configuration*) et les chaînes de plus de
    10 000 caractères aussi, la coupe toujours dite : `"[...] et 65437 de
    plus"`. Même texte au journal, dans le warning et dans la page.
  - **Pas de warning pour une recherche planifiée** (identifiant
    `scheduler__…`) : ses messages peuvent être vus par d'autres que son auteur
    (rapport partagé, tableau de bord). La requête reste au journal.
  - **Journal** (`esearch.log`, sourcetype `esearch:log:debug_search`) et
    **search.log du job** (inspecteur), selon `[settings] debug_search_scope` :
    `query` (défaut) n'écrit que la requête envoyée ; `all` écrit toutes les
    lignes de la recherche, commande et proxy. Les lignes portent le marqueur
    `[debug sid=<sid> debug_tag=incident-42]`. Dans le search.log, Splunk
    étiquette ERROR toute sortie d'erreur d'une commande : le vrai niveau est en
    tête de ligne (`stderr: [DEBUG] [debug sid=…] …`).
  - Retrouver (administrateurs) :
    `index=_internal sourcetype=esearch:log:debug_search debug_tag=incident-42`,
    ou par `debug_sid`. `debug_tag=` non vide sans `debug=true` est refusé.
- **Mode DEBUG global** : le réglage `[settings] log_level` d'`esearch.conf`,
  qui vaut pour toutes les recherches de tous les utilisateurs, commandes et
  proxy compris. Trois façons de le poser, prises en compte dès la recherche
  suivante, sans redémarrage :
  - page *Configuration*, *Réglages globaux* → *Niveau de log* → `DEBUG` ;
  - `local/esearch.conf` : `[settings]` puis `log_level = DEBUG` ;
  - REST : `curl -k -u admin -X POST https://localhost:8089/servicesNS/nobody/SA-esearch/configs/conf-esearch/settings -d log_level=DEBUG`.

  `DEBUG` ajoute le texte de chaque requête au journal, donc à `_internal` :
  revenir à `INFO` après le diagnostic. Pour la version du cluster interrogé,
  c'est un autre réglage : `detect_version = true`.
- Messages utilisateur : troncature à `limit`/`max_limit`, shards en échec,
  TLS désactivé — visibles dans le job inspector.
- Paquet installable : `./build.sh` (`./build.sh --help` pour les options).

## Compatibilité & montées de version

Matrice et stratégie de résilience : [COMPATIBILITY.md](COMPATIBILITY.md).

## Administration

Guide complet : [OPERATIONS.md](OPERATIONS.md) (install, upgrade, profils,
rotation de secrets, RBAC, mTLS, SHC, dépannage). Page de configuration dans
l'app (menu → *Elasticsearch Query — Configuration*).

## Licence

Apache License 2.0, © 2026 aurelien-oui : fichiers `LICENSE` et `NOTICE` de
l'app. Une reprise redistribuée doit conserver la mention de copyright et
reprendre le contenu du fichier `NOTICE`. Les bibliothèques embarquées gardent
leur propre licence (MIT, BSD, Apache-2.0, MPL-2.0 pour certifi) : textes dans
`LICENSES/`, index `LICENSES/README.txt`.

Projet indépendant, sans lien avec Elastic, Splunk ou le projet OpenSearch, ni
soutenu par eux. Elasticsearch is a trademark of Elasticsearch B.V., registered
in the U.S. and in other countries. Splunk, OpenSearch et les autres noms cités
sont des marques de leurs propriétaires respectifs.

