# Compatibilité & résilience aux montées de version

Cette app est conçue pour minimiser sa sensibilité aux montées de version de
Splunk, Splunk Enterprise Security et Elasticsearch/OpenSearch.

## Matrice de versions

| Composant | Minimum | Testé | Notes |
|---|---|---|---|
| **Splunk Enterprise** | 8.1 (SCPv2 chunked) | **9.3.14 et 10.4.1** | `python.version=python3` + `python.required=3.9,3.13` → couvre Splunk 9.x (Python 3.9) et 10.x (Python 3.13) |
| **Splunk Enterprise Security** | n/a (aucune dépendance de code) | **Contrat d'intégration vérifié** (modèle d'exécution, hygiène CIM, objets de connaissance d'une surcouche) ; app ES non installée (téléchargement réservé aux licences ES) | Tourne sur les plateformes d'ES 8.x (Splunk 9.x/10.x), toutes deux exercées. Détail ci-dessous |
| **Elasticsearch** | 7.10 (PIT) / 7.x (scroll) | **7.17.24, 8.17.4 et 9.5.5** (clusters réels) | Repli automatique scroll si PIT/`_shard_doc` indisponible |
| **OpenSearch** | 1.x (scroll) | **1.3.20, 2.19.3 et 3.9.0** (clusters réels) | `/_pit` (syntaxe ES) refusé → bascule scroll automatique, vérifiée dans le journal. Une `query_string` y est limitée à 32 000 caractères par le cluster : message dédié. Pas d'ES\|QL : refus explicite |
| **ES\|QL (`esql=`)** | Elasticsearch 8.11 (8.14 recommandé) | sonde sur **18 versions** (7.17.24, 8.10.4 → 9.5.5, OpenSearch 3.9.0) ; bout en bout dans Splunk sur 8.11.4, 8.17.4, 9.5.5 ; refus vérifié sur 7.17.24 | Ni Elasticsearch 7.x / ≤ 8.10 ni OpenSearch : refus explicite. Détail ci-dessous |
| **Splunk Cloud** | **non pris en charge** | non installé ; contrôles AppInspect « cloud » passés, à titre d'information | `sc_admin` traité en administrateur, sans effet sur Enterprise |
| **Python (embarqué Splunk)** | 3.9 | **3.9 (Splunk 9.3) et 3.13.11 (Splunk 10.4.1)**, les deux sur Splunk réel | libs vendorisées compatibles 3.9→3.13 |
| **Splunk SDK (splunklib)** | 2.1.1 vendorisé | 2.1.1, sous Python 3.9 (Splunk 9.3) et 3.13 (local) | la ligne 3.x exige Python ≥ 3.13 : incompatible avec Splunk 9. Dépendances embarquées : `deprecation` 2.1.0, `packaging` 26.3. AppInspect avertit (`check_python_sdk_version`, « Upgrade to 3.0.0 or later ») : accepté, la 3.x excluant Splunk 9 |

## Ce qui rend l'app résiliente

### Splunk
- **Protocole SCPv2 (chunked)** : voie supportée et pérenne (SCPv1 déprécié abandonné).
- **Bornes du time picker** : lues via l'**API supportée** `searchinfo.earliest_time/latest_time`
  en priorité ; le format interne `info.csv` n'est plus qu'un **repli** (l'app ne
  casse donc ni si Splunk change `info.csv`, ni si une version future ne peuple
  pas le natif). Validé sur Splunk réel : All time / relatif / 24h / plage absolue.
- **APIs REST stables** utilisées par la page de setup : `configs/conf-esearch`,
  `storage/passwords` ; token CSRF lu avec plusieurs noms de cookie possibles.
- **`earliest=` / `latest=` dans la commande** : résolus par l'endpoint
  REST `search/timeparser` de splunkd, avec le `now` de la recherche (colonne
  `now` d'`info.csv`) ; aucune réimplémentation des modificateurs de temps. Sans
  `now` dans `info.csv`, l'heure courante, journalisée. Vérifié sur 9.3.14 : même
  compte que le sélecteur et qu'Elasticsearch, relatif, ISO et format Splunk ;
  le format `MM/JJ/AAAA:HH:MM:SS`, que timeparser refuse, est réécrit en ISO,
  interprété dans le même fuseau (vérifié avec un utilisateur en Europe/Paris).
- **splunklib 2.1.1** vendorisé (pas de dépendance au SDK de l'instance) : la
  dernière ligne qui accepte le Python 3.9 de Splunk 9 (la 3.x exige 3.13).

### Splunk Enterprise Security (ES)
- L'app ne charge, n'importe et n'appelle **rien** de Splunk ES : une montée de
  version d'ES n'a aucun impact fonctionnel direct.
- **Commande globale** (`export = system`) : utilisable dans toutes les apps et
  dans les **correlation searches** de Splunk ES. Les profils authentifiés y
  fonctionnent sans configuration de credentials par recherche, grâce au proxy
  REST privilégié (le secret est lu côté serveur en système ; voir
  OPERATIONS.md §5). Capability `esearch_run` accordée à `user` par défaut.
- Si la sortie de `| esearch` alimente des **data models CIM** d'ES, le nommage
  des champs compte : l'app produit les champs bruts d'ES (dot-notation) +
  `_time`/`_raw` ; la normalisation CIM reste du ressort de la configuration ES.
  Les champs de **classification de sécurité** `eventtype` et `tag` venant d'un
  document ES sont préfixés `es_` : un document ne peut pas forger
  la classification qu'exploitent les correlation searches. Les champs **métier**
  CIM (`action`, `src`, `dest`, `severity`, `signature`…) passent intacts.

**Pourquoi l'app ES elle-même n'est pas testée.** Son téléchargement sur
Splunkbase est réservé aux comptes titulaires d'une licence ES (liste
d'autorisation, pour la durée de la licence) ; il n'existe pas de version d'essai
téléchargeable, et rien n'indique que les anciennes versions échappent à cette
règle. Deux voies existent hors achat : une licence d'évaluation ou de
développement via l'équipe commerciale Splunk, ou le bac à sable ES hébergé en
Splunk Cloud — où une app privée ne s'installe qu'après la validation de Splunk
Cloud, jamais faite pour cette app (ses contrôles AppInspect « cloud » passent,
ce qui n'en tient pas lieu).

**Vérification, pour la compatibilité avec Splunk ES 8.x.**
Le *contrat d'intégration* a été vérifié en reproduisant fidèlement le modèle
d'exécution d'une correlation search sur Splunk 9.3.14 :

- commande résolue et exécutée **depuis une autre app** (`search`, pas l'app elle-même)
  — l'export global fonctionne ;
- **saved search planifiée** (le mécanisme d'une correlation search), propriétaire
  et exécutée **par un compte non-admin**, servie par le proxy privilégié **sans
  credentials par recherche** (journal : `user=<compte> profil=<authentifié>`) ;
- hygiène CIM confirmée sur un document portant `eventtype`/`tag` **et** des
  champs métier : classification assainie, champs métier préservés, `_time` exact.

**ES est une surcouche : ce qu'elle peut réellement changer.**
L'app n'importe ni n'appelle rien d'ES. ES agit sur un search head par quatre
leviers ; chacun a été examiné, et mesuré quand c'était possible, avec une app
qui reproduit ces objets, partagés globalement :

| Levier d'ES | Effet sur `\| esearch` | Preuve |
|---|---|---|
| **Objets de connaissance globaux** (CIM, Asset & Identity en lookups automatiques `[default]`, alias, champs calculés, eventtypes, tags) | **Aucun sur le résultat live** : Splunk ne les applique qu'aux événements lus depuis un index. Une correlation search qui filtre `tag=…` ou attend `src_priority` ne les trouvera pas sur un résultat brut. Appliqués en revanche après `\| lookup` / `\| typer \| tags` explicites, et sur une **copie matérialisée** relue depuis un index (OPERATIONS § 9bis) | Mesuré : 26 cas, dont témoin indexé (objets appliqués) contre `\| esearch` (aucun) |
| **Rôles** (`ess_user`, `ess_analyst`, `ess_admin`) | Ils héritent de `user` (et `power`) : `esearch_run` leur parvient par défaut. En **mode restreint** (OPERATIONS § 5), il faut leur ajouter `esearch_user`. ES s'administre avec `admin`, qui tient `esearch_run` directement | Documentation ES 8 (rôles) + matrice de droits vérifiée |
| **Recherches planifiées** (correlation searches, données des tableaux de bord ES) | Même modèle d'exécution que le contrat vérifié ci-dessus. Le risque est de **charge** : chaque correlation search qui appelle `\| esearch` interroge Elasticsearch à chaque exécution — d'où la matérialisation recommandée | Contrat vérifié ; charge mesurée à 8 recherches simultanées |
| **Data models accélérés, notables, risque** | Les data models ne lisent que des index : un résultat live n'y entre jamais. Un notable ou un événement de risque est **écrit dans un index** (`notable`, `risk`) : les enrichissements d'ES s'y appliquent normalement à la relecture | Même mécanisme que la variante B, vérifiée |

Un seul point n'est pas vérifiable sans le paquet ES : un **conflit de nom de
commande** (`esearch`, `esindices` sont exportées globalement). Aucun n'est connu ;
à contrôler sur l'instance cible avec
`| rest /servicesNS/-/-/configs/conf-commands splunk_server=local | search title=esearch OR title=esindices | table title eai:acl.app`
— une seule ligne par commande, dans l'app `SA-esearch`, est attendue.

Ce qui **n'a pas** pu être vérifié, faute de pouvoir installer l'app : le
chargement réel dans l'interface d'ES 8.x (Incident Review, data models CIM
accélérés, notable events). Le contrat sur lequel l'app repose — commande
globale, proxy, nommage des champs — l'est, lui, et l'analyse ci-dessus montre
qu'ES n'a pas d'autre prise sur elle.

> **Plateforme.** Splunk ES 8.x s'exécute sur Splunk Enterprise 9.x/10.x. Les
> deux ont été réellement exercées (9.3.14 et 10.4.1), donc le socle plateforme
> d'ES 8.x est couvert. Vérifier le numéro de plateforme exact exigé par votre
> version d'ES 8.x dans ses notes de version.

### TLS, certificats et authentification
37 cas vérifiés (certificats côté client et côté serveur, basic, clé API,
authentification par certificat), **conformes dans les sept configurations** :

| Splunk | Elasticsearch | Licence ES | Particularité | Résultat |
|---|---|---|---|---|
| 9.3.14 (Python 3.9, OpenSSL 1.0.2) | 8.17.4 | essai | — | 37/37 |
| 9.3.14 | 8.17.4 | gratuite | domaine PKI ignoré par ES | 37/37 |
| 9.3.14 | 7.17.24 | essai | alertes TLS différentes d'ES 8 | 37/37 |
| 10.4.1 (Python 3.13, OpenSSL 3.5) | 8.17.4 | essai | — | 37/37 |
| 10.4.1 | 8.17.4 | gratuite | domaine PKI ignoré par ES | 37/37 |
| 10.4.1 | 7.17.24 | essai | — | 37/37 |
| 10.4.1 | 8.17.4 | essai | **TLS 1.3 seul** | 37/37 |

| Limite | Détail |
|---|---|
| TLS 1.3 seul | Injoignable depuis **Splunk 9.x** (Python lié à OpenSSL 1.0.2, sans TLS 1.3) ; **fonctionne en Splunk 10.x**. Vérifié dans les deux cas |
| Authentification par certificat (domaine PKI) | Exige une licence Elasticsearch Platinum/Enterprise (ou d'essai) ; sans elle, l'app explique le 401. Le **mTLS seul** (certificat exigé à la connexion) fonctionne avec la licence gratuite |
| Clé client chiffrée | Non supportée (nommée à la lecture du profil) |

### Authentification Splunk : comptes natifs, LDAP, SAML

Les droits par profil (`allowed_roles`) et le profil par défaut reposent sur les
rôles que Splunk attribue à la session qui appelle, quelle que soit l'origine du
compte.

| Source des comptes | Testé avec | Résultat |
|---|---|---|
| Comptes natifs Splunk | Splunk 9.3.14 et 10.4.1 | droits par profil, profil par défaut, mode restreint : conformes sur les deux versions |
| LDAP | OpenLDAP (`osixia/openldap:1.5.0`), Splunk 9.3.14 et 10.4.1 | droits, rôles multiples, profil par défaut : conformes ; groupes imbriqués (`nestedGroups`), contrôle négatif compris ; délais d'effet d'un retrait de groupe mesurés (OPERATIONS § 5) |
| SAML | Keycloak 26.4.2, Splunk 9.3.14 et 10.4.1, vraie connexion par le fournisseur | idem ; rafraîchissement hors connexion par extension d'authentification (`getUserInfo`) : conforme |
| SAML avec requête d'attributs (AQR) | Shibboleth IdP 5.2.3, Splunk 9.3.14 | conforme **derrière un relais** qui corrige le `Content-Type` des requêtes SOAP de Splunk ; sans lui, refus du fournisseur et rôles figés, sans alerte. Exigences dans OPERATIONS § 5 |

Mêmes délais d'effet sur Splunk 9.3.14 et 10.4.1 ; l'AQR n'a été vérifiée que
sur 9.3.14. Non testés : Active Directory, ADFS, Okta et Entra ID — mêmes
mécanismes Splunk (`roleMap`), mais pas exercés.

### Elasticsearch / OpenSearch
- **Pagination adaptative** : PIT + `search_after` (recommandé, ES ≥ 7.12) par
  défaut ; **repli automatique sur scroll** dès que l'ouverture du PIT *ou* la
  première recherche (`_shard_doc`) échoue — couvre ES 7.10/7.11, OpenSearch, et
  toute future incompatibilité. Réglable : `pagination = auto|pit|scroll`.
- **DSL de requête stable** : `query_string`, `bool/must`, `range`, `_source`
  — inchangé d'ES 7 à 9.
- **Parsing défensif** des réponses (`.get()` partout, repli sur `resp.text`
  pour les messages d'erreur) : robuste aux variations de forme de réponse.
- **Détection passive** de la version/distribution (`GET /`, loguée) pour
  faciliter le diagnostic lors des montées de version — sans changer le comportement.
- **Clusters réels exercés** : Elasticsearch 7.17.24, 8.17.4 et 9.5.5,
  OpenSearch 1.3.20, 2.19.3 et 3.9.0, avec des contrôles de bout en bout dans
  Splunk — pagination de 11 500 documents en PIT et en scroll, `query_string`,
  `sort=desc`, bornes temporelles, `| esindices`. Tout conforme. Sur OpenSearch,
  le profil « PIT » bascule bien en scroll
  (`no handler found for uri [/logs-web/_pit]`).

### ES|QL (`esql=`)

Mesuré sur 18 versions (7.17.24, 8.10.4 → 9.5.5, OpenSearch 3.9.0). L'app ne demande **jamais** sa version au
cluster : chaque limite se reconnaît à la réponse d'Elasticsearch, et le
message nomme la version minimale.

| Cas | Minimum | Ce que fait l'app |
|---|---|---|
| ES\|QL lui-même | **8.11** (8.11–8.13 : préversion technique d'Elastic ; 8.14 stable) | 405 sur `/_query` (Elasticsearch 7.x, ≤ 8.10, OpenSearch) → « ES\|QL indisponible sur ce cluster : Elasticsearch 8.11 minimum… » |
| période et lookups (`filter`), `LIMIT`, réponse `columns`/`values` | 8.11 | identiques de 8.11 à 9.5 ; les versions récentes ne font qu'ajouter des clés à la réponse |
| type `geo_point` | 8.12 (8.11 : « unsupported ») | colonne de type non pris en charge : avertissement |
| type `date_nanos` | 8.17 | idem |
| type `flattened` | 9.5 | idem |
| colonnes `METADATA` (`_index`, `_id`… rendues `es_index`, `es_id`) | **8.11**, syntaxe selon la version | 8.11.4 : `FROM x [METADATA _index, _id]` seulement ; 8.17.4 : les deux formes ; 9.5.5 : sans crochets seulement (mesuré ; 8.18 à 9.4 non mesurés). L'app ne réécrit rien : l'erreur de syntaxe d'Elasticsearch est relayée |
| champs `nested` | aucune version (mesuré jusqu'en 9.5) | jamais rendus (colonnes absentes) : `query=` les rend |
| lookups insérés dans la requête (`lookup_stage=result`, marqueur après EVAL/STATS) | **8.15** (`MV_APPEND`) | « Unknown function [MV_APPEND] » → « lookups insérés … : Elasticsearch 8.15 minimum », avec les deux remèdes ; vérifié sur 8.14.3 par Splunk |
| casse ignorée sur une valeur **multivaluée** d'un lookup inséré (colonne `text`) | **8.19 et 9.1** (pas 8.18 ni 9.0, mesuré) | avant : comparée à l'identique, jamais perdue (`COALESCE(TO_LOWER(c), c)`) ; documenté |
| mode asynchrone (profil `esql_mode = async`) | **8.13** | « no handler found for uri [/_query/async] » (8.10 à 8.12, OpenSearch) ou « Invalid index name [_query] » (7.x) → « mode ES\|QL asynchrone indisponible : Elasticsearch 8.13 minimum … repasser le profil en mode synchrone » ; vérifié sur 7.17.24 par Splunk |
| texte des erreurs | change en 9.4 (« Found 1 problem » disparaît) | erreurs lues par **type**, jamais par texte |

Mise en garde (mesurée, tas de 512 Mo) : une requête ES|QL peut **arrêter un
nœud** bien plus tôt qu'une requête Lucene — 10 Ko (5 000 parenthèses, 8.17.4),
89 Ko (liste `IN` de 10 000 valeurs, 8.15.5, sous charge), 48 Ko (2 000 `LIKE`,
8.17.4). D'où les bornes propres à ES|QL (OPERATIONS § 10.15).

## Politique de dépréciation
- Options SPL `user=`/`password=`/`apikey=` : dépréciées (warning), remplacées
  par les profils + `storage/passwords`. Toujours acceptées pour compatibilité.
- API scroll ES : dépréciée côté ES mais conservée comme repli tant qu'ES la
  supporte ; PIT est le chemin principal.
