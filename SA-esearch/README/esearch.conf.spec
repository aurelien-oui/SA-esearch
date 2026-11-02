[settings]
allow_adhoc_host = <bool>
* Autorise l'option es_host= dans la SPL (mode ad hoc, sans profil).
* En production, laisser false pour imposer les profils (anti-SSRF).
* Défaut : false

max_limit = <integer>
* PLAFOND : nombre maximal d'événements retournés par une recherche, quel que
* soit limit=. Ce n'est pas le nombre ramené — voir default_limit.
* Une valeur non numérique ou < 1 est ignorée (avertissement + défaut).
* Défaut : 50000

default_limit = <integer>
* NOMBRE de résultats proposé par défaut dans le champ « Limite » de la page
* Query, dès son ouverture (en tête de la liste ; 100, 1000 et 10000 suivent,
* et toute autre valeur peut être saisie). C'est ce réglage qu'il faut changer
* pour ramener plus (ou moins) de résultats depuis l'interface. Une limite déjà
* présente dans l'URL de la page (lien, rechargement) est conservée. Toujours
* borné par max_limit. Sans effet sur les recherches SPL, qui portent leur
* propre limit=.
* Défaut : 100

verify_certs = <bool>
* Vérification du certificat TLS en mode ad hoc.
* Défaut : true

log_level = [DEBUG|INFO|WARNING|ERROR]
* Verbosité de $SPLUNK_HOME/var/log/splunk/esearch.log
* Défaut : INFO

profile_order = <profil1,profil2,...>
* Ordre de priorité des profils. Une recherche sans profile= (| esearch,
* | esindices) utilise le PREMIER profil de cette liste que l'utilisateur a le
* droit d'utiliser (allowed_roles) ; le menu Profil de la page Query suit le
* même ordre et présélectionne ce profil.
* Un profil absent de la liste vient après ceux qui y figurent, par ordre
* alphabétique ; un nom qui ne correspond à aucun profil est ignoré.
* Réglé dans la page Configuration (bloc « Profil par défaut »).
* Défaut : vide (ordre alphabétique)

pagination = [auto|pit|scroll]
* Pagination quand limit dépasse 10000 : PIT+search_after (pit, recommandé),
* scroll (compat vieux ES/OpenSearch), auto = pit avec repli scroll.
* Valable dans [settings] et par profil. Défaut : auto

detect_version = <bool>
* Détection passive de version/distribution ES (GET / loggé) à chaque
* recherche. Coût = un aller-retour par recherche. Défaut : false (activer pour
* diagnostiquer une montée de version).

sanitize_metadata_fields = <bool>
* Préfixe `es_` les champs host / source / sourcetype provenant
* d'Elasticsearch, au lieu de les laisser écraser les métadonnées de
* l'événement Splunk. Les autres champs réservés (_time, _raw, __mv_*, internes)
* sont assainis dans tous les cas.
* Mettre true si des correlation searches ou le CIM s'appuient sur `host`.
* Défaut : false (comportement historique)

lookup_fields_ignore = <liste>
* Colonnes de lookup écartées des filtres lookup_include= et
* lookup_exclude= de | esearch, pour toutes les recherches : noms séparés par
* des virgules, motifs `*` admis (commentaire, description, date_*). Les
* colonnes `_*` (internes à Splunk) sont toujours écartées. S'ajoute à l'option
* lookup_fields_ignore= de la commande.
* Défaut : vide

debug_search_scope = query|all
* Ce qu'écrit une recherche lancée avec | esearch debug=true, dans
* esearch.log (sourcetype esearch:log:debug_search) et dans le search.log du
* job : `query`, la seule requête envoyée à Elasticsearch (méthode, URL, corps
* JSON) ; `all`, toutes les lignes de la recherche (commande et proxy). Dans les
* deux cas, la requête est aussi montrée en warning (sauf recherche planifiée).
* Une valeur illisible vaut `query`.
* Défaut : query

esql_max_bytes = <integer>
* Taille maximale, en octets UTF-8, d'une requête ES|QL (esql=),
* ajouts de l'app compris (SORT, LIMIT). Contrôlée par la commande et par le
* proxy avant tout envoi. Mesuré (tas de 512 Mo) : une requête ES|QL a arrêté un
* nœud Elasticsearch dès 10 Ko. Entre 1024 et 1000000 (limite propre
* d'Elasticsearch 9.5).
* Défaut : 65536

esql_max_depth = <integer>
* Imbrication maximale de parenthèses d'une requête ES|QL (hors
* chaînes et commentaires). Elasticsearch refuse au-delà d'une profondeur
* d'expression de 400 (≈ 198 parenthèses), mais un nœud chargé peut s'arrêter
* avant de répondre : l'app refuse plus tôt. Entre 1 et 400.
* Défaut : 100

esql_lookup_values_max = <integer>
* Nombre maximal de valeurs (exactes ou à joker) d'un lookup inséré
* dans une requête ES|QL (lookup_stage=result, ou marqueur $lookup$ placé après
* un EVAL / STATS). Au-delà : refus explicite, qui renvoie à lookup_stage=source
* (filtre des documents, sans cette limite). Mesuré : une liste de 10 000
* valeurs a arrêté un nœud Elasticsearch 8.15.5 sous charge ; 1 000 passent sur
* toutes les versions. Entre 1 et 65536.
* Défaut : 1000

esql_async_wait = <durée ES>
* Profils en mode ES|QL asynchrone (esql_mode = async) : attente
* de chaque interrogation (`wait_for_completion_timeout`). Une requête finie
* dans ce délai rend son résultat d'un coup ; sinon la commande interroge à
* nouveau. Défaut : 10s

esql_async_keep_alive = <durée ES>
* Conservation, côté Elasticsearch, du résultat d'une requête
* asynchrone. Lu, il est libéré aussitôt ; une recherche interrompue sans
* annulation le laisse expirer au bout de ce délai. Borne aussi la validité du
* jeton remis par le proxy. Défaut : 5m

esql_async_max = <integer>
* Durée maximale, en secondes, d'une requête ES|QL asynchrone,
* interrogations comprises : au-delà, elle est annulée (DELETE) et la recherche
* le dit. ES|QL n'a pas de délai côté serveur. Entre 10 et 86400.
* Défaut : 1800

esql_hide_keyword = <bool>
* [settings] et par profil. Masquer la colonne `X.keyword` quand la colonne `X`
* est aussi rendue (champ texte à sous-champ keyword : même valeur, en double),
* comme Discover de Kibana par défaut. Dans un profil, vide = réglage global.
* Défaut : true

debug_terms_max = <integer>
* Nombre d'éléments d'une liste `terms` montrés dans la requête
* affichée en debug (journal, warning, page Query) ; la suite est résumée
* « [...] et X de plus ». Entre 1 et 100000.
* Défaut : 100

page_keep_alive = <durée ES>
* Durée de vie du contexte de pagination (PIT ou scroll) entre deux
* pages. Réglage GLOBAL : il n'est pas lu dans une section de profil.
* Doit couvrir un aller-retour commande <-> proxy REST. Format Elasticsearch,
* entier strictement positif + unité (30s, 2m, 5m...) ; une valeur invalide
* (0s, -1m, 1.5m, sans unité) est ignorée (avertissement + défaut).
* Défaut : 2m

max_timeout_read = <integer>
* Plafond (s) appliqué par le proxy REST au timeout de lecture ES
* demandé par un profil authentifié (anti-abus). Défaut : 300.

query_max_bytes = <integer>
* Taille maximale (octets, UTF-8) de la requête Lucene query=, lookups
* insérés compris, contrôlée avant envoi par la commande et par le proxy.
* Mesuré sur un tas de 512 Mo : une phrase de 4 Mo arrêtait le nœud
* (OutOfMemoryError). Entre 1024 et 2147483647 (2 Gio, plafond de
* http.max_content_length). Défaut : 1048576 (1 Mio).

query_max_depth = <integer>
* Imbrication maximale (parenthèses, hors phrases) de query=.
* Mesuré : ~3 000 niveaux arrêtaient le nœud (StackOverflowError) ; le réglage
* indices.query.bool.max_nested_depth d'Elasticsearch ne s'applique pas à
* query_string. Entre 1 et 100000. Défaut : 30.

max_response_mb = <integer>
* Plafond (Mo) d'une réponse d'Elasticsearch une fois décompressée :
* une page de recherche (jusqu'à 10 000 documents) ou une réponse ES|QL.
* Au-delà, la recherche échoue avec un message qui nomme ce réglage. Protège
* le search head d'une réponse hostile (bombe de décompression) ; un encodage
* chaîné (`Content-Encoding: gzip, gzip`) est refusé quel que soit le plafond.
* Réglage GLOBAL. Entre 1 et 4096. Défaut : 256 (une page de 10 000 documents
* de 26 Ko en moyenne).

[profile:<nom>]
es_host = <url>
* URL de base d'Elasticsearch (ex : https://es.example.com:9200). Obligatoire.

verify_certs = <bool>
* Vérification du certificat TLS. Défaut : true

ca_file = <chemin>
* Bundle CA (PEM) pour valider le certificat du serveur. Optionnel.
* Chemins (ca_file, client_cert, client_key) : `$SPLUNK_HOME` est remplacé et un
* chemin relatif est pris sous $SPLUNK_HOME. Emplacement recommandé :
* $SPLUNK_HOME/etc/auth/esearch/ — jamais le répertoire de l'app, qu'un
* redéploiement remplace (voir OPERATIONS.md, mTLS).

timefield = <champ>
* Champ date utilisé pour le filtre temporel (time picker) et _time.
* Défaut : @timestamp

auth_type = [none|basic|apikey]
* none   : pas d'authentification
* basic  : user/mot de passe -> username = <user> ci-dessous, secret dans
*          storage/passwords (realm 'esearch:<nom>', username <user>)
* apikey : clé API ES -> secret dans storage/passwords
*          (realm 'esearch:<nom>', username 'apikey')
* Défaut : none

username = <string>
* Requis si auth_type = basic.

allowed_roles = <* | admin | rôle1,rôle2,...>
* Qui peut utiliser ce profil, avec ou sans authentification (tous les
* profils passent par le proxy REST, qui le contrôle avant toute lecture
* de secret) :
*   *              tout porteur de la capability esearch_run
*   admin          administrateurs seulement
*   rôle1,rôle2    ces rôles (directs ou hérités), plus les administrateurs
* Le rôle admin passe toujours — donc aussi les recherches de propriétaire
* nobody, exécutées en splunk-system-user (cf. OPERATIONS.md § 5).
* Valeur illisible (« *, x », espace, « : », « / ») : profil refusé à tous.
* Absent ou vide : ouvert à tout porteur d'esearch_run ; la page
* Configuration oblige à choisir.
* Rôles relus à chaque nouvelle session (cache du proxy : 60 s par session).
* Comptes LDAP/SAML : délais propres à Splunk, cf. OPERATIONS.md § 5.

max_limit = <integer>
* Surcharge du PLAFOND global pour ce profil. Optionnel.

pagination = [auto|pit|scroll]
* Pagination quand limit dépasse 10000 : PIT+search_after (pit, recommandé),
* scroll (compat vieux ES/OpenSearch), auto = pit avec repli scroll.
* Valable dans [settings] et par profil. Défaut : auto

esql_mode = [sync|async]
* Mode des requêtes ES|QL (esql=) de ce profil. sync (défaut) : une requête,
* bornée par le délai de lecture. async : POST /_query/async, puis
* interrogations (esql_async_wait) jusqu'à la fin, annulée au-delà de
* esql_async_max ; pour les requêtes plus longues que max_timeout_read.
* Elasticsearch 8.13 minimum (sinon refus explicite). Optionnel.

index_pattern = <motif>
* Périmètre proposé par | esindices, donc par le menu « Index » de la page
* Query (ex. logs-*). Utile quand le cluster expose des centaines de cibles.
* N'est PAS un contrôle d'accès : Elasticsearch reste seul juge de ce que la
* clé du profil peut lire ; un utilisateur peut toujours saisir un autre motif.
* Optionnel. Défaut : * (toutes les cibles visibles par le profil)

client_cert = <chemin>
* mTLS : certificat client PEM présenté à Elasticsearch. Optionnel.

client_key = <chemin>
* mTLS : clé privée PEM (NON chiffrée) associée à client_cert.
* Clé protégée par passphrase : la déchiffrer à l'installation, cf. OPERATIONS.md.

esql_hide_keyword = <bool>
* [settings] et par profil. Masquer la colonne `X.keyword` quand la colonne `X`
* est aussi rendue (champ texte à sous-champ keyword : même valeur, en double),
* comme Discover de Kibana par défaut. Dans un profil, vide = réglage global.
* Défaut : true

# NOTE pagination : réglable dans [settings] ou par profil UNIQUEMENT (pas une
# option de la commande | esearch).
