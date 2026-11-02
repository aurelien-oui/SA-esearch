# Guide d'exploitation — SA-esearch

Destiné aux administrateurs Splunk. Pour l'usage de la commande, voir `README.md`.

---

## 1. Installation

### Via l'interface
Apps → « Installer une app depuis un fichier » → le `.tgz` → redémarrer si demandé.

### Via la CLI
```bash
$SPLUNK_HOME/bin/splunk install app SA-esearch-<version>.tgz
$SPLUNK_HOME/bin/splunk restart
```

### Configuration initiale
L'app est livrée **sans profil ni secret**. Deux options :
- **Page de setup** : app « esearch for Elasticsearch » → onglet *Configuration* →
  *Profils* → *Nouveau profil* (hôte, TLS, type d'auth, accès) et saisir le
  secret ; les réglages communs à tous les profils sont sous *Réglages
  globaux*. Le secret est stocké chiffré (jamais dans un .conf).
- **En ligne de commande** : voir §3 (profils) et §4 (secrets).

---

## 2. Mise à jour

L'update **préserve** `local/` (profils) et les secrets (storage/passwords).

```bash
$SPLUNK_HOME/bin/splunk install app <nouveau>.tgz -update 1
$SPLUNK_HOME/bin/splunk restart
```

⚠️ Ne jamais modifier `default/` : toute personnalisation va dans `local/`
(sinon écrasée à l'update). Après ajout/modif d'une **vue** (setup), un
redémarrage Splunk est requis pour l'enregistrer.

---

## 3. Profils de connexion

Fichier `local/esearch.conf`. Un profil = une cible Elasticsearch nommée.

```ini
[profile:prod]
es_host = https://es.example.com:9200
verify_certs = true
ca_file = $SPLUNK_HOME/etc/auth/esearch/ca.pem
timefield = @timestamp
# auth_type : none | basic | apikey   (si basic : username = svc_splunk)
auth_type = apikey
# qui peut l'utiliser : admin | * | rôle1,rôle2 (§ 5)
allowed_roles = *
# pagination : auto | pit | scroll
pagination = auto
```

Plusieurs profils : l'ordre de priorité (`[settings] profile_order`) désigne
celui d'une recherche sans `profile=` — le premier que l'utilisateur a le droit
d'utiliser (§ 5).

Recharger sans redémarrer : `| rest /services/configs/conf-esearch` ou
`$SPLUNK_HOME/bin/splunk reload ...` ; en pratique la commande relit le fichier
à chaque exécution.

---

## 4. Secrets (storage/passwords) et rotation

Les secrets ne sont **jamais** dans un `.conf`. Realm = `esearch:<profil>`,
username = `apikey` (clé API) ou le nom d'utilisateur (basic).

### Créer / faire tourner un secret
Splunk nomme l'entrée `<realm>:<username>:` en **échappant** les deux-points du
realm : le secret de clé API du profil `prod` s'appelle `esearch\:prod:apikey:`,
soit `esearch%5C%3Aprod%3Aapikey%3A` dans une URL. Sans l'antislash (`%5C`), la
requête vise une entrée qui n'existe pas : 404 sur un DELETE, et la recréation
échoue ensuite en 409 « A password already exists » (vérifié).

```bash
NS=https://localhost:8089/servicesNS/nobody/SA-esearch
# Créer
curl -k -u admin "$NS/storage/passwords" \
  -d name=apikey -d realm=esearch:prod -d password='<CLE>'
# Faire tourner : mise à jour EN PLACE, sans instant où le profil n'a plus de secret
curl -k -u admin "$NS/storage/passwords/esearch%5C%3Aprod%3Aapikey%3A" \
  -d password='<NOUVELLE_CLE>'
# Supprimer
curl -k -u admin -X DELETE "$NS/storage/passwords/esearch%5C%3Aprod%3Aapikey%3A"
```
En auth basic, `apikey` est remplacé par le nom d'utilisateur, encodé pour l'URL.
Le proxy relit le secret à chaque requête, par le nom de son entrée : la
nouvelle valeur sert dès la recherche suivante. (Ou plus simplement : page
Configuration → *Éditer* le profil → nouveau secret.)

La page Configuration ne lit, des secrets, que le realm et le nom d'utilisateur
(`f=realm&f=username`) : aucun secret n'arrive dans le navigateur.

**Profil authentifié en `http://`** : la clé ou le mot de passe circule en clair
sur le réseau. La page le dit à l'enregistrement (message non
vert) et chaque recherche sur ce profil l'avertit ; rien n'est refusé, pour
qu'un cluster de test reste utilisable. En production : `https://`.

### Procédure de rotation de clé API ES recommandée
1. Créer la nouvelle clé côté Elasticsearch (sans supprimer l'ancienne).
2. Mettre à jour le secret Splunk (ci-dessus).
3. Lancer une recherche de contrôle : `| esearch profile=prod query="*" limit=1`.
4. Révoquer l'ancienne clé côté ES.

---

## 5. Accès global, droits par profil (Splunk ES, toutes les apps)

`| esearch`, `| esindices` et `| esprofiles` sont **globales**
(`export = system`) : utilisables depuis n'importe quelle app, y compris les
**correlation searches de Splunk ES**.

**Un seul passage vers Elasticsearch : le proxy** :
- l'admin configure les profils et leurs secrets une fois (§3, §4) ;
- pour **tout profil**, avec ou sans authentification, les commandes passent
  par un **handler REST privilégié** (`/esearch_proxy`, `passSystemAuth`). Il
  vérifie d'abord que l'appelant a le droit d'utiliser le profil
  (`allowed_roles`, ci-dessous), lit le secret éventuel **côté serveur en
  système**, exécute la requête et ne renvoie que les **résultats** — le secret
  n'est jamais exposé ni renvoyé ;
- l'appel est gouverné par la capability **`esearch_run`**, accordée par défaut
  au rôle `user` (donc à tous) et directement à `admin`.

Résultat : **tout utilisateur, depuis n'importe quelle app, peut utiliser les
profils qui lui sont ouverts**, sans accès aux secrets. Seul le **mode ad hoc**
(`es_host=`, désactivé par défaut, §6) interroge Elasticsearch en direct.

Un profil sans authentification passe lui aussi par le proxy : un utilisateur
privé de `esearch_run` n'y a pas accès non plus.

### Restreindre qui peut interroger Elasticsearch
1. Retirer l'octroi global dans `local/authorize.conf` :
   ```ini
   [role_user]
   esearch_run = disabled
   ```
2. Affecter le rôle `esearch_user` (fourni, porte `esearch_run`) uniquement aux
   utilisateurs autorisés.
3. **Seulement si le mode ad hoc est activé** (`allow_adhoc_host = true`) : il
   contourne le proxy, donc `esearch_run`. Restreindre alors la commande dans
   `metadata/local.meta`. Pour les profils, l'étape est inutile : tous passent
   par le proxy (vérifié).
   `| esindices` n'a pas de mode ad hoc : elle n'a pas besoin de cette ligne.
   ```ini
   [commands/esearch]
   access = read : [ admin, esearch_user ], write : [ admin ]
   export = system
   ```

Les administrateurs gardent l'accès : `esearch_run` est accordée directement au
rôle `admin`, et non seulement par héritage de `user` : la restriction ne leur
retire donc rien.

**Splunk Cloud** — **non pris en charge** ; ce qui suit vaut si l'app y était
installée. L'administrateur y a le rôle `sc_admin`, pas `admin`. L'app le
traite en administrateur, sans effet
sur Splunk Enterprise, où ce rôle n'existe pas : profils réservés, page Configuration,
écriture de l'app. Mais elle ne lui accorde pas `esearch_run` directement : une
stanza `[role_sc_admin]` dans `authorize.conf` **créerait** ce rôle sur Splunk
Enterprise. `sc_admin` la tient donc par héritage de `user`, et la restriction
ci-dessus la lui retire. En mode restreint sur Cloud, donner à `sc_admin` le
rôle hérité `esearch_user`, ou la capability `esearch_run` (Paramètres →
Rôles). Vérifié avec un rôle `sc_admin` important `user`, comme sur
Cloud : profil réservé à `admin` admis, page Configuration visible et lisible.

> Déploiement Splunk ES : les correlation searches tournent en planifié dans le
> contexte de l'app ES ; grâce au proxy système, les profils authentifiés y
> fonctionnent sans configuration de credentials par recherche.
> **En mode restreint**, les rôles d'ES (`ess_user`, `ess_analyst`) ne tiennent
> `esearch_run` que par héritage de `user` : ajoutez `esearch_user` aux rôles
> hérités de ceux qui doivent interroger Elasticsearch, et au propriétaire des
> correlation searches qui l'appellent. Les objets de connaissance d'ES (CIM,
> Asset & Identity, tags) ne s'appliquent pas aux résultats live : voir § 9bis.

### Réserver un profil à certains rôles (`allowed_roles`)

Un profil correspond à **une** identité Elasticsearch, partagée par tous ceux qui
l'utilisent. Pour que des utilisateurs Splunk n'aient pas les mêmes droits côté
Elasticsearch, on crée **un profil par identité** (une clé API pour le SOC, une
autre pour les RH…) et on réserve chaque profil aux rôles Splunk concernés. Page
Configuration → bloc « Qui peut utiliser ce profil ? » — choix **obligatoire**
pour tout profil, avec ou sans authentification :

| Choix | `allowed_roles` | Qui passe |
|---|---|---|
| Administrateurs seulement | `admin` | le rôle `admin` (ou `sc_admin` sur Splunk Cloud), direct ou hérité |
| Tous les porteurs d'esearch_run | `*` | tout utilisateur qui a `esearch_run` |
| Seulement les rôles cochés | `soc_analyst,rh_enquete` | ces rôles, **directs ou hérités**, plus les administrateurs |

- **Où c'est contrôlé** : dans le proxy REST, avant toute lecture de secret,
  pour `| esearch`, `| esindices` et `| esprofiles`. Le proxy est le seul chemin
  vers un profil ; la commande, qui tourne avec les droits de l'utilisateur, ne
  pourrait pas se protéger elle-même.
- **Ce que l'utilisateur voit** : seulement ses profils. Le menu Profil de la
  page Query (`| esprofiles`) ne liste que les profils qui lui sont ouverts.
- **Refus, neutre** : un profil interdit et un profil inexistant reçoivent le
  même message — « profil 'soc' inconnu ou non autorisé — profils disponibles
  pour vous : public, tous ». Il ne révèle ni l'existence du profil ni les rôles
  qui y ont droit. Le motif exact reste dans esearch.log, réservé aux
  administrateurs : `proxy: REFUS user=alice profil=soc allowed_roles=… rôles=…`
  ou `… motif=inconnu`.
- **Les administrateurs passent toujours** : ils peuvent de toute façon modifier
  la configuration. Sont administrateurs `admin` et `sc_admin`, qui le
  remplace sur Splunk Cloud (directs ou hérités).
- **Délai** : les rôles lus sont gardés 60 s par le proxy, **pour une même
  session** (les pages d'une recherche). Une nouvelle connexion relit les siens.
  Pour les comptes d'annuaire, les délais propres à Splunk s'ajoutent :
  voir « Comptes LDAP et SAML » ci-dessous.
- **Clé absente ou vide** (conf écrite à la main) : profil **ouvert**. La page l'affiche « ⚠ non configuré
  (ouvert) » et oblige à choisir à la prochaine édition. Une valeur illisible
  (`*, soc`, espace, `:`, `/`) **ferme** le profil à tous, avec un message qui
  le dit — une restriction mal écrite ne doit pas valoir ouverture.
- **Profil sans authentification** : même règle.

**Recherches enregistrées et tableaux de bord : sous quelle identité ?** Le
contrôle porte sur l'utilisateur **qui exécute** la recherche, ce qui n'est pas
toujours celui qui la lance (mesuré sur Splunk 9.3) :

| Recherche | S'exécute en | Profil réservé à `soc_analyst`, lancé par alice |
|---|---|---|
| Recherche ad hoc, panneau de tableau de bord | l'utilisateur qui regarde | refusé |
| Enregistrée, propriétaire alice | alice | refusé |
| Enregistrée, `dispatchAs = user` | celui qui la lance | refusé |
| Enregistrée, propriétaire `nobody` (partagée, planifiée ou lancée à la main) | `splunk-system-user`, qui hérite d'`admin` | **admis** |
| Enregistrée, propriétaire admin, `dispatchAs = owner` (défaut) | admin | **admis** |

Les deux dernières lignes passent parce qu'elles s'exécutent en administrateur.
C'est voulu : une recherche partagée de propriétaire `nobody` — correlation
search, matérialisation (§ 9bis) — doit fonctionner quel que soit le profil.
Conséquence : **qui peut créer ou modifier une recherche de propriétaire nobody,
ou d'un administrateur, peut s'en servir pour atteindre un profil réservé.** La
restriction qui tient dans tous les cas se pose **côté Elasticsearch** : donner à
l'identité de chaque profil les seuls index qu'elle doit lire (rôle ES, clé API
limitée). `allowed_roles` choisit qui, côté Splunk, utilise quelle identité ; il
ne remplace pas les droits de cette identité.

> Évolution possible, non implémentée : un réglage par profil interdisant les
> exécutions en `splunk-system-user`, pour réserver un profil sensible aux seules
> recherches interactives.

### Profil par défaut : ordre de priorité

Une recherche sans `profile=` (`| esearch query="…"`, `| esindices`) utilise le
**premier profil de la liste de priorité que l'utilisateur a le droit
d'utiliser**. La recherche l'annonce : « profil par défaut : soc (le premier de
vos profils dans l'ordre fixé par l'administrateur ; profile= pour en choisir un
autre) ». Le menu Profil de la page Query suit le même ordre et présélectionne
ce profil.

- **Réglage** : page Configuration → onglet *Profils* : la liste est dans
  l'ordre de priorité (flèches ↑ ↓ de chaque ligne, puis *Enregistrer l'ordre*
  dans la barre qui apparaît ; flèches inactives pendant un filtrage). Stocké dans
  `[settings] profile_order = soc,rh,public`. Un profil absent de la liste vient
  ensuite, par ordre alphabétique — un profil créé n'est jamais perdu.
- **Vérifier** : bouton *Vérifier pour un rôle* au-dessus de la liste — cocher
  les rôles d'un utilisateur affiche son profil par défaut (surligné dans la
  liste) et ses autres profils autorisés (rôles hérités compris).
- **Plusieurs rôles** : l'utilisateur ne sort jamais de ses droits — le profil
  par défaut est choisi **parmi ses profils autorisés**, le premier dans l'ordre.
  Un profil interdit placé en tête est simplement sauté pour lui.
- **Aucun profil autorisé** : « aucun profil disponible pour vous : demandez à un
  administrateur l'accès à un profil ».
- **Recherches de propriétaire nobody** : elles s'exécutent en
  `splunk-system-user`, qui hérite d'`admin` et passe tout profil : sans
  `profile=`, elles prennent donc le **premier profil de la liste**. Préciser
  `profile=` dans les recherches enregistrées rend leur résultat indépendant de
  l'ordre.

### Comptes LDAP et SAML : quand un retrait de groupe prend effet

Avec un annuaire, les rôles viennent des groupes (`roleMap` d'authentication.conf),
et c'est Splunk qui les résout. Le proxy lit ce que Splunk lui donne pour la
session qui appelle. Mesuré sur Splunk 9.3.14, puis 10.4.1 à l'identique
(OpenLDAP ; Keycloak 26.4.2 en SAML) : les droits et le profil par
défaut se comportent comme avec des comptes natifs, rôles multiples compris.
Ce qui diffère, c'est le **moment** où un retrait de groupe prend effet :

| Compte | Recherche interactive | Recherche planifiée du compte (il n'est pas connecté) |
|---|---|---|
| LDAP | à la connexion suivante (mesuré : 2 s) | **rôles gardés en cache par Splunk** : accès conservé au moins 948 s (aucune limite observée) ; retiré **aussitôt** par un rechargement de l'authentification |
| SAML | une session ouverte garde les rôles de sa connexion ; une nouvelle connexion prend les nouveaux | **rôles de la dernière connexion**, même après rechargement ; rafraîchis à la prochaine connexion de l'utilisateur |

À faire quand on retire un utilisateur d'un groupe qui ouvre un profil réservé :

- **LDAP** : recharger l'authentification — *Paramètres → Méthodes
  d’authentification → Recharger la configuration d'authentification*
  (libellés de Splunk Web en français), ou
  `curl -k -u admin -X POST https://localhost:8089/services/authentication/providers/services/_reload`.
- **SAML** : Splunk n'interroge le fournisseur hors connexion que par deux
  mécanismes, tous deux mesurés (ci-dessous) : une **extension
  d'authentification** (script `getUserInfo`), ou la **requête d'attributs**
  (AQR) si le fournisseur la propose. Sans l'un d'eux : désactiver ou
  réattribuer les recherches planifiées de l'utilisateur, ou le désactiver dans
  Splunk ; ses sessions ouvertes gardent leurs rôles jusqu'à leur expiration.
- Dans les deux cas, la protection qui ne dépend d'aucun cache reste la même :
  révoquer, côté Elasticsearch, ce que l'identité du profil n'a plus à lire.

Groupes **imbriqués** en LDAP (un groupe membre d'un autre) : avec
`nestedGroups = 1` dans la stratégie, le compte reçoit le rôle du groupe parent ;
avec `nestedGroups = 0`, il ne le reçoit pas (contrôle négatif mesuré). Un profil
réservé au groupe parent s'ouvre donc aux membres des sous-groupes **seulement**
si la stratégie l'active.

#### SAML : rafraîchir les rôles hors connexion

Mesuré sur Splunk 9.3.14 (Keycloak 26.4.2 et Shibboleth IdP 5.2.3), retrait du
groupe chez le fournisseur, recherche planifiée privée de l'utilisateur lancée
en son absence :

| Mécanisme | Effet mesuré | Conditions |
|---|---|---|
| Aucun | accès conservé jusqu'à la prochaine connexion de l'utilisateur ; le rechargement de l'authentification n'y change rien | — |
| Extension d'authentification (`scriptPath`, `scriptFunctions = getUserInfo`) | accès retiré une fois `getUserInfoTtl` écoulé (mesuré : 63 s pour un TTL de 30 s) | `useAuthExtForTokenAuthOnly = false` — **sa valeur par défaut, `true`, réserve l'extension aux jetons** : sans ce réglage, elle n'est jamais appelée pour une recherche planifiée. Sortie du script : `--status=success --userInfo=<user>;<nom>;<grp1:grp2>;<email>` (les groupes en **troisième** position, séparés par `:`) |
| Requête d'attributs (AQR, `attributeQuerySoapUrl` / `idpAttributeQueryUrl`) | accès retiré une fois `attributeQueryTTL` écoulé, puis rendu quand le groupe revient | voir ci-dessous : Splunk et un fournisseur standard ne s'entendent pas sans aménagement |

Les deux TTL valent **21 600 s (6 h)** par défaut : sans réglage, un retrait de
groupe met jusqu'à six heures à atteindre les recherches planifiées.

**AQR, exigences constatées** (Shibboleth IdP 5.2.3) :

- Splunk envoie sa requête SOAP en `Content-Type: text/plain` ; Shibboleth la
  rejette (`RequestUnsupported`) et Splunk garde, **sans le signaler**, les rôles
  en cache. Il faut, devant le fournisseur, un relais HTTP (proxy inverse ou
  petit service) qui réécrit cet en-tête en `text/xml` et transmet le corps et
  la réponse tels quels ; `attributeQuerySoapUrl` pointe alors sur ce relais.
- Le `NameID` de la requête est au format `persistent` : le fournisseur doit
  savoir le résoudre vers le compte.
- Splunk demande les attributs de rôle, de nom et de courriel (`role`,
  `realName`, `mail`, d'après `authentication.conf`) au format de nom `uri` : le
  fournisseur doit les publier sous ce format.
- Les métadonnées SP de Splunk (`/services/admin/SAML-sp-metadata`) portent un
  attribut `index` sur `SingleLogoutService`, invalide au schéma SAML : un
  fournisseur strict les refuse, il faut le retirer avant import.
- Si le fournisseur répond `UnknownPrincipal`, Splunk **supprime l'utilisateur**
  (`Removing SAML user … user not found`), recherches planifiées comprises dans
  leurs effets : une erreur de configuration côté fournisseur se paie cher.

Okta, ADFS, Entra ID : non testés ; vérifiez ces points chez votre
fournisseur avant de compter sur l'AQR.

### Qui a fait quoi, côté Elasticsearch (`X-Opaque-Id`)

Chaque requête envoyée à Elasticsearch porte l'en-tête
`X-Opaque-Id: splunk/<utilisateur>` — l'utilisateur Splunk qui exécute la
recherche (`splunk-system-user` pour une recherche de propriétaire nobody), via
le proxy comme en mode ad hoc (vérifié sur le fil). Elasticsearch le reporte dans l'API des tâches
(`GET _tasks?detailed`), les slow logs et les journaux de dépréciation : un
administrateur du cluster distingue ainsi les utilisateurs Splunk derrière une
même clé API. **Traçabilité seulement** : Elasticsearch n'en tire aucun droit.
Il figure aussi dans l'audit log d'Elasticsearch (licence payante ; vérifié
avec la licence d'essai d'ES 8.17.4) : champ `opaque_id` des événements
`indices:data/read/search`. Le
nom est encodé en pourcentage (un en-tête HTTP n'admet pas les caractères non
ASCII) : `jean dupont` devient `splunk/jean%20dupont`.

Chaque requête porte aussi `User-Agent: SA-esearch/<version>` :
un proxy sortant, un pare-feu applicatif ou les journaux d'accès
d'Elasticsearch identifient l'app et sa version, au lieu de
`python-requests/2.32`.

---

## 6. Réactiver le mode ad hoc (es_host= en SPL)

Désactivé par défaut (anti-SSRF). Pour l'autoriser (environnement de test, dépannage) :
```ini
# local/esearch.conf
[settings]
allow_adhoc_host = true
```
⚠️ En le réactivant, tout utilisateur pouvant lancer `esearch` peut faire
émettre des requêtes par le search head vers une URL arbitraire. À éviter en prod.

**Identifiants en mode ad hoc** (`user=`/`password=`, `apikey=`, ou
`compte:mot_de_passe@` dans `es_host`) : la fonction reste, mais **Splunk écrit le
texte complet de la recherche** — identifiants compris — dans `audit.log` (index
`_audit`), l'historique et l'inspecteur de la recherche, **avant** que la commande
ne démarre (mesuré). L'app ne peut pas l'empêcher ; son propre journal
(`esearch.log`) les masque. La recherche affiche un avertissement qui le dit. Préférer un profil (secret chiffré dans `storage/passwords`) ; à
défaut, restreindre la lecture de `_audit` et `_internal` aux administrateurs.

---

## 7. mTLS (certificat client)

```ini
[profile:prod]
es_host = https://es.example.com:9200
client_cert = $SPLUNK_HOME/etc/auth/esearch/client.pem
client_key  = $SPLUNK_HOME/etc/auth/esearch/client.key
```

**Où ranger certificats et clés : `$SPLUNK_HOME/etc/auth/esearch/`**, à côté des
certificats de Splunk lui-même — c'est la convention de la documentation Splunk
(un sous-dossier de `etc/auth` par usage). **Jamais dans le répertoire de
l'app** : un serveur de déploiement remplace tout le répertoire de l'app à
chaque redéploiement (sauf `excludeFromUpdate`), ce qui ferait disparaître les
certificats et casserait le mTLS ; et une clé privée n'a pas à voyager avec
l'app.

Les chemins suivent la convention des `.conf` de Splunk :
`$SPLUNK_HOME` est remplacé, et un chemin relatif est pris sous `$SPLUNK_HOME`
(`etc/auth/esearch/ca.pem`). Pas de chemin absolu propre à une machine dans
`esearch.conf`.

```bash
mkdir -p "$SPLUNK_HOME/etc/auth/esearch"
cp ca.pem client.pem client.key "$SPLUNK_HOME/etc/auth/esearch/"
chown -R splunk: "$SPLUNK_HOME/etc/auth/esearch"
chmod 700 "$SPLUNK_HOME/etc/auth/esearch"; chmod 600 "$SPLUNK_HOME/etc/auth/esearch/"*.key
```
La clé PEM doit être **non chiffrée**. Clé protégée par passphrase :
```bash
openssl rsa -in client-encrypted.key -out client.key   # demande la passphrase
chmod 600 client.key
```
Clé : permissions `600`, propriétaire = utilisateur Splunk.

**Erreurs détectées à la lecture du profil**, avec un message
qui les nomme, avant tout appel réseau : `ca_file` illisible (format DER au lieu
de PEM — la conversion est indiquée), clé chiffrée par une phrase de passe, clé
qui ne correspond pas au certificat, certificat ou clé illisible.

**Erreurs de la poignée de main TLS** : la cause est traduite en clair sur les deux chemins, par une phrase fixe (jamais le texte brut de
l'exception) — CA absente de `ca_file`, nom d'hôte absent du certificat,
certificat serveur expiré ou pas encore valide, certificat client absent ou
refusé, protocole TLS sans version commune, `http://` vers un port TLS. Le
détail technique reste dans `esearch.log`.

**TLS 1.3 seul** : le Python de Splunk 9.x (OpenSSL 1.0.2) ne parle pas TLS 1.3.
Un cluster qui n'accepte que TLS 1.3 est injoignable depuis Splunk 9.x
(vérifié) : autoriser TLS 1.2 côté Elasticsearch, ou passer en Splunk 10.x.

### Certificat de transport ou certificat d'identité ?

Deux usages distincts d'un même certificat client :

- **mTLS** (`xpack.security.http.ssl.client_authentication`) : Elasticsearch
  exige un certificat client valide pour établir la connexion. Fonctionne avec
  toutes les licences, y compris la licence gratuite (vérifié).
- **Authentification par certificat** (domaine **PKI** d'Elasticsearch) :
  Elasticsearch déduit l'IDENTITÉ de l'appelant du certificat, sans mot de
  passe ni clé API — profil `auth_type = none` + `client_cert`. Exige une
  licence **Platinum/Enterprise** (ou d'essai) : sans elle, Elasticsearch ignore
  ce domaine et répond 401.

Si le domaine PKI associe à un rôle le certificat client
que présente l'app pour le mTLS, ce certificat est AUSSI une identité. Or
Elasticsearch, face à une clé API invalide (révoquée, expirée), **retombe sur
le certificat** : l'accès continue, sous l'identité du certificat. Vérifié :
révoquer la clé ne coupe rien.

- Séparer les deux : certificat de **transport** (mTLS) d'une CA que le domaine
  PKI ne reconnaît pas, certificat d'**identité** d'une autre (paramètre
  `certificate_authorities` du domaine PKI).
- À défaut : pour révoquer l'accès de Splunk, révoquer la clé **et** retirer le
  mapping PKI du certificat.
- L'app le **signale** : pour un profil qui combine
  certificat client et clé API (ou mot de passe), elle vérifie
  (`GET /_security/_authenticate`, un appel par recherche) l'identité
  réellement retenue, et avertit si Elasticsearch a authentifié par le
  certificat : « Elasticsearch n'a pas retenu la clé API du profil… ».

**Clé API refusée (401)** : le message précise la cause probable —
clé au format `id:api_key` (Elasticsearch attend la valeur `encoded`, base64 de
`id:api_key`), ou clé expirée ou révoquée — sans jamais réénoncer la clé.

Un mot de passe `basic` peut contenir n'importe quel caractère (accents, `€`,
écritures non latines) : l'en-tête est encodé en UTF-8.

---

## 7bis. Compression des réponses : `http.compression` côté Elasticsearch

Le volume qui circule entre Elasticsearch et le search head, ce sont les
**réponses** : une page de 10 000 documents pèse de l'ordre de 3 Mo en clair. La
commande les demande toujours compressées (`Accept-Encoding: gzip`), mais
Elasticsearch ne compresse que si **`http.compression`** est active — et ce
réglage vaut `true` en HTTP, **`false` dès que HTTPS est activé**. Sur un cluster
de production, donc en HTTPS, les réponses circulent en clair dans le tunnel TLS.

Mesuré sur Elasticsearch 8.17.4, une page de 10 000 documents :

| Cluster | Content-Encoding | Sur le fil |
|---|---|---|
| HTTPS, configuration par défaut | aucun | 2 628 Ko |
| HTTPS, `http.compression: true` | gzip | 151 Ko (**17 fois moins**) |
| HTTP | gzip | ~10 fois moins que le volume utile |

**Activer** — dans `elasticsearch.yml` de chaque nœud recevant des requêtes HTTP
(réglage **statique** : redémarrage du nœud requis) :

```yaml
http.compression: true
# http.compression_level: 3     # défaut ; plus haut = moins de volume, plus de CPU
```

**Vérifier** depuis le search head — l'en-tête attendu est `Content-Encoding: gzip` :

```bash
curl -s -o /dev/null -D - -H 'Accept-Encoding: gzip' --cacert <ca.pem> \
     -H 'Authorization: ApiKey <clé>' https://<es>:9200/ | grep -i content-encoding
```

**Pourquoi Elasticsearch la désactive en HTTPS : BREACH.** Compresser une réponse
chiffrée laisse fuir sa taille ; un attaquant capable d'**observer** le trafic
chiffré **et** d'**injecter** du contenu qu'il choisit dans des réponses qui
contiennent aussi un secret peut deviner ce secret octet par octet, en comparant
les tailles. Le choix revient à l'administrateur du cluster et à l'équipe
sécurité : le risque porte sur ce lien search head ↔ Elasticsearch et sur ce que
les réponses peuvent mêler (données indexées que d'autres alimentent, et données
sensibles). L'activer est le seul moyen de réduire réellement le volume réseau ;
le coût est du CPU de compression sur les nœuds Elasticsearch.

Compresser les **requêtes** n'apporterait rien : elles font 0,2 à 0,4 Ko.

---

## 8. Déploiement en Search Head Cluster

- Déployer via le **deployer** (`shcluster/apps/`), pas app par app.
- **Profils et secrets se créent sur UN membre** (page *Configuration*, ou REST),
  jamais par le deployer ni dans le paquet : la réplication de configuration du
  cluster les propage. `esearch.conf` est répliqué grâce à
  `[shclustering] conf_replication_include.esearch = true` (fourni par l'app,
  `default/server.conf`) ; les secrets de `storage/passwords` le sont par défaut
  (`conf_replication_include.passwords = true` dans la configuration système), et
  le capitaine réplique `splunk.secret`, qui les chiffre, au déploiement initial. Inutile de les créer sur chaque membre.
- **Non vérifié en cluster réel** : ce qui précède repose sur la documentation
  Splunk et sur la configuration par défaut de Splunk. À vérifier à la mise en service : créer un profil sur un membre, puis
  l'utiliser depuis un autre.
- Les certificats de `$SPLUNK_HOME/etc/auth/esearch/` non plus (hors app, par
  construction) : les déposer sur chaque membre, au même chemin.
- Le log applicatif est dans `$SPLUNK_HOME/var/log/splunk/esearch.log` (hors
  dossier d'app) : pas de conflit de réplication.

---

## 9. Dépannage

| Symptôme | Piste |
|---|---|
| `Unknown search command 'esearch'` | RBAC (§5) : l'utilisateur n'a pas le rôle ; ou app non chargée (restart) |
| « requête ES\|QL : apostrophe en position N » | En ES\|QL, une chaîne s'écrit entre guillemets doubles (`\"…\"` en SPL). Autres messages ES\|QL : § 10.15 |
| « option inconnue : … », « valeur invalide pour … », « query= est obligatoire » | Argument de la recherche à corriger ; le message donne la valeur attendue ou la liste des options. |
| « External search command exited unexpectedly » | Ce n'est pas une erreur d'argument : la commande s'est arrêtée brutalement. Voir le `search.log` du job (inspecteur) et `esearch.log` à la même heure. |
| `Secret introuvable dans storage/passwords` | realm/username incorrects (§4) ou secret non créé |
| `es_host ad hoc désactivé` | normal en prod ; utiliser un profil, ou §6 |
| `Elasticsearch HTTP 401/403` | secret invalide, ou clé ES sans droit de lecture sur l'index |
| Résultats vides mais ES en a | vérifier le time picker et `timefield` ; voir le log |
| `résultats partiels — N shard(s) en échec` | problème côté cluster ES (à investiguer côté ES) |
| « aucun index ne correspond à 'motif' — il n'existe pas, ou l'identité Elasticsearch du profil n'y a pas accès » | Elasticsearch a répondu 0 shard : rien derrière le motif **pour cette identité**. Sur un motif à joker, un cluster sécurisé masque en silence les index non autorisés (un nom exact refusé, lui, donne un 403). Vérifier le nom, puis les droits de la clé du profil. Un motif mixte (`logs-*,secret-*`) ne déclenche pas ce message : seule la partie autorisée est lue, sans avertissement possible. |
| « profil 'x' inconnu ou non autorisé — profils disponibles pour vous : … » | Le profil n'existe pas, ou l'utilisateur n'y a pas droit (`allowed_roles`, § 5) : le message ne distingue pas les deux, par choix. Le motif exact est dans esearch.log (`proxy: REFUS user=… profil=… allowed_roles=… rôles=…` ou `motif=inconnu`). Un changement de rôle vaut dès la connexion suivante ; comptes LDAP/SAML et recherches planifiées : § 5, « Comptes LDAP et SAML ». |
| « profil par défaut : x » | Avertissement normal d'une recherche sans `profile=` : elle a pris le premier profil autorisé dans l'ordre de priorité (§ 5). Préciser `profile=` pour en choisir un autre. |
| « requête trop imbriquée » / « requête trop longue » | Bornes de l'app sur `query=` (30 niveaux de parenthèses, 1 Mio) : au-delà, la requête pouvait arrêter Elasticsearch. § 10.13 |
| « requête trop large : trop de clauses » | Plafond de clauses du cluster (cité dans le message). Un terme sans champ compte une clause par champ de l'index : préfixer le champ (`champ:valeur`) ou réduire la liste. § 10.13 |
| « lookup : The lookup table 'x' requires a .csv or KV store lookup definition » | Lookup `lookup_include=` / `lookup_exclude=` absente, ou non lisible par l'utilisateur dans l'app de la recherche (mêmes droits que `\| inputlookup`). |
| « aucune ligne d'inclusion utilisable (lookup vide) » | Une lookup d'inclusion n'a aucune ligne utile : en `inclusion_type=and`, rien ne peut correspondre, Elasticsearch n'est pas interrogé. |
| « The number of terms [N] used in the Terms Query request has exceeded the allowed maximum of [65536] » | `lookup_mode=terms` : une lookup dépasse `index.max_terms_count` (65 536 par défaut, réglable par index côté Elasticsearch). Réduire la lookup ou relever le réglage. |
| « lookup_mode=terms exige UNE colonne » / « valeur à joker » | Mode terms : choisir la colonne (`lookup_fields_keep`), ou repasser en `lookup_mode=lucene` pour les lookups à plusieurs colonnes ou à jokers. |
| « colonne 'x' inutilisable comme champ Elasticsearch » | Colonne de lookup au nom invalide (espace…) : l'écarter par `lookup_fields_ignore` ou le réglage global. |
| « syntaxe de requête invalide : … » | Requête Lucene mal formée ; la position de l'erreur est donnée (`line 1, column 9`). |
| « aucun profil disponible pour vous » | Recherche sans `profile=`, et aucun profil n'est ouvert à l'utilisateur (`allowed_roles`), ou aucun n'est déclaré. |
| « accès au proxy esearch refusé : la capability 'esearch_run' est requise » | rôle sans `esearch_run` (mode restreint, § 5) |
| `open_contexts` élevé sans recherche active | recherches **annulées** : chaque abandon retient un contexte de pagination jusqu'à l'expiration de `[settings] page_keep_alive` (défaut `2m`), puis il se libère seul. Baisser ce réglage si vos utilisateurs annulent beaucoup. |
| « contexte de pagination a expiré entre deux pages » + résultats PARTIELS | sous charge, le cluster (ou le proxy) a mis plus que `[settings] page_keep_alive` (défaut `2m`) à servir la page suivante, et Elasticsearch a libéré le contexte. Relancer ; si c'est fréquent, augmenter `page_keep_alive` (page *Configuration*, ou `esearch.conf`) (au prix de contextes retenus plus longtemps à l'annulation, ligne précédente) ou matérialiser (§ 9bis). |
| Boucle vers une **page de réglage** à l'ouverture de l'app | un `local/app.conf` force `[ui] setup_view` ou `is_configured` : l'y retirer, puis `_reload` l'app. La config passe par le menu → *Configuration*, sans setup obligatoire. |

Détail d'un job : `$SPLUNK_HOME/var/run/splunk/dispatch/<sid>/search.log`.

### Journal de l'app (`esearch.log`)

Vérifié sur Splunk 9.3.14 : chaque famille d'entrées a été déclenchée, puis des
marqueurs uniques (secrets, texte de requête) ont été cherchés dans tous les
journaux de Splunk.

**Où.** `$SPLUNK_HOME/var/log/splunk/esearch.log`, fichier rotatif de 5 Mo
gardé en 3 copies (`esearch.log.1` à `.3`, lu dans le code, rotation non
provoquée), droits `600`, compte `splunk`. S'il ne peut pas être ouvert, les
lignes partent sur la sortie d'erreur, donc dans le `search.log` du job.
Splunk l'**indexe dans `_internal`** (aucun coût de licence : mesuré, le
compteur de licence ne voit pas cet index). Le rôle `user` ne peut pas chercher
`_internal` (vérifié).

**Sourcetypes.** L'app les déclare (`props.conf` / `transforms.conf`) : sans
eux, Splunk en apprendrait un au hasard du contenu, et une recherche par
sourcetype perdrait des lignes. Segmentation **sans priorité**, par règles
disjointes :

| Sourcetype | Contenu |
|---|---|
| `esearch:log` | lignes ordinaires (INFO, WARNING, ERROR) |
| `esearch:log:debug` | lignes `[DEBUG]` du niveau global (`log_level = DEBUG`), sans marqueur ; les lignes INFO de la même période restent `esearch:log` |
| `esearch:log:debug_search` | lignes d'une recherche `debug=true`, reconnues à leur marqueur `[debug …]` placé juste après le pid (un texte `[debug sid=…]` glissé dans un message ne trompe pas la règle) |

Champs extraits à la recherche : `niveau`, `pid`, `composant` (`esearch`,
`proxy`…), `debug_sid`, `debug_tag` ; les `clé=valeur` des messages (`user`,
`profil`, `index`…) le sont par Splunk. Date et découpage déclarés
(une ligne = un événement), `TRUNCATE` porté à 100 000 octets pour la ligne de
la requête envoyée.
Exemple : `index=_internal sourcetype=esearch:log:debug_search debug_tag=incident-42`.

**Bornes.** Une saisie démesurée ne gonfle ni le journal ni les messages :

| Cas | Comportement |
|---|---|
| Toute ligne du journal (un `index=` ou un `profile=` de 1 Mo, par exemple) | bornée à 60 000 octets, sous le `TRUNCATE` de 100 000 de Splunk, coupe dite `[...] et X caractères de plus` ; sans cela, Splunk tronquerait en silence et quelques recherches feraient tourner le fichier |
| `debug_tag=`, `sort=`, index, noms ou types de lookups, colonne, valeur invalides et très longs | valeur citée sur 80 caractères dans le message d'erreur, coupe dite |
| Requête affichée en debug (valeurs `terms` ou noms de champ démesurés) | valeurs et noms de champ `terms` à 200 caractères, toute chaîne à 10 000, texte entier à 50 000, coupe dite |
| U+0085, U+2028, U+2029 dans une valeur | neutralisés (`\u2028`…), comme les caractères de contrôle : pas de fausse fin de ligne |
| Fichier partagé : une recherche fait tourner `esearch.log` | avant chaque écriture, le fichier est rouvert si le chemin ne désigne plus celui qu'on tient : le proxy persistant n'écrit pas dans l'ancien fichier |

**Limite acceptée.** Plusieurs processus écrivent le
même fichier et chacun peut le faire tourner : si deux le font au même instant,
une rotation peut être perdue ou un fichier écrasé — la bibliothèque `logging`
de Python ne prend pas en charge ce cas (documenté par Python). Risque gardé :
il faut deux dépassements de 5 Mo simultanés, et la perte se limite à des lignes
de journal (non mesuré ; Splunk lit le fichier au fil de l'eau, une ligne déjà
lue reste dans `_internal`). Une rotation par
un seul processus imposerait de faire écrire les commandes par le proxy.

**Qui écrit.** Les commandes (`esearch:`, `esindices:`, `esprofiles:`), dans le
processus de la recherche, et le proxy (`proxy:`), processus persistant de
splunkd ; le `pid` les distingue. Format :
`date [NIVEAU] [pid=N] message`. Deux protections s'appliquent à toute ligne :
les caractères de contrôle sont neutralisés (un saut de ligne devient `\x0a`, aucune
fausse entrée ne peut être forgée par un nom de profil ou d'index), et les
identifiants d'une URL sont masqués (`http://***@hôte`).

**Niveau.** Deux réglages, qui donnent le même contenu :

- `[settings] log_level`, `INFO` par défaut : **global**, toutes les recherches
  de tous les utilisateurs. Il se pose par la page *Configuration* (*Niveau de
  log*), `local/esearch.conf` ou REST, et vaut dès la recherche suivante
  (README, « Exploitation »). Revenir à `INFO` après un diagnostic ;
- `| esearch … debug=true` : **cette recherche seulement**, quel que
  soit `log_level`. Ce qu'elle écrit dépend de `[settings] debug_search_scope` : `query` (défaut), **la seule requête envoyée à Elasticsearch**
  (`esearch: requête envoyée POST <url> <corps JSON>`) ; `all`, toutes ses
  lignes, commande et proxy. Les lignes écrites portent le marqueur
  `[debug sid=<sid>]`, complété par `debug_tag=<nom>`. Le niveau du journal
  partagé n'est pas modifié : les recherches voisines, servies par le même
  processus proxy, n'en héritent pas (testé). Le sid et l'étiquette transmis
  au proxy y sont revalidés (forme bornée, 400 sinon).

**Ce qu'une recherche `debug=true` montre à son auteur** :

- **la requête envoyée, en warning** : `esearch debug — requête envoyée à
  Elasticsearch : POST https://es.example.com:9200/logs-web/_search {…}`. C'est le corps
  que le proxy a réellement construit et envoyé (il le renvoie à la commande),
  pour la première page ; la pagination (PIT, scroll) y ajoute ses propres
  champs. Listes `terms` coupées à `[settings] debug_terms_max` (100), chaînes
  à 10 000 caractères, coupe dite (`"[...] et 65437 de plus"`) ; identifiants
  d'URL masqués. **Pas de warning pour une recherche planifiée** (sid
  `scheduler__…`, vérifié sur une vraie planification) : ses messages peuvent
  être lus par d'autres que son auteur ;
- **dans la page Query**, la même requête dans un panneau, corps indenté ;
- **dans le search.log du job** (inspecteur) : les lignes écrites au journal
  pour cette recherche (selon la portée), commande et proxy. Splunk étiquette
  ERROR toute sortie d'erreur d'une commande, sans réglage possible : le vrai
  niveau est en tête de ligne (`stderr: [DEBUG] [debug sid=…] esearch: requête
  envoyée …`). C'est la voie standard du SDK Splunk (son propre logger écrit
  sur la sortie d'erreur).

L'appel de la commande vers le proxy (boucle locale, certificat autosigné de
splunkd) n'écrit pas d'`InsecureRequestWarning` dans le search.log.

En DEBUG global, deux lignes s'ajoutent par recherche : le texte de la requête
(`esearch: query=…`) et la requête envoyée. Exemple relevé, portée `all`,
`debug=true debug_tag=incident-42` (pid 85002 : la commande ; pid 85031 : le
proxy ; la ligne `requête envoyée` s'y ajoute, non reproduite ici) :

```
[INFO]  [pid=85002] [debug sid=1792312743.2 debug_tag=incident-42] esearch: protocole=v2 user=admin profil=prod index=logs-web limit=3
[DEBUG] [pid=85002] [debug sid=1792312743.2 debug_tag=incident-42] esearch: query=status:500
[INFO]  [pid=85002] [debug sid=1792312743.2 debug_tag=incident-42] esearch: action=page profil=prod -> proxy REST
[INFO]  [pid=85031] [debug sid=1792312743.2 debug_tag=incident-42] proxy: user=admin profil=prod index=logs-web limit=3 timeout_read=30
[INFO]  [pid=85031] [debug sid=1792312743.2 debug_tag=incident-42] esearch: POST https://es.example.com:9200/logs-web/_search (une page, size=3)
[INFO]  [pid=85002] [debug sid=1792312743.2 debug_tag=incident-42] esearch: 3 événements émis
```

Exemples relevés, sauf trois tirés du code : configuration douteuse,
repli PIT → scroll et erreur interne.

| Événement | Niveau | Exemple |
|---|---|---|
| Recherche : qui, quel profil, quel index | INFO | `esearch: protocole=v2 user=admin profil=prod index=logs-web limit=5` |
| Bornes de temps, filtre `range` envoyé | INFO | `esearch: bornes temps=searchinfo earliest=… latest=…` ; `esearch: range @timestamp {…}` |
| Passage par le proxy, page servie | INFO | `esearch: action=page profil=… -> proxy REST` ; `proxy: user=admin profil=… index=… limit=5 timeout_read=30` ; `proxy: page de 5 hits, suite=non (0 avertissement(s))` |
| Requête envoyée (hôte et index, pas le corps) | INFO | `esearch: POST https://es.example.com:9200/logs-web/_search (une page, size=5)` |
| Volume | INFO | `esearch: 1 page(s) via proxy privilégié` ; `esearch: 5 événements émis` |
| Version du cluster (si `detect_version = true`), repli PIT → scroll | INFO | `esearch: cluster elasticsearch 8.17.4 (default)` ; `esearch: PIT indisponible (…), repli scroll` |
| Profil par défaut retenu | INFO | `esearch: profil par défaut retenu : public` |
| `\| esindices`, `\| esprofiles` | INFO | `esindices: user=admin profil=… pattern=None` ; `proxy: user=alice N profil(s) disponible(s) : …` |
| Refus d'un profil, avec son motif exact | WARNING | `proxy: REFUS user=alice profil=soc allowed_roles=admin rôles=user` ; `… motif=inconnu` ; `… motif=nom invalide` |
| Configuration douteuse (fichier illisible, continuation de ligne) | WARNING | `conf illisible …` ; `esearch.conf : valeur(s) terminée(s) par '\' …` |
| Erreur rendue à l'utilisateur | ERROR | `esearch: Elasticsearch HTTP 400: syntaxe de requête invalide : Encountered "<EOF>" at line 1, column 9.` ; `esearch: Elasticsearch injoignable (ConnectionError) — …` |
| Erreur interne | ERROR | trace Python complète (l'utilisateur ne voit que « erreur interne (détail dans esearch.log) ») |

**Jamais écrit** (vérifié) : les secrets des profils (clé API, mot de passe
basic), l'en-tête `Authorization`, les jetons de session Splunk (aucune chaîne
à leur forme dans le journal et ses rotations), les identifiants placés dans
`es_host`, la valeur des options `user=`/`password=`/`apikey=`. Les secrets
des profils ne se retrouvent dans **aucun** journal de Splunk ni répertoire de
dispatch, et `passwords.conf` ne les garde que chiffrés.

**Écrit, et à savoir** :

- les noms d'utilisateurs Splunk, les profils, les motifs d'index et, dans un
  refus, les rôles de l'appelant : c'est la traçabilité voulue ;
- le **texte de la requête** n'est journalisé qu'en `DEBUG` — global, ou pour
  la recherche d'un utilisateur qui pose lui-même `debug=true` (tout utilisateur
  de la commande le peut, pour ses propres recherches). Une requête refusée par
  Elasticsearch n'est pas recopiée en `ERROR` : l'erreur cite la cause, pas la
  requête (vérifié) ;
- l'hôte Elasticsearch des profils (lignes `POST`, erreurs de connexion) ;
- quand le secret d'un profil manque, le nom du compte qu'on cherchait :
  `Secret introuvable (realm='esearch:<profil>', username='<compte>')` — pour un
  profil basic, c'est l'identifiant Elasticsearch, pas son mot de passe.

**Hors de l'app**, Splunk garde de son côté :

- le **texte SPL** de chaque recherche : `audit.log` (indexé dans `_audit`) et,
  dans le dispatch du job, `info.csv`, `request.csv`, `status.csv` et
  `search.log`. Des identifiants écrits dans le SPL en mode ad hoc
  (`es_host="http://compte:secret@…"`, `password=`) y restent **en clair** :
  masqués dans `esearch.log`, pas chez Splunk. C'est une raison de plus de
  passer par les profils (§ 3 et § 6) ;
- `splunkd_access.log` : chaque appel au proxy et chaque écriture REST de
  configuration ou de secret, celles que fait la page Configuration
  (utilisateur, URL — donc nom du profil —, statut) ; jamais le corps de la
  requête, donc jamais un secret.

Côté Elasticsearch, chaque requête porte `X-Opaque-Id: splunk/<utilisateur>`
(§ 5).

---

## 9bis. Matérialiser des résultats esearch — **approche recommandée** pour tout usage récurrent

Au lieu de requêter Elasticsearch à chaque affichage, une **recherche planifiée**
interroge ES périodiquement et écrit le résultat dans Splunk. Les dashboards,
lookups et **correlation searches Splunk ES** lisent alors la copie locale.
L'app fournit des **templates désactivés** (`savedsearches.conf`) à cloner dans
`local/`.

### Quand matérialiser, quand interroger en direct

| | Requête live (`\| esearch`) | Matérialisation |
|---|---|---|
| Exploration ponctuelle, ad hoc | ✅ | — |
| Dashboard consulté par N personnes | — | ✅ |
| Enrichissement, lookup, Asset & Identity | — (objets globaux non appliqués, ci-dessous) | ✅ |
| Correlation search planifiée | possible | ✅ préférable |
| Gros volumes répétés | — | ✅ |

**Règle simple : requête récurrente ou volumineuse → matérialisation ;
exploration ponctuelle → requête live.**

### Ce que la matérialisation supprime comme contraintes

Tout ce qui pèse sur le chemin live disparaît, parce qu'il n'y a plus qu'**une**
requête par intervalle au lieu d'une par utilisateur :

- **charge Elasticsearch** : constante et prévisible, quel que soit le nombre
  d'utilisateurs ;
- **mémoire du search head** : bornée par la recherche planifiée, pas par le
  produit `utilisateurs × volume` ;
- **contextes de pagination** : plus de PIT retenu par des recherches
  interactives annulées (cf. §9, ligne `open_contexts`) ;
- **disponibilité** : les dashboards continuent de fonctionner si le cluster ES
  est injoignable — ils lisent une copie locale.

Contrepartie unique : la **fraîcheur**. Les données ont l'âge de la
planification. C'est le seul arbitrage à faire.

> Précédent utile : l'add-on `SA-SentinelOneDevices` publié par Splunk pour
> Enterprise Security ne contient **aucun code** — uniquement des recherches
> planifiées alimentant une collection KV Store, et un lookup par-dessus. Pour
> un cas d'usage d'enrichissement d'actifs, c'est exactement ce motif qui a été
> retenu, sans requête live du tout.

### Objets de connaissance : appliqués à la copie, pas aux résultats live

Les objets de connaissance **globaux** — alias, champs calculés et lookups
automatiques (y compris en strophe `[default]`, comme les enrichissements Asset &
Identity de Splunk ES), strophes `[host::…]`, eventtypes et tags (dont ceux du
CIM) — **ne s'appliquent pas** aux événements produits par `| esearch`, même
suivis d'un `| search`. Splunk ne les applique qu'aux événements **lus depuis un
index**. Vérifié sur Splunk 9.3.14.

Deux façons d'en bénéficier :

- **explicitement** sur le résultat live : `| lookup <table> host OUTPUT …`,
  `| typer | tags` (vérifiés) ;
- **en matérialisant** dans un index (variante B) : à la relecture, les objets
  globaux s'appliquent normalement.

### Variante A — KV Store (état courant / enrichissement)
Collection `esearch_cache` + lookup du même nom (fournis). Mise à jour par `_key`,
**le document le plus récent** de chaque clé :
```spl
| esearch profile=prod index="assets-*" query="*" limit=50000 sort=desc
| dedup host
| eval _key=host, materialise_le=now()
| outputlookup append=true esearch_cache
```
Chacun des trois ajouts évite un défaut mesuré : sans `append=true`,
`outputlookup` **remplace toute la collection** à chaque passage ; sans
`sort=desc | dedup`, les documents d'une même clé s'écrasent dans un ordre
quelconque ; sans `materialise_le`, la rétention porte sur `_time` — la date du
document Elasticsearch — et **vide la collection** juste après l'avoir remplie.
Lecture / enrichissement : `... | lookup esearch_cache host OUTPUT ip owner category`.
Les champs sont préservés en **colonnes**. **Important** : seuls les champs listés
dans `fields_list` (transforms.conf `[esearch_cache]`) sont stockés/lus — un lookup
KV Store l'exige. La liste fournie est un **exemple** (champs d'actif/log courants) :
**adaptez-la à votre schéma ES** dans `local/transforms.conf`. Rétention : template
`esearch_cache_retention_TEMPLATE`, qui purge les entrées **non rafraîchies**
depuis 2 jours (`materialise_le`). Nécessite le KV Store activé.

### Variante B — summary index (historique / tendances)
```spl
| esearch profile=prod index="logs-*" query="status:500" limit=50000
| fields - _raw
| collect index=esearch_summary
```
`fields - _raw` est **indispensable** : sans lui, `collect` écrit le JSON
d'Elasticsearch tel quel et, à la relecture (sourcetype `stash`), **aucun champ
n'est extrait**. Sans `_raw`, chaque champ est écrit en `clé="valeur"` et
retrouvé à la relecture, objets de connaissance globaux compris.
⚠️ `collect` fixe `host`/`source`/`sourcetype` à ceux du search head : le `host`
venant d'Elasticsearch est conservé sous **`orig_host`** — à utiliser (ou
renommer avant `collect`) pour tout enrichissement par hôte. À réserver au
trending/métriques (l'index grossit).

### Activer un template
Copier la stanza voulue depuis `default/savedsearches.conf` vers
`local/savedsearches.conf`, régler `profile`/`query`/`_key`/`cron_schedule`, puis
`disabled = 0` et `enableSched = 1`.

---

## 10. Limites connues

Ces limites sont assumées : elles sont documentées ici pour qu'un exploitant les
découvre avant la production, pas après.

### 10.1 Contexte Elasticsearch retenu à l'annulation d'une recherche
Quand un utilisateur annule une recherche (ou ferme l'onglet) au milieu d'une
pagination, la commande s'arrête sans pouvoir fermer proprement le contexte de
pagination ouvert côté Elasticsearch (PIT ou scroll). Ce contexte n'est donc pas
libéré immédiatement : il expire tout seul au bout de `[settings] page_keep_alive`
(défaut `2m`).

- **Impact** : sur un cluster ES, chaque contexte consomme des ressources et le
  nombre de scrolls simultanés est plafonné (`search.max_open_scroll_context`,
  défaut 500). Beaucoup d'annulations rapprochées, sur beaucoup d'utilisateurs,
  peuvent donc saturer temporairement ce plafond.
- **Surveillance** : `GET _nodes/stats/indices/search` → `open_contexts`
  (voir § 9), et `GET _nodes/stats` → `search.scroll_current`.
- **Atténuation** : baisser `page_keep_alive` si vos utilisateurs annulent
  beaucoup. Attention : le délai est ré-armé à chaque page, mais il doit rester
  supérieur au temps écoulé **entre deux pages** — sinon une recherche légitime
  mais lente verra son contexte expirer en cours de route et échouera. Le défaut
  `2m` couvre largement une page nominale ; en dessous d'une minute, vérifier
  d'abord la latence réelle de vos pages sur l'index le plus lourd.
- **Pas de nettoyage automatique** : l'app ne balaie pas les contextes orphelins,
  volontairement — elle ne peut pas distinguer les siens de ceux d'un autre client
  du même cluster.

### 10.2 Volume : un plafond par réponse, pas par recherche
`limit` et `[settings] max_limit` bornent le **nombre de documents** ramenés, pas
leur **taille**. Un index dont les documents font plusieurs centaines de Ko
(payloads bruts, traces complètes, champs `message` très longs) peut donc produire
un volume important même sous un `limit` modeste.

**Plafond par réponse** (`[settings] max_response_mb`, défaut 256 Mo) :
chaque réponse d'Elasticsearch — une page de recherche (jusqu'à 10 000
documents), une réponse ES|QL — est lue **décompressée, par morceaux**, et la
recherche échoue au-delà, avec un message qui nomme le réglage. Il protège le
search head d'une réponse hostile : sans lui, 298 Ko de gzip occuperaient
300 Mo de mémoire, et ~1 Ko suffirait en `gzip, gzip` (mesuré). Un encodage chaîné ou inattendu est refusé
avant lecture. Le dépassement est borné à ~16 Mo au-dessus du plafond (mesuré :
+85 Mo de mémoire pour un plafond de 64 Mo face à une bombe de 300 Mo). Défaut :
une page de 10 000 documents de 26 Ko en moyenne ; une page de journaux
applicatifs ordinaires en fait environ 3 Mo. Le total d'une recherche paginée n'est pas plafonné, seulement
chaque page.

Résiduel connu (urllib3 1.26, corrigé en 2.8, qui exige Python 3.10) : en
`Transfer-Encoding: chunked`, une ligne de taille de morceau démesurée est mise
en mémoire avant le contrôle du plafond. Il faut un serveur hostile (Elasticsearch
compromis, ou usurpé : HTTP en clair, `verify_certs = false`).

- **Impact** : mémoire du search head et bande passante ES↔Splunk. Les réponses
  sont compressées (gzip) si le cluster l'accepte — **pas par défaut en HTTPS**
  (§ 7bis) : cela limite l'effet réseau, jamais l'effet mémoire.
- **Atténuation** : restreindre les champs ramenés côté requête plutôt que
  post-filtrer dans Splunk, et baisser `max_limit` sur les index volumineux.
  Pour un usage récurrent, préférer la matérialisation (§ 9bis).

### 10.3 Collisions de noms de champs
Deux limites structurelles à l'aplatissement des documents ES :

- Un document contenant à la fois `a.b` et un objet `a` avec une clé `b` produit
  deux valeurs pour le même nom de champ. La seconde est conservée sous
  `a.b#2` (puis `#3`…) : rien n'est perdu, mais le nom diffère de la source.
- Un document dont un champ s'appelle `host`, `source` ou `sourcetype` écrase la
  métadonnée Splunk du même nom. Le réglage `[settings] sanitize_metadata_fields`
  (défaut `false`) préfixe ces champs en `es_host` / `es_source` /
  `es_sourcetype` pour éviter la collision. Il est **désactivé par défaut** parce
  qu'il change le nom des champs vus par les recherches existantes : à activer
  au moment du déploiement initial, pas sur un environnement déjà outillé.

### 10.4 Plafond `index.max_result_window`
Une page vaut au maximum 10 000 documents, ce qui correspond au défaut ES
`index.max_result_window`. Au-delà de ce volume par page, ES rejette la requête —
c'est une limite du cluster, pas de l'app. La pagination (PIT + `search_after`)
franchit ce plafond en cumulé ; seule la taille d'**une** page est concernée.

### 10.5 Options de transport plafonnées côté serveur
`retry_count`, `backoff_base` et `timeout_connect` sont acceptés en SPL, mais
**plafonnés** (5 tentatives, 1 s de base d'attente, 30 s de connexion) — côté
commande *et* côté proxy, ce dernier étant appelable directement par tout porteur
d'`esearch_run`. Sans ces bornes, une seule requête pourrait immobiliser un worker
privilégié pendant des dizaines de minutes (urllib3 borne la durée de chaque
attente, jamais leur nombre). Les valeurs par défaut (3 / 0,5 s / 5 s) sont très
en dessous des plafonds : un usage normal n'est pas affecté. `timeout_read` reste
plafonné séparément par `[settings] max_timeout_read`.

### 10.6 Configuration : une seule lecture, celle de Splunk

L'app lit `esearch.conf` **par splunkd**
(`servicesNS/nobody/SA-esearch/configs/conf-esearch`). Les
commandes utilisent le jeton de l'utilisateur ; le proxy, le jeton système. Ce
que montrent la page Configuration et `btool` est donc ce qui s'exécute,
couches de configuration de Splunk comprises. Mesuré : un profil déclaré dans
`etc/system/local/esearch.conf` est servi, comme `btool` l'affiche.

À savoir :

- **Valeurs multi-lignes** : Splunk les rend jointes par un saut de ligne.
  Aucune clé n'en admet. L'app le signale à chaque recherche et **refuse** le
  profil touché ; les autres profils restent servis. Une `allowed_roles` sur
  plusieurs lignes est refusée, jamais lue comme `*`. **Ne pas mettre de saut
  de ligne dans une valeur.**
- **Fichier illisible** : c'est l'affaire de Splunk. `btool check`
  le signale, et l'app voit ce que Splunk a pu lire.
- **Coût** : une lecture REST par recherche et par appel du proxy, 52 ms
  mesurés (Splunk 9.3.14 émulé, donc lent).
- **Droits** : la conf de l'app est lisible par tous (`metadata/default.meta`,
  `read : [ * ]`). Un utilisateur du rôle `user` la lit (vérifié). Restreindre
  cette lecture empêcherait ses recherches.
- **Sans splunkd**, pas de conf : l'erreur le dit
  (« configuration esearch illisible par splunkd »), sans repli sur les
  fichiers.

### 10.7 Versions vérifiées sur cluster réel
La matrice de `COMPATIBILITY.md` annonce ES 7.10+ / 8.x / 9.x et OpenSearch.
Vérifiées sur cluster réel : **Elasticsearch 7.17, 8.17 et 9.5**, **OpenSearch
1.3, 2.19 et 3.9** (recherche, pagination PIT et scroll, `| esindices`, `_time`,
authentification, mTLS sur ES 8.x). Les versions **antérieures à 7.12** (repli
`_cat/indices` quand `_resolve/index` est absent, absence de PIT avant 7.10, tri
`_shard_doc` absent avant 7.12) ne l'ont été que contre un serveur simulé.
**Les valider sur votre cluster avant mise en production si vous êtes dans ce
cas.**

---

### 10.8 Bornes temporelles à la seconde près

La commande applique la sémantique de Splunk — `earliest` inclus, `latest`
exclu, à la milliseconde. Mais Splunk ne lui transmet, par
`searchinfo`, que des **secondes entières** : une borne demandée à `…000.5`
arrive `…000` (vérifié sur Splunk 9.3.14 et 10.4.1). Les deux bornes étant tronquées de la même façon, deux fenêtres
consécutives restent jointives (ni trou ni doublon) ; seule une borne
sub-seconde est décalée de moins d'une seconde. `info.csv` porte la valeur exacte,
mais `searchinfo` reste la source retenue, parce qu'elle est l'API supportée. Les bornes usuelles — time picker arrondi, recherches
planifiées `@m` — sont entières et donc exactes. Les bornes écrites dans la
commande (`earliest=` / `latest=`) ne passent pas par `searchinfo` :
résolues par splunkd à la milliseconde, elles sont exactes, sub-seconde
comprise.

### 10.9 Configuration des profils lisible par les utilisateurs (hors secrets)

Les **secrets** ne sont lisibles que par les administrateurs (`storage/passwords`).
En revanche, le **reste** de la configuration des profils — hôte Elasticsearch,
identifiant basic, chemins de certificats, `allowed_roles`, ordre de priorité —
est lisible par tout utilisateur qui sait interroger l'API REST de Splunk
(`| rest /services/properties/esearch`). Mesuré sur Splunk 9.3.14 :

- les permissions Splunk sur une strophe ou sur tout `esearch.conf` masquent
  les profils de `configs/conf-esearch`, mais **pas** de `/services/properties`,
  qui les ignore ;
- `/services/properties` n'est gardé que par la capability
  **`rest_properties_get`**, accordée par défaut au rôle `user`, et donc héritée
  par tous les rôles, `admin` et le rôle système compris. Splunk interdit de
  retirer une capability héritée dans un rôle enfant : la seule façon de la
  retirer est de la désactiver sur `user`, pour **toute l'instance** ;
- ce retrait casse Splunk Web lui-même (il lit la configuration des apps par
  cet endpoint) : Monitoring Console en erreur 500 pour l'administrateur,
  *Paramètres → Interface utilisateur → Vues* en erreur 500 pour un utilisateur.

Choix retenu : ne pas toucher à cette capability et **le dire**. Ce
qui protège réellement reste en place : les secrets, le droit d'utiliser un
profil (`allowed_roles`, contrôlé par le proxy), la liste de profils présentée à
chaque utilisateur, les messages de refus neutres, et `esearch.log` (dans
`_internal`, que le rôle `user` ne peut pas chercher, vérifié). Pour rendre
aussi l'hôte et l'identifiant confidentiels, il faudrait sortir la définition
des profils d'`esearch.conf` (vers `storage/passwords`) : évolution non faite.

### 10.10 Deux administrateurs qui modifient le même profil en même temps

**La dernière modification gagne.** La page écrit le profil (`esearch.conf`)
puis son secret (`storage/passwords`), en deux requêtes ; le secret est **mis à
jour en place** (création s'il n'existe pas, mise à jour si un autre
administrateur vient de le créer), jamais supprimé puis recréé. Mesuré sur
Splunk 9.3.14 (deux administrateurs, même profil, même instant, 20 tours) :
aucune erreur, aucun profil sans secret ni avec deux secrets, aucun profil
mêlant le secret d'un auteur à la configuration de l'autre.

Ce mélange n'est pas pour autant **empêché** : deux requêtes restent deux requêtes, et deux enregistrements
exactement simultanés peuvent encore s'entrelacer. Un formulaire resté ouvert
écrase, à l'enregistrement, ce qu'un autre a modifié entre-temps.

### 10.11 Page de configuration : session expirée, splunkd injoignable

Vérifié au navigateur, Splunk 9.3.14 :

- **Session Splunk expirée** : « session expirée — reconnectez-vous (rechargez la
  page), puis recommencez ». Splunk Web détecte aussi l'expiration de lui-même
  et renvoie vers sa page de connexion ; le message de l'app couvre l'intervalle.
- **splunkd qui ne répond plus** : chaque appel de la page attend au plus
  **30 s**, puis « splunkd ne répond pas (aucune réponse en 30 s) — la
  modification a pu être prise en compte : rechargez la page pour le vérifier ».
  splunkd arrêté : « splunkd injoignable ». L'enregistrement des réglages ne
  tente de créer la stanza que sur un 404, jamais sur une autre erreur : pas de
  second délai.
- **Boutons d'enregistrement** : désactivés, « Enregistrement en cours… », le
  temps de l'appel ; un second clic ne relance rien.

### 10.12 Coût du proxy

Mesuré sur Splunk 9.3.14 émulé, ES 8.17.4 local (médiane de 7 exécutions,
durée du job) : passer par le proxy plutôt qu'en mode ad hoc ajoute
**0,1 à 0,2 s** pour 1 événement (2,30 → 2,44 s) et **environ 0,4 s** pour
10 000 (5,15 → 5,54 s). Endurance : 388 recherches en 30 min, sans échec, sans
contexte Elasticsearch retenu et sans croissance mémoire du processus du
proxy (78,1 → 78,9 Mo).

Coût accepté : le proxy ne garde rien entre deux pages,
donc ouvre à chaque page une connexion vers splunkd et une session vers
Elasticsearch. À revoir seulement si la latence gêne.

La première page d'une recherche Lucene ajoute un appel
`_field_caps` sur le champ date (un aller-retour, couvert par le privilège
`read`) : s'il est de type `date` avec doc values dans tous les index visés,
Elasticsearch décode `_time` lui-même, selon le format du mapping. Sinon, ou si
l'appel échoue, `_time` se lit dans `_source`.

### 10.13 Taille et forme de la requête (`query=`)

Mesuré sur Splunk 9.3.14, Elasticsearch 8.17.4 avec un tas de 512 Mo, et
7.17.24 (index de 7 champs), en faisant varier la seule
option `query=`. Ce qui limite, dans l'ordre où on le rencontre :

| Limite | Valeur | Ce que voit l'utilisateur |
|---|---|---|
| **Imbrication des parenthèses** (app) | 30 niveaux par défaut (`query_max_depth`) | « requête trop imbriquée : N niveaux de parenthèses, maximum 30 (réglage query_max_depth …) » — refusée **avant** tout envoi |
| **Taille** (app) | 1 Mio (1 048 576 octets, en UTF-8) par défaut (`query_max_bytes`) | « requête trop longue : N octets, maximum 1048576 (réglage query_max_bytes …) » — refusée avant tout envoi |
| **Nombre de clauses** (Elasticsearch) | plafond du cluster, **calculé d'après son tas** en ES 8 : 4 681 avec un tas de 512 Mo, alors que le réglage affiché `indices.query.bool.max_clause_count` vaut 4 096 | « requête trop large : trop de clauses (plafond de ce cluster : 4681 clauses) … » |
| **Longueur** (OpenSearch seulement) | 32 000 caractères par défaut (`search.query.max_query_string_length`, réglage du cluster) | « requête trop longue pour ce cluster : N caractères, maximum 32000 (réglage du cluster search.query.max_query_string_length) — … ». Mesuré sur OpenSearch 3.9.0 : ce plafond arrive avant celui des clauses |
| Syntaxe (Elasticsearch) | — | « syntaxe de requête invalide : Encountered "<EOF>" at line 1, column 9. » |

**Le nombre de clauses dépend des champs.** Un terme sans champ
(`query="a OR b"`) est cherché dans **chaque** champ de l'index (le
`default_field` d'Elasticsearch vaut `*`) et compte pour autant de clauses. Mesuré :
sur 7 champs, 660 termes passent et 670 sont refusés (≈ 4 681 / 7) ; préfixés de
leur champ (`status:a OR status:b`), 4 097 passent et 5 000 sont refusés. Une
liste de valeurs passée en requête (indicateurs, identifiants) se heurte donc à
cette limite bien avant celle de la taille : préfixer le champ, découper, ou
matérialiser la liste côté Elasticsearch (index de référence et requête
`terms` sur lui, hors de l'app).

**Pourquoi l'app borne elle-même.** Sans ces bornes, un seul `| esearch`
**arrête le nœud Elasticsearch**, sans qu'Elasticsearch le refuse (mesuré) :

- 3 000 niveaux de parenthèses : `java.lang.StackOverflowError`, processus
  arrêté, sur ES 8.17.4 comme sur 7.17.24, par le proxy comme en mode ad hoc
  (2 500 niveaux passaient ; le seuil dépend de la pile de la JVM). Le réglage
  `indices.query.bool.max_nested_depth` (30) ne s'applique pas à
  `query_string` : 1 000 niveaux passaient sans erreur ;
- une phrase de 4 Mo : `java.lang.OutOfMemoryError` sur un tas de 512 Mo, et un
  vidage mémoire de la taille du tas écrit sur le disque du nœud (2 Mo
  passaient ; le seuil dépend du tas et de la charge).

Tout utilisateur de la commande le pourrait. Les bornes sont contrôlées
par la commande et, pour tout profil, **par le proxy** (avant toute lecture de
secret) : un appel direct de l'endpoint ne les contourne pas. 30 est la valeur
qu'Elasticsearch impose à ses propres requêtes booléennes ; 1 Mio dépasse de
loin une requête humaine ou générée, puisque le plafond de clauses tombe avant.
Elles sont réglables (ci-dessous).

**Au-delà de l'app.** splunkd accepte une recherche de 10 Mo (`max_content_length`
vaut 2 Go), mais l'analyse de la recherche prend alors ~47 s avant même le
refus, et Splunk garde le texte entier dans `audit.log` et le dispatch (§ 9).
`http.max_content_length` d'Elasticsearch (100 Mo) n'est jamais atteint.

**Les refus d'Elasticsearch sont lus d'après leur cause réelle**
(`caused_by`), et non d'après la raison de premier niveau, qui recopie la
requête entière sans dire pourquoi (« Failed to parse query [<requête>] ») :
mesuré, 130 000 caractères pour 8 192 termes. Tout texte repris
d'Elasticsearch est tronqué à
300 caractères (longueur totale annoncée), et la ligne `DEBUG` du texte de la
requête à 10 000.

**Bornes réglables** : `[settings] query_max_bytes` (défaut 1 Mio, de
1 024 octets à 2 Gio) et `query_max_depth` (défaut 30, de 1 à 100 000), carte
« Protections du cluster et du search head » de la page Configuration. Les défauts sont mesurés sur un
cluster de test (tas de 512 Mo) ; un cluster de production plus robuste peut les relever.
Elasticsearch ne borne lui-même ni l'un ni l'autre pour `query_string` (seule
la taille du corps, `http.max_content_length`). Contrôlées par la commande et
par le proxy, qui lit sa propre configuration (une SPL ne les relève pas).

**Reprises.** `retry_count` ne rejoue que ce qui n'a pas pu
atteindre Elasticsearch ou ce qu'il a refusé faute de place : connexion
impossible, réponses **429** et **503**. Une recherche **partie sans réponse** —
connexion fermée pendant le traitement (le nœud est tombé), délai de lecture
dépassé — et les réponses **500, 502, 504** ne sont pas rejouées : elle a pu
faire tomber le nœud, et la rejouer, derrière un répartiteur, sur le nœud
suivant, pourrait les abattre l'un après l'autre. Une connexion gardée ouverte
puis fermée par le serveur entre deux pages n'est pas concernée : urllib3 la
voit morte et en ouvre une autre (mesuré, 5 pages sur 5).

### 10.14 Filtres par lookup : jokers, échappement, limites

Mesuré sur Splunk 9.3.14, ES 8.17.4, champs `keyword`. Usage :
README, « Filtres par lookup ».

**Quel échappement ?** Ni celui de Splunk, ni directement celui d'Elasticsearch :
celui de l'app, traduit en Lucene.

- Splunk ne transforme pas le contenu d'une lookup : `| inputlookup` rend
  `uc\*` tel quel (4 caractères). Ses lookups `match_type = WILDCARD(champ)`
  (réglage par définition, `transforms.conf`) ne connaissent que `*`, et
  **n'ont aucun échappement** : `uc\*` y est une barre oblique littérale suivie
  d'un joker ; `?` y est littéral. L'app ne lit pas `match_type` : ses règles
  valent pour toute lookup.
- Lucene (`query_string`) connaît `*` **et** `?`, et neutralise par `\`. Son
  échappement n'est pas réglable ; ce qui l'est, côté Elasticsearch, est
  ci-dessous.
- Règle de l'app : `*` joker ; `\*` étoile littérale ; `\\` barre oblique
  littérale (utile devant un joker : `DOMAINE\\*`) ; toute autre barre oblique
  est littérale (`DOMAINE\compte`, fréquent dans les données Windows) ; `?`
  littéral, comme dans Splunk. Une valeur sans joker part en phrase exacte
  (`host:"uc1"`), une valeur à joker en terme échappé (`host:uc\ 4*`).

**Côté Elasticsearch, ce qui change le comportement :**

| Réglage / cas | Effet mesuré |
|---|---|
| Champ `keyword` | correspondance sensible à la casse : `UC*` ne trouve pas `uc1` |
| Champ `text` | le joker suit l'analyseur : `GET*` et `get*` trouvent les mêmes documents ; une phrase y est cherchée mot à mot, pas comme valeur entière (sémantique Elasticsearch, non mesurée ici) |
| `allow_leading_wildcard` (défaut true ; réglage de nœud `indices.query.query_string.allowLeadingWildcard`) | à false, une valeur commençant par `*` est refusée : « syntaxe de requête invalide : '*' or '?' not allowed as first character in WildcardQuery » (mesuré par le paramètre de requête ; le réglage de nœud, qui en fixe le défaut, n'a pas été basculé) |
| `search.allow_expensive_queries` (dynamique) | à false, la requête DSL `wildcard` est refusée, mais pas le joker de `query_string`, utilisé par l'app. Anomalie mesurée : juste après la bascule à false, 5 essais sur 5 ont rendu 0 résultat **sans erreur**, puis le résultat normal une seconde plus tard |

**Limites.**

- Le plafond de clauses du cluster (§ 10.13) s'applique au filtre : une ligne
  de 2 colonnes compte 2 clauses. Mesuré : 2 000 lignes d'une colonne passent,
  5 000 sont refusées (plafond 4 681).
- La borne de 1 Mio (§ 10.13) est appliquée pendant la lecture : une lookup qui
  la dépasserait est abandonnée sans être lue jusqu'au bout.
- **Plafond silencieux de Splunk, contourné.** Une recherche lancée en
  `oneshot` ne rend que 50 000 lignes (`[restapi] maxresultrows`), **sans aucun
  message** : un filtre construit ainsi serait incomplet, et une exclusion
  exclurait moins que prévu. L'app lit donc les lookups par `export`, qui rend
  toutes les lignes (mesuré : 65 537 sur 65 537, et une collection KV store de
  50 001 lignes lue en entier).

**Mode `terms`.** Mesuré directement contre Elasticsearch 8.17.4 :
le plafond de clauses vaut pour la requête entière (8 groupes de 600 termes,
4 800, refusés, même en sous-requêtes `bool`), alors qu'un filtre `terms` compte
pour une clause : 65 536 valeurs passent, 65 537 sont refusées
(`index.max_terms_count`, réglable par index), deux filtres de 60 000 passent,
et `terms` fonctionne en exclusion (`must_not`). La commande transmet une
structure contrainte (`{"inclusion"|"exclusion": {"type", "listes": [{"champ",
"valeurs"}]}}`), revalidée par `build_payload` — donc par le proxy pour tout
profil, avant toute lecture de secret — et traduite en `filter` / `must_not` :
un appel direct de l'endpoint ne peut pas y glisser de DSL. Bornée à 32 Mio
(sous les 100 Mo de `http.max_content_length`). Sur un champ `text`, `terms`
ne cherche que les mots tels qu'Elasticsearch les a découpés et mis en
minuscules (mesuré) : à réserver aux champs `keyword`.

**Découper une requête trop longue en plusieurs envois** : étudié et écarté. Seule l'inclusion se découpe (union des
résultats, au prix de doublons, d'une fusion pour `sort=` et d'un total
approximatif) ; une exclusion doit figurer entière dans chaque requête.

**Coût.** Une recherche Splunk de plus, pour toutes les lookups à la fois
(`inputlookup append=t`) : mesuré sous émulation, environ 1,1 s pour une
lookup, 1,35 s pour trois, contre 1,1 s par lookup lues une à une.

**Pourquoi pas une sous-recherche `[| inputlookup … | format]` dans `query=`.**
Essayé : `format` écrit `host="uc1"` (syntaxe Splunk), qui casse les options
de la commande ; transformé en Lucene et passé par `return`, il perd ses
guillemets et la requête est coupée à la première valeur contenant un espace,
et une valeur `OR` ou `)` en change la logique. Une sous-recherche **entre
guillemets** (`query="… [ … ]"`) n'est pas développée par Splunk : la commande
reçoit le texte tel quel.

### 10.15 Requêtes ES|QL (`esql=`) : bornes, plafond de lignes, risques

Mesuré sur Elasticsearch 8.11 à 9.5, tas de 512 Mo.

| Limite | Valeur | Ce que voit l'utilisateur |
|---|---|---|
| **Taille** (app, `[settings] esql_max_bytes`) | 64 Ko par défaut (1 024 à 1 000 000), ajouts de l'app compris | « requête ES\|QL trop longue : N octets, maximum M » — refusée **avant** tout envoi |
| **Imbrication** (app, `esql_max_depth`) | 100 parenthèses par défaut (1 à 400), hors chaînes et commentaires | « requête ES\|QL trop imbriquée » — refusée avant envoi |
| **Apostrophes** (app) | une apostrophe hors chaîne | « requête ES\|QL : apostrophe en position N … » |
| **Valeurs d'un lookup inséré** (app, `esql_lookup_values_max`) | 1 000 par défaut (1 à 65 536), valeurs exactes et motifs | « lookup X : N valeurs à insérer dans la requête ES\|QL, maximum M … lookup_stage=source » — refusé avant envoi |
| **Profondeur d'expression** (Elasticsearch) | 400, constante du parseur d'ES (398 `OR` enchaînés, ≈ 198 parenthèses) | « requête ES\|QL trop complexe : … plafonne la profondeur des expressions à 400 … remplacer une suite de OR par IN » |
| **Lignes rendues** (Elasticsearch) | 10 000 (`esql.query.result_truncation_max_size`, réglable à chaud, 20 000 mesuré) ; coupe **silencieuse** côté ES | « N lignes : plafond ES\|QL du cluster probablement atteint … » ; et « résultat coupé à N lignes (limit= ou max_limit) » |
| **Durée** | délai de lecture (`timeout_read`, plafonné par `max_timeout_read`) | à l'échéance, la connexion est coupée et Elasticsearch **annule** la requête (mesuré, < 0,2 s, 8.11 à 9.5). Pas de nouvelle tentative sur délai dépassé ni sur 429 (disjoncteur mémoire) : la rejouer en relancerait le coût |

**Mode asynchrone** (profil `esql_mode = async`, Elasticsearch 8.13+).
- **Déroulé** : `POST /_query/async` avec une attente de `esql_async_wait`. Une
  requête finie dans ce délai rend son résultat d'un coup ; sinon, la commande
  interroge le proxy (`GET /_query/async/<id>`), un appel court à chaque fois,
  jusqu'à la fin. Le résultat lu est libéré aussitôt (`DELETE`).
- **Durée** : au-delà de `esql_async_max` (1 800 s), la commande annule la
  requête (`DELETE` : tâches arrêtées en moins d'une seconde, mesuré) et la
  recherche affiche « requête ES|QL asynchrone arrêtée après N s ». Même chose
  sur toute erreur en cours de route.
- **Recherche arrêtée dans Splunk** : le processus de la commande est tué avant
  d'annuler. La requête finit côté Elasticsearch, et son résultat expire au bout
  de `esql_async_keep_alive` (5 min).
- **Sécurité** : l'`id` d'Elasticsearch donne accès au résultat, et tous les
  utilisateurs d'un profil partagent la même identité Elasticsearch. Le proxy ne
  le remet donc que dans un **jeton signé** (HMAC-SHA256), lié à l'utilisateur,
  au profil et à une échéance, et il refuse tout autre jeton avant de lire un
  secret. Clé : `$SPLUNK_HOME/var/run/splunk/esearch_async.key` (0600, créée au
  premier usage) ; la supprimer invalide les requêtes en cours.

**Pourquoi des bornes propres à ES|QL.** Elles sont bien plus basses que
celles de `query=` (1 Mio, 30 niveaux, § 10.13), parce que les nœuds tombent
bien plus tôt. Une requête ES|QL a **arrêté le nœud** dans ces cas mesurés :
- 5 000 parenthèses, 10 Ko (8.17.4, OutOfMemoryError) ;
- une liste `IN` de 10 000 valeurs, 89 Ko (8.15.5, OutOfMemoryError) ;
- 2 000 `LIKE` reliés par des `OR` équilibrés, 48 Ko (8.17.4,
  OutOfMemoryError) ;
- un `RLIKE` à 20 000 alternatives, 220 Ko (8.17.4, StackOverflowError, sur un
  nœud au repos).

Les deux premiers cas ne se sont reproduits que sous charge : au repos, la même
requête est refusée proprement ou réussit. Les seuils croissent avec le tas du
nœud.

**Ce que les bornes ne couvrent pas.** Une requête écrite à la main avec de
nombreux `LIKE` peut arrêter un nœud sous 64 Ko : seul un tas adapté protège
alors le cluster. À signaler aux auteurs de requêtes ; pour des listes de
valeurs, préférer `IN` (une seule expression) ou les lookups
(`lookup_include=`), appliqués au début, côté documents.

**Plafond du cluster.** Relever `esql.query.result_truncation_max_size` (réglage
dynamique du cluster) permet de ramener plus de 10 000 lignes, au prix de
mémoire côté Elasticsearch. Pour de l'extraction en volume, `query=` reste la
bonne voie : il pagine sans perte (PIT ou scroll).

**Dépannage.**
| Symptôme | Piste |
|---|---|
| « ES\|QL indisponible sur ce cluster » | Elasticsearch < 8.11, 7.x ou OpenSearch. `query=` fonctionne sur tous |
| « valeurs vides — type non pris en charge par ES\|QL… » | deux causes : un type qu'ES\|QL ne lit pas sur ce cluster (`date_nanos` avant 8.17, `flattened` avant 9.5…) : version du cluster ; ou un champ de **types différents selon les index** visés (`date` ici, `long` là, fréquent avec `FROM *`) : le convertir explicitement, `EVAL x = TO_DATETIME(x)` ou `x::datetime` (mesuré sur 8.17), ou restreindre `FROM` aux index cohérents |
| un champ manque alors qu'il est dans le document | champ `nested` : jamais rendu par ES\|QL ; utiliser `query=` |
| colonne `X.keyword` absente | masquée car elle double `X` (`esql_hide_keyword`, global ou par profil) |
| « mode ES\|QL asynchrone indisponible sur ce cluster » | profil en `esql_mode = async` sur un cluster < 8.13, 7.x ou OpenSearch : repasser le profil en synchrone |
| « requête ES\|QL asynchrone arrêtée après N s » | `esql_async_max` atteint : restreindre la requête (période, index, agrégation plus tôt) ou relever le réglage |
| « requête ES\|QL asynchrone introuvable » | résultat expiré (`esql_async_keep_alive`) ou supprimé, entre deux interrogations : relancer ; allonger `esql_async_keep_alive` si le proxy ou le cluster sont lents |
| « lookups insérés dans la requête … Elasticsearch 8.15 minimum » | `lookup_stage=result` ou marqueur après EVAL/STATS sur un cluster < 8.15. Remèdes : `lookup_stage=source`, ou un marqueur avant tout EVAL/STATS (filtre des documents) |
| « lookup X : colonne(s) … absente(s) de la requête à cet endroit » | après un `STATS`/`KEEP`, la colonne du lookup n'existe plus : la garder (BY, KEEP), ou placer le lookup plus tôt (marqueur) |
| un lookup inséré ne retrouve pas une date | la valeur doit être une date complète (`2026-10-22T10:00:00Z`) ; Lucene (filtre des documents) accepte `2026-10-22` |
| 0 ligne alors que la requête en rend sans période | l'index n'a pas le champ de temps du profil (`timefield`) : le filtre de période ne laisse rien passer, comme pour `query=` |

### 10.16 L'environnement de splunkd n'est pas suivi

Une bibliothèque `requests` laissée par défaut hérite en silence de
l'environnement de splunkd. L'app l'écarte :

| Variable | Effet évité |
|---|---|
| `HTTP_PROXY`, `HTTPS_PROXY` (`NO_PROXY`) | tout le trafic vers Elasticsearch passerait par ce proxy ; mesuré : un proxy injoignable dans `splunk-launch.conf` ferait échouer toutes les recherches (`ProxyError`) |
| `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` | remplacerait le bundle de CA embarqué pour un profil vérifié **sans** `ca_file` |
| `~/.netrc` de l'utilisateur splunk | son identifiant serait envoyé à un profil **sans** authentification |

**Seule la configuration visible dans la page Configuration s'applique** :
profils (`es_host`, `ca_file`, certificat client, secret) et réglages. Vérifié
avec un proxy injoignable dans `splunk-launch.conf` : recherches Lucene (PIT et
scroll), ES|QL, clé API, `| esindices`, utilisateur non administrateur, TLS.

**Conséquence** : un réseau qui n'atteint Elasticsearch que par un proxy
obligatoire, ou une CA fournie par l'environnement, ne sert pas. Pour la CA :
un `ca_file` dans le profil. Pour un proxy obligatoire, l'app n'a pas de
réglage.

L'appel de la commande vers splunkd en boucle locale — qui porte le jeton de
session de l'utilisateur — n'hérite pas non plus de ces variables. Il ne
vérifie pas le certificat de splunkd (`verify=False`, choix assumé) : vérifié contre la CA de splunkd
(`etc/auth/cacert.pem`), il échoue avec le certificat par défaut, émis pour
`SplunkServerDefaultCert` sans SAN — `127.0.0.1` ne correspond pas (mesuré,
9.3.14). L'appel ne quitte pas la machine.

### 10.17 Mémoire du search head pour les gros résultats

Une recherche `query=` garde en mémoire, dans le processus de la commande, **tous
ses résultats** avant de les remettre à Splunk. Le SDK Splunk envoie par lots de
`maxresultrows` (50 000 par défaut), autant que `max_limit` par défaut. Le proxy,
lui, ne tient qu'une page (10 000 documents au plus).

Pics mesurés (Splunk 9.3.14 émulé) :

| Résultats | Pic de la commande | Pic du proxy |
|---|---|---|
| 10 000 documents de 1 Ko | 217 Mo | 111 Mo |
| 10 000 documents de 10 Ko | 1 155 Mo | 462 Mo |
| 30 000 documents de 2 Ko | 808 Mo | 155 Mo |

Ordre de grandeur : environ **11 fois le volume brut** des résultats dans la
commande. 50 000 documents de 10 Ko approcheraient 5 Go (extrapolé, non lancé).

Par ailleurs, une page de 10 000 documents de plus de ~26 Ko dépasse
`max_response_mb` (256 Mo) : la recherche échoue sur « réponse trop
volumineuse » dès que `limit` approche 10 000.

**Conduite à tenir** :

- sur des index aux documents volumineux, baisser `max_limit` (global ou par
  profil) en proportion de la mémoire disponible sur le search head ;
- préférer une agrégation (`esql=` avec `STATS`) ou une sélection de champs
  (`_source_include`) à un rapatriement massif de documents entiers ;
- relever `max_response_mb` seulement si la mémoire le permet : il borne une
  page, pas la recherche.

Limite connue. Deux évolutions ont été mesurées, sans être réalisées :
- envoyer à Splunk par lots plus petits : essai à 2 000, 808 → 163 Mo ;
- calculer la taille des pages vers Elasticsearch en octets.

### 10.18 Champ date d'un autre type que `date`

Elasticsearch n'impose pas de date à un document, sauf dans un data stream
(`@timestamp` de type `date` ou `date_nanos` obligatoire). Dans un index
classique, le champ date peut manquer, ou avoir un autre type : le mapping
automatique fait d'un nombre JSON un `long`, jamais une `date`. Seuls `date` et
`date_nanos` sont des dates pour Elasticsearch, et Kibana n'accepte qu'eux comme
champ de temps.

**Ce que fait l'app** : elle détecte le type du champ dans chaque index visé,
et le dit (mesuré sur ES 7.17, 8.17 et OpenSearch 3.9) :

| Type du champ date dans un index visé | Période | Tri (`sort=`) | `_time` |
|---|---|---|---|
| `date`, `date_nanos` | exacte | natif | décodé par Elasticsearch |
| nombre (`long`, `double`…) en ms | exacte | natif | lu dans `_source` |
| nombre en **secondes** | exacte | voir ci-dessous | lu dans `_source` |
| `keyword`, `text` | **comparée comme du texte : peu fiable**, avertissement | alphabétique (keyword seul), avertissement | lu dans `_source` (ISO 8601, époque) |
| absent | **exclut tous les documents**, avertissement | en fin | aucun |
| `integer`, `short`, `byte` | **fait échouer l'index** (milliseconde hors bornes), avertissement | natif | lu dans `_source` |
| autre (`ip`, `boolean`…) | ne s'applique pas, avertissement | — | aucun |

- Les avertissements de type nomment les index concernés (trois, puis le
  compte). Ils ne paraissent que si une période ou un tri est demandé.
- La période en secondes ne vise que les index où le champ est numérique (filtre
  `_index`) : un `keyword` n'y entre pas.
- **Tri refusé avant l'envoi** quand Elasticsearch ne saurait pas le faire
  (« sort=… impossible »). Familles mesurées sur ES 7.17 et 8.17 :
  - triables ensemble : dates, entiers, champ absent ;
  - à part : `double` / `scaled_float` / `half_float` ; `float` ; `keyword` /
    `wildcard` ; `unsigned_long` ;
  - jamais : `text`.

  Sans `sort=`, la recherche part normalement.
- **Non détecté** : un mélange d'index en secondes et en millisecondes. Le tri
  natif y est faux sans erreur (toutes les millisecondes d'abord).
- **Événements sans `_time`** : Splunk les accepte, mais `timechart`, `bin` et la
  timeline les ignorent sans rien dire (mesuré : 3 comptés sur 6). La commande
  les compte et l'annonce, seulement s'il y en a. Avec « Toute période », les
  documents sans date sont rendus, sans `_time`.
- **ES|QL** : les index du `FROM` ne sont pas analysés.
  - L'avertissement vient du type de la colonne date dans la réponse : rien si
    elle manque, ce qui est légitime après un `STATS`.
  - La période n'y est pas appliquée en secondes.
  - Un tri sur un champ de types différents selon les index est refusé par
    ES|QL (8.14 à 9.5) : le message le dit.
- **Coût** : aucune requête de plus que la sonde `_field_caps` de la première
  page (§ 10.12), qui lit les mappings sans parcourir les données. Elle demande
  `include_unmapped`, et le redemande sans lui sur un cluster qui le refuse
  (Elasticsearch < 7.2).
- **Le remède durable reste le mapping** : `date` (ou `date` avec
  `format: epoch_second`) dans un modèle d'index, puis réindexation.

## 11. Désinstallation

```bash
$SPLUNK_HOME/bin/splunk remove app SA-esearch
```
Supprimer aussi les secrets résiduels (realm `esearch:*`) via storage/passwords
si l'app est retirée définitivement.
