# -*- coding: utf-8 -*-
"""Appel du proxy REST privilégié (/esearch_proxy) depuis une commande.

Partagé par | esearch, | esindices et | esprofiles : depuis la 1.16.0, tout
profil passe par le proxy, seul à connaître les droits (allowed_roles) et les
secrets. La commande s'authentifie avec la session de l'utilisateur : le proxy
sait donc QUI appelle, et la capability esearch_run s'applique.
"""
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

from sa_esearch import APP_NAME
from sa_esearch.diagnostic import erreur_proxy


def appel_proxy(searchinfo, body, timeout):
    """POST form-encodé vers le proxy ; rend sa réponse JSON, ou lève
    RuntimeError avec le message du proxy (refus, erreur de configuration).

    Form-encodé : splunkd ne remplit `args['form']` du handler persistant que
    pour ce format (un corps JSON brut n'est pas capturé). Le proxy tourne sur
    le même search head : appel en boucle locale, d'où verify=False."""
    url = (searchinfo.splunkd_uri.rstrip("/")
           + "/servicesNS/nobody/" + APP_NAME + "/esearch_proxy")
    # Boucle locale vers splunkd, dont le certificat est autosigné : verify=False
    # est voulu. Vérifier contre la CA de splunkd (etc/auth/cacert.pem) échoue
    # avec le certificat par défaut, émis pour « SplunkServerDefaultCert » sans
    # SAN : le nom 127.0.0.1 ne correspond pas (mesuré, 9.3.14, F3 de la revue
    # 1.26.4) — et la CA réelle dépend de sslRootCAPath. L'avertissement d'urllib3 qui en découle est neutralisé pour CET
    # appel seulement : il partait sur la sortie d'erreur, donc dans le
    # search.log de CHAQUE recherche, étiqueté ERROR par Splunk (constaté).
    # trust_env=False (1.26.0), par précaution : CET appel porte le jeton de
    # session de l'utilisateur, sans vérification de certificat. Splunk ajoute
    # bien NO_PROXY=127.0.0.1,localhost,[::1] quand HTTP(S)_PROXY est posé (mesuré,
    # 9.3.14), mais un NO_PROXY redéfini sans la boucle locale, ou un splunkd
    # joint par un autre nom, aurait fait passer le jeton par le proxy de
    # l'environnement.
    with warnings.catch_warnings(), requests.Session() as session:
        warnings.simplefilter("ignore", InsecureRequestWarning)
        session.trust_env = False
        r = session.post(url, headers={"Authorization": "Splunk " + searchinfo.session_key},
                         data=body, verify=False, timeout=timeout)
    if r.status_code >= 300:
        try:
            corps = r.json()
        except ValueError:
            corps = None
        raise RuntimeError(erreur_proxy(r.status_code, corps, r.text))
    return r.json()
