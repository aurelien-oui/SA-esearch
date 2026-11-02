# -*- coding: utf-8 -*-
"""Jeton d'une requête ES|QL asynchrone (profil esql_mode=async, 1.24.0).

Elasticsearch rend un `id` qui donne accès au résultat. Tous les utilisateurs
Splunk d'un profil partagent la même identité Elasticsearch : ES ne peut donc
pas réserver cet `id` à celui qui a lancé la requête. Le proxy ne le remet
qu'enveloppé dans un jeton signé (HMAC-SHA256), qui le lie à l'utilisateur, au
profil et à une échéance, et il refuse tout autre jeton avant même de lire un
secret. Il ne garde rien en mémoire entre deux appels : il reste sans état,
comme pour la pagination.

Clé : 32 octets aléatoires, dans $SPLUNK_HOME/var/run/splunk/esearch_async.key
(droits 0600), créée au premier usage et partagée par les processus du proxy
sur ce search head. La supprimer invalide les jetons en cours.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time

_DUREES = {"nanos": 1e-9, "micros": 1e-6, "ms": 1e-3, "s": 1, "m": 60, "h": 3600, "d": 86400}
_ID = re.compile(r"^[A-Za-z0-9_=+/-]{1,1000}$")


def chemin_cle():
    return os.path.join(os.environ.get("SPLUNK_HOME", "/opt/splunk"), "var", "run", "splunk",
                        "esearch_async.key")


def _cle():
    chemin = chemin_cle()
    try:
        with open(chemin, "rb") as f:
            cle = f.read().strip()
        if len(cle) >= 32:
            return cle
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    try:
        # O_EXCL : deux processus qui créent la clé en même temps n'en écrivent
        # qu'une ; le second relit celle du premier.
        fd = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_hex(32).encode())
    except FileExistsError:
        time.sleep(0.05)
    with open(chemin, "rb") as f:
        return f.read().strip()


def secondes(duree):
    """Durée Elasticsearch (`5m`, `30s`…) en secondes."""
    m = re.match(r"^\s*(\d+)\s*(nanos|micros|ms|s|m|h|d)\s*$", str(duree))
    return int(m.group(1)) * _DUREES[m.group(2)] if m else 300


def _b64(octets):
    return base64.urlsafe_b64encode(octets).decode().rstrip("=")


def signe(ident, profil, utilisateur, conservation):
    """Jeton remis à la commande : id, profil, utilisateur, échéance, signature."""
    if not _ID.match(str(ident)):
        raise RuntimeError("identifiant de requête asynchrone inattendu d'Elasticsearch")
    corps = _b64(json.dumps({"id": ident, "p": profil, "u": utilisateur,
                             "exp": int(time.time() + secondes(conservation) + 60)},
                            separators=(",", ":")).encode())
    return corps + "." + hmac.new(_cle(), corps.encode(), hashlib.sha256).hexdigest()


def verifie(jeton, profil, utilisateur):
    """`id` du jeton, ou ValueError : signature fausse, autre utilisateur ou
    profil, échéance passée. Le message ne dit pas lequel (pas d'aide à qui
    fabriquerait des jetons)."""
    refus = ValueError("jeton de requête asynchrone invalide ou expiré")
    try:
        corps, signature = str(jeton).rsplit(".", 1)
        attendue = hmac.new(_cle(), corps.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, attendue):
            raise refus
        d = json.loads(base64.urlsafe_b64decode(corps + "=" * (-len(corps) % 4)))
    except (ValueError, TypeError):
        raise refus
    if (not isinstance(d, dict) or d.get("p") != profil or d.get("u") != utilisateur
            or not isinstance(d.get("exp"), int) or d["exp"] < time.time()
            or not _ID.match(str(d.get("id")))):
        raise refus
    return d["id"]
