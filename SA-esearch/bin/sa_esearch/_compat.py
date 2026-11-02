# -*- coding: utf-8 -*-
"""Compat pour splunklib VENDORISÉ (non installé via pip).

splunklib 3.x appelle `importlib.metadata.version("splunk-sdk")` à chaque requête
HTTP (User-Agent). Embarqué dans l'app, ce paquet n'a pas de métadonnées de
distribution → `PackageNotFoundError`, qui **casse tout accès storage/passwords**.

Depuis 1.26.5, l'app embarque la ligne 2.1.x (Python 3.9 de Splunk 9 ; la 3.x
exige 3.13), qui lit sa version dans ses propres sources : le shim n'y sert
plus, mais reste en place pour qu'un retour à la 3.x ne casse rien.

Plutôt que de patcher le SDK vendorisé (dette à réappliquer à chaque montée), on
neutralise ICI, de façon CIBLÉE, le lookup de version pour le seul nom
`splunk-sdk` : le SDK vendorisé reste ainsi **intact** (remplaçable tel quel).

Appliqué à l'import de `sa_esearch` (donc avant toute requête splunklib)."""

import importlib.metadata as _md

_FALLBACK = "0.0.0-vendored"
_TARGET = "splunk-sdk"


def apply():
    """Idempotent : `importlib.metadata.version('splunk-sdk')` renvoie un repli
    au lieu de lever, sans toucher aux autres paquets (vrais) installés."""
    if getattr(_md.version, "_esearch_shim", False):
        return
    _orig = _md.version

    def version(name, *a, **k):
        try:
            return _orig(name, *a, **k)
        except _md.PackageNotFoundError:
            if name == _TARGET:
                return _FALLBACK
            raise

    version._esearch_shim = True
    _md.version = version
