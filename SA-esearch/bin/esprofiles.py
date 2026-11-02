#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Commande générante `| esprofiles` : les profils que l'utilisateur peut
utiliser, dans l'ordre de priorité fixé par l'administrateur.

  | esprofiles

Un événement par profil : `profile` (nom), `rang` (1 = profil par défaut des
recherches sans profile=), `libelle` (nom, suivi de « (par défaut) » pour le
premier). Alimente le menu « Profil » de la page Query : seuls les profils
autorisés y figurent, le profil par défaut en tête.

La liste vient du proxy REST privilégié, seul à appliquer allowed_roles : elle
est donc exactement celle des profils que | esearch acceptera.

Protocole SCPv2 (chunked). Logique applicative dans bin/sa_esearch/.
"""

import logging
import os
import sys
import traceback

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Libs vendorisées (requests, certifi, ...) prioritaires sur celles de Splunk
_LIB = os.path.join(APP_ROOT, "bin", "lib")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

import requests
import sa_esearch  # noqa: F401  (effet de bord : shim de compat avant le SDK)
from sa_esearch import config as cfg
from sa_esearch.arguments import ArgumentsSignales
from sa_esearch.log import get_logger
from sa_esearch.proxy import appel_proxy
from splunklib.searchcommands import Configuration, GeneratingCommand, dispatch

logger = get_logger()


@Configuration()
class ESProfilesCommand(ArgumentsSignales, GeneratingCommand):

    def _err(self, msg):
        self.write_error("{}", msg)

    def _warn(self, msg):
        self.write_warning("{}", msg)

    def generate(self):
        if self.refuse_arguments():
            return
        try:
            yield from self._run()
        except (ValueError, RuntimeError) as e:
            logger.error("esprofiles: %s", e)
            self._err(f"esprofiles: {e}")
        except requests.exceptions.RequestException as e:
            logger.error("esprofiles HTTP: %s", e)
            self._err(f"esprofiles: le proxy esearch (splunkd) injoignable "
                      f"({e.__class__.__name__}: {e})")
        except Exception:
            logger.error("esprofiles erreur inattendue:\n%s", traceback.format_exc())
            self._err("esprofiles: erreur interne (détail dans esearch.log)")

    def _run(self):
        # Conf lue par splunkd, avec le jeton de l'utilisateur (1.26.7, M6).
        cp = cfg.load_conf(logger, cfg.service_appelant(self._metadata.searchinfo))
        level = (cfg.conf_get(cp, "settings", "log_level", "INFO") or "INFO").upper()
        logger.setLevel(getattr(logging, level, logging.INFO))
        resp = appel_proxy(self._metadata.searchinfo, {"action": "profiles"}, (5, 30))
        for w in resp.get("warnings", []):
            self._warn(w)
        for rang, nom in enumerate(resp.get("profiles") or [], start=1):
            yield {"profile": nom, "rang": rang,
                   "libelle": f"{nom} (par défaut)" if rang == 1 else nom}


dispatch(ESProfilesCommand, sys.argv, sys.stdin, sys.stdout, __name__)
