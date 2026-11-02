#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Commande générante `| esindices` : liste les cibles interrogeables d'un
profil Elasticsearch (index concrets, alias et data streams).

  | esindices profile=prod
  | esindices profile=prod pattern="logs-*"
  | esindices                      (profil par défaut de l'utilisateur)

Sert notamment à alimenter le menu déroulant « Index » de la page Query.
Comme `| esearch`, elle passe par le proxy REST privilégié pour tout profil :
il contrôle le droit de l'appelant (allowed_roles) et lit le secret côté
serveur, sans jamais l'exposer.

Retourne un événement par cible, champ `index`. En cas d'échec du listing
(clé sans droit `monitor` sur le cluster, par exemple), la commande émet un
avertissement et ne retourne rien : la page Query bascule alors sur la saisie
manuelle plutôt que de rester bloquée.

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
from splunklib.searchcommands import (
    Configuration,
    GeneratingCommand,
    Option,
    dispatch,
    validators,
)

logger = get_logger()


@Configuration()
class ESIndicesCommand(ArgumentsSignales, GeneratingCommand):

    profile = Option(require=False)
    pattern = Option(require=False)
    retry_count = Option(require=False, default=1, validate=validators.Integer(minimum=0, maximum=5))
    backoff_base = Option(require=False, default=0.5, validate=validators.Float(minimum=0, maximum=1.0))
    timeout_connect = Option(require=False, default=5, validate=validators.Integer(minimum=1, maximum=30))
    timeout_read = Option(require=False, default=15, validate=validators.Integer(minimum=1))

    # write_error/write_warning appellent message.format() : on passe le message
    # comme ARGUMENT pour neutraliser d'éventuelles accolades.
    def _err(self, msg):
        self.write_error("{}", msg)

    def _warn(self, msg):
        self.write_warning("{}", msg)

    def _utilisateur(self):
        """Utilisateur Splunk de la recherche (journal)."""
        return getattr(getattr(self._metadata, "searchinfo", None), "username", None) or "?"

    def generate(self):
        if self.refuse_arguments():
            return
        try:
            yield from self._run()
        except (ValueError, RuntimeError) as e:
            logger.error("esindices: %s", e)
            self._err(f"esindices: {e}")
        except requests.exceptions.RequestException as e:
            # Seul interlocuteur HTTP : splunkd (le proxy). Le nommer, et non
            # Elasticsearch, envoie diagnostiquer le bon composant.
            logger.error("esindices HTTP: %s", e)
            self._err(f"esindices: le proxy esearch (splunkd) injoignable "
                      f"({e.__class__.__name__}: {e})")
        except Exception:
            logger.error("esindices erreur inattendue:\n%s", traceback.format_exc())
            self._err("esindices: erreur interne (détail dans esearch.log)")

    def _run(self):
        # Conf lue par splunkd, avec le jeton de l'utilisateur (1.26.7, M6).
        cp = cfg.load_conf(logger, cfg.service_appelant(self._metadata.searchinfo))
        level = (cfg.conf_get(cp, "settings", "log_level", "INFO") or "INFO").upper()
        logger.setLevel(getattr(logging, level, logging.INFO))
        logger.info("esindices: user=%s profil=%s pattern=%s", self._utilisateur(),
                    self.profile, self.pattern)
        profil = self.profile or self._profil_par_defaut()
        resp = self._appel({"action": "indices", "profile": profil,
                            "pattern": self.pattern or "",
                            "timeout_connect": int(self.timeout_connect),
                            "timeout_read": int(self.timeout_read),
                            "retry_count": int(self.retry_count),
                            "backoff_base": float(self.backoff_base)})
        # Un événement par cible, sans _time : ce n'est pas une série temporelle
        # et le time picker ne doit pas filtrer le menu.
        for name in resp.get("indices", []):
            yield {"index": name}

    def _appel(self, body):
        resp = appel_proxy(self._metadata.searchinfo, body,
                           (int(self.timeout_connect), int(self.timeout_read) + 30))
        for w in resp.get("warnings", []):
            self._warn(w)
        return resp

    def _profil_par_defaut(self):
        """Même règle que | esearch : le premier profil autorisé dans l'ordre
        fixé par l'administrateur, annoncé."""
        dispo = self._appel({"action": "profiles"}).get("profiles") or []
        if not dispo:
            raise ValueError("aucun profil disponible pour vous : demandez à un "
                             "administrateur l'accès à un profil")
        self._warn(f"esindices: profil par défaut : {dispo[0]}")
        return dispo[0]


dispatch(ESIndicesCommand, sys.argv, sys.stdin, sys.stdout, __name__)
