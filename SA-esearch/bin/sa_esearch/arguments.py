# -*- coding: utf-8 -*-
"""Erreurs d'arguments des commandes, signalées à l'EXÉCUTION.

splunklib contrôle les arguments (option inconnue, valeur refusée par un
validateur, option obligatoire absente) pendant la phase `getinfo`, écrit le
message puis quitte. Mesuré (Splunk 9.3.14) : Splunk rejette alors le
message (« Error adding inspector message: invalid level or message already
exists ») et n'affiche que « External search command exited unexpectedly » —
que le code de sortie soit 1 ou 0. Seuls les messages écrits pendant
l'exécution s'affichent.

Ce mixin laisse donc passer `getinfo` sans erreur, note les arguments refusés
et la commande les signale au début de `generate()` (`refuse_arguments()`).
Le SDK vendorisé n'est pas modifié : `_protocol_v2_option_parser` est le point
d'extension qu'il prévoit pour l'analyse des arguments.
"""

import re

from sa_esearch.log import apercu, court, get_logger

# Options que splunklib ajoute à toute commande (journalisation, enregistrement
# des échanges) : pas à proposer à l'utilisateur.
_OPTIONS_SDK = frozenset(("logging_configuration", "logging_level", "record", "show_configuration"))


def _attendu(validateur, erreur):
    """Ce qu'attend un validateur splunklib, en clair (bornes reprises de son
    message, seul endroit où il les expose)."""
    genre = type(validateur).__name__
    if genre == "Boolean":
        return "true ou false"
    texte = {"Integer": "un nombre entier", "Float": "un nombre"}.get(genre, "une autre valeur")
    bornes = re.search(r"range \[([^,\]]+),([^\]]+)\]", str(erreur))
    if bornes:
        mini, maxi = (b.strip() for b in bornes.groups())
        if "∞" not in mini and "∞" not in maxi:
            texte += f" entre {mini} et {maxi}"
        elif "∞" not in mini:
            texte += f" d'au moins {mini}"
        elif "∞" not in maxi:
            texte += f" d'au plus {maxi}"
    return texte


class ArgumentsSignales:
    """À placer AVANT GeneratingCommand dans les bases de la commande.

    `OBLIGATOIRES` ((option, aide), …) remplace `Option(require=True)` :
    splunklib quitterait en `getinfo` si l'option manquait."""

    OBLIGATOIRES = ()

    def _arguments_refuses(self):
        return self.__dict__.setdefault("_esearch_arguments_refuses", [])

    def _protocol_v2_option_parser(self, arg):
        resultat = super()._protocol_v2_option_parser(arg)
        if len(resultat) != 2:
            return resultat
        nom, valeur = (str(x) for x in resultat)
        try:
            option = self.options[nom]
        except KeyError:
            options = sorted(o for o in self.options if o not in _OPTIONS_SDK)
            self._arguments_refuses().append(
                f"option inconnue : {apercu(nom)} ("
                + (f"options : {court(', '.join(options), 400)})" if options else "aucune option acceptée)"))
            # Rendu comme argument positionnel : splunklib l'ignore pour une
            # commande génératrice, et l'exécution s'arrêtera sur l'erreur.
            return [arg]
        if option.validator is not None:
            try:
                option.validator(valeur)
            except ValueError as e:
                self._arguments_refuses().append(
                    f"valeur invalide pour {nom} : {apercu(valeur)} ({_attendu(option.validator, e)} attendu)")
                return [arg]
        return resultat

    def refuse_arguments(self):
        """Signale les arguments refusés ; True s'il y en a (la commande
        s'arrête alors sans rien produire)."""
        refus = list(self._arguments_refuses())
        for nom, aide in self.OBLIGATOIRES:
            if getattr(self, nom, None) is None:
                refus.append(f"{nom}= est obligatoire" + (f" ({aide})" if aide else ""))
        if not refus:
            return False
        commande = getattr(getattr(self._metadata, "searchinfo", None), "command", None) \
            or type(self).__name__
        for message in refus:
            get_logger().error("%s: %s", commande, message)
            self.write_error("{}", f"{commande}: {message}")
        return True
