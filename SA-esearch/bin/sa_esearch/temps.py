# -*- coding: utf-8 -*-
"""Bornes `earliest=` / `latest=` écrites dans la commande (1.25.0).

Même sémantique que les modificateurs de temps de Splunk dans une recherche
(mesurée, Splunk 9.3) : dès qu'une borne est écrite, le sélecteur de
temps est ignoré ; `earliest=` seul va jusqu'à `now`, `latest=` seul part du
début des temps. Aucune fenêtre implicite (pas de « 24 h » par défaut).

La résolution est celle de Splunk, pas une réimplémentation : chaque valeur
part à l'endpoint `search/timeparser` de splunkd, avec le jeton de
l'utilisateur (son fuseau horaire s'applique aux arrondis `@d` et aux dates
absolues) et le `now` de la recherche (les deux bornes et le sélecteur
partagent la même référence). Formes acceptées : relatif (`-1h@h`, `@d`,
`now`), époque (`1700000000`, `0`), ISO 8601 (`2026-10-01T00:00:00`) et le
format des modificateurs Splunk (`10/01/2026:00:00:00`), que timeparser
refuse : il est réécrit en ISO, dans le même fuseau (vérifié).
"""

import json
import re

# Format des modificateurs de temps Splunk : %m/%d/%Y:%H:%M:%S.
_SPL = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4}):(\d{1,2}):(\d{1,2}):(\d{1,2})$")
_MAXI = 100
FORMES = "relatif (-1h@h, @d, now), époque, ISO 8601 ou MM/JJ/AAAA:HH:MM:SS"


def normalise(nom, valeur):
    """Texte à transmettre à timeparser pour l'option `nom`."""
    v = str(valeur).strip()
    if not v:
        raise ValueError(f"{nom}= est vide (attendu : {FORMES})")
    if len(v) > _MAXI:
        raise ValueError(f"{nom}= trop long ({len(v)} caractères, {_MAXI} au plus)")
    if v.lower().startswith("rt"):
        raise ValueError(f"{nom}={v} : le temps réel n'est pas pris en charge "
                         "(Elasticsearch est interrogé une fois)")
    m = _SPL.match(v)
    if m:
        mo, j, a, h, mi, s = (int(x) for x in m.groups())
        v = f"{a:04d}-{mo:02d}-{j:02d}T{h:02d}:{mi:02d}:{s:02d}"
    return v


def bornes(earliest, latest, resout, now):
    """(earliest, latest) en époque, ou None si aucune borne n'est écrite.

    `resout(nom, texte)` rend l'époque de `texte` ou lève ValueError ; `now` est
    la référence de la recherche. 0 en earliest signifie « pas de borne basse »,
    comme pour le sélecteur.
    """
    if earliest is None and latest is None:
        return None
    e = resout("earliest", normalise("earliest", earliest)) if earliest is not None else 0.0
    if latest is not None:
        lat = resout("latest", normalise("latest", latest))
        if lat <= 0:
            raise ValueError(f"latest={latest} : borne au début des temps, aucun événement possible")
    else:
        lat = float(now)
    if lat <= e:
        haut = f"latest={latest}" if latest is not None else "now"
        bas = f"earliest={earliest}" if earliest is not None else "le début des temps"
        raise ValueError(f"{haut} ({lat:.0f}) n'est pas postérieur à {bas} ({e:.0f}) : "
                         "fenêtre vide")
    return e, lat


def resolveur(service, now):
    """Fonction `resout` pour bornes(), adossée à splunkd (`service` : splunklib
    connecté avec le jeton de l'utilisateur). Une valeur par appel : timeparser
    refuse la requête entière pour une seule valeur invalide, sans dire laquelle."""
    from splunklib.binding import HTTPError

    def resout(nom, texte):
        try:
            rep = service.get("search/timeparser", time=texte, now=f"{float(now):.3f}",
                              output_time_format="%s.%Q", output_mode="json")
            corps = json.loads(rep.body.read())
        except HTTPError as e:
            if e.status == 400:
                raise ValueError(f"{nom}={texte} : temps invalide pour Splunk "
                                 f"(attendu : {FORMES})") from None
            raise RuntimeError(f"résolution de {nom}= par splunkd impossible "
                               f"(HTTP {e.status})") from None
        except OSError as e:
            raise RuntimeError(f"résolution de {nom}= : splunkd injoignable "
                               f"({e.__class__.__name__})") from None
        try:
            return float(corps[texte])
        except (KeyError, TypeError, ValueError):
            raise ValueError(f"{nom}={texte} : réponse de Splunk inattendue "
                             f"({str(corps)[:80]})") from None
    return resout
