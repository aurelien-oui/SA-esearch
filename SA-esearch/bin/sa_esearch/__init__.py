"""Package interne de la commande esearch (config, transformation, client ES)."""

__version__ = "2.0.0"

# Nom de l'app Splunk — centralisé (utilisé pour le namespace storage/passwords,
# l'URL du proxy REST, etc.). Un renommage ne touche qu'ici (+ les .conf).
APP_NAME = "SA-esearch"

# Compat splunklib vendorisé (voir _compat) : appliqué dès l'import du package,
# donc avant toute requête HTTP splunklib. Le SDK vendorisé reste intact.
from sa_esearch import _compat as _compat

_compat.apply()
