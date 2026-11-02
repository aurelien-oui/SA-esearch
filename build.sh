#!/usr/bin/env bash
# Empaquette SA-esearch en .tgz installable.
#
# Les trois documents (README / OPERATIONS / COMPATIBILITY) vivent
# à la racine de ce dossier — source unique de vérité. Ils sont copiés dans
# `docs/` **au moment du build uniquement** : l'arborescence de travail n'est
# jamais polluée par une copie qui pourrait diverger.
#
# Usage :
#   ./build.sh                 -> paquet prod (sans local/), version lue dans app.conf
#   ./build.sh --with-local    -> paquet de test (embarque local/ si présent)
#   ./build.sh -o /chemin      -> répertoire de sortie (défaut : dossier courant)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="SA-esearch"
SRC="$SCRIPT_DIR/$APP"
DOCS=(README.md OPERATIONS.md COMPATIBILITY.md)

with_local=0
out_dir="$PWD"
while [ $# -gt 0 ]; do
  case "$1" in
    --with-local) with_local=1; shift ;;
    -o|--out)     out_dir="$2"; shift 2 ;;
    -h|--help)    sed -n '2,13p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)            echo "option inconnue : $1" >&2; exit 2 ;;
  esac
done

[ -d "$SRC" ] || { echo "introuvable : $SRC" >&2; exit 1; }

version="$(sed -n 's/^version *= *//p' "$SRC/default/app.conf" | head -1)"
[ -n "$version" ] || { echo "version illisible dans default/app.conf" >&2; exit 1; }

# Cohérence des trois emplacements de version : un décalage ici produit un paquet
# qui s'installe mais s'affiche sous un mauvais numéro.
v_init="$(sed -n 's/^__version__ *= *"\(.*\)"/\1/p' "$SRC/bin/sa_esearch/__init__.py" | head -1)"
v_man="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["info"]["id"]["version"])' "$SRC/app.manifest")"
for got in "$v_init" "$v_man"; do
  [ "$got" = "$version" ] || { echo "versions incohérentes : app.conf=$version __init__=$v_init manifest=$v_man" >&2; exit 1; }
done

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

# rsync absent sur certaines images minimales -> tar|tar, portable.
excl=(--exclude='__pycache__' --exclude='*.pyc' --exclude='._*' --exclude='.DS_Store' --exclude='log')
[ "$with_local" -eq 1 ] || excl+=(--exclude='local' --exclude='local.meta')
tar -cf - -C "$SCRIPT_DIR" "${excl[@]}" "$APP" | tar -xf - -C "$stage"

mkdir -p "$stage/$APP/docs"
for d in "${DOCS[@]}"; do
  cp "$SCRIPT_DIR/$d" "$stage/$APP/docs/$d"
done

find "$stage/$APP" -type d -exec chmod 755 {} +
find "$stage/$APP" -type f -exec chmod 644 {} +
chmod 755 "$stage/$APP/bin"/*.py 2>/dev/null || true

suffix=""; [ "$with_local" -eq 1 ] && suffix="-test"
paquet="$out_dir/${APP}-${version}${suffix}.tgz"
mkdir -p "$out_dir"
# --format=gnu : évite les en-têtes PAX que Splunk ancien digère mal.
tar -czf "$paquet" --format=gnu -C "$stage" "$APP"

echo "$paquet"
tar -tzf "$paquet" | grep -c . | xargs echo "  entrées :"
du -h "$paquet" | cut -f1 | xargs echo "  taille  :"
