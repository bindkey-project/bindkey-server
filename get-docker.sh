#!/bin/sh
# Script Shell POSIX

set -e
# Arrête le script si une commande échoue


# ───────────────────────────────
# Script officiel d’installation Docker
# ───────────────────────────────
# Configure les dépôts et installe :
# - Docker Engine
# - Docker CLI
# - Docker Compose
# - containerd / runc


# Identifiant de version du script
SCRIPT_COMMIT_SHA="7d96bd3c5235ab2121bcb855dd7b3f3f37128ed4"

# Supprime un éventuel préfixe "v" dans la version si fourni (ex : v23.0 → 23.0)
VERSION="${VERSION#v}"

# Valeur par défaut du canal de distribution (stable/test)
DEFAULT_CHANNEL_VALUE="stable"

# Si l'utilisateur n'a pas défini $CHANNEL, on utilise le canal stable
if [ -z "$CHANNEL" ]; then
	CHANNEL=$DEFAULT_CHANNEL_VALUE
fi

# URL de téléchargement Docker par défaut
DEFAULT_DOWNLOAD_URL="https://download.docker.com"

# Si l'utilisateur n'a pas fourni de miroir, on utilise l'URL Docker officielle
if [ -z "$DOWNLOAD_URL" ]; then
	DOWNLOAD_URL=$DEFAULT_DOWNLOAD_URL
fi

# Nom du fichier de configuration du repository
DEFAULT_REPO_FILE="docker-ce.repo"

# Si aucune valeur n'est fournie, utiliser le fichier repo standard
if [ -z "$REPO_FILE" ]; then
	REPO_FILE="$DEFAULT_REPO_FILE"

	# Si l'URL contient "-stage", utiliser le repo spécial "staging"
	case "$DOWNLOAD_URL" in
		*-stage*) REPO_FILE="docker-ce-staging.repo";;
	esac
fi

# Initialisation de variables diverses
mirror=''               # Nom éventuel du miroir (Aliyun, Azure, etc.)
DRY_RUN=${DRY_RUN:-}    # Mode simulation
REPO_ONLY=${REPO_ONLY:-0}  # Mode où seul le repository est configuré

# Analyse des arguments en ligne de commande
while [ $# -gt 0 ]; do
	case "$1" in
		--channel)
			CHANNEL="$2"   # Définit le canal (stable/test)
			shift
			;;
		--dry-run)
			DRY_RUN=1     # Active le mode simulation
			;;
		--mirror)
			mirror="$2"   # Définit le miroir à utiliser
			shift
			;;
		--version)
			VERSION="${2#v}"  # Spécifie une version exacte à installer
			shift
			;;
		--setup-repo)
			REPO_ONLY=1  # N'installe pas Docker, configure juste le dépôt
			shift
			;;
		--*)
			echo "Illegal option $1"  # Mauvaise option → affiche un warning
			;;
	esac
	shift $(( $# > 0 ? 1 : 0 ))
done