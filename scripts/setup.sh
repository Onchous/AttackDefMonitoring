#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$ROOT"
docker compose version >/dev/null

FARM_CLIENT_DIR=./farm_exports
if [[ -d ../DestructiveFarm/client ]]; then
    FARM_CLIENT_DIR=../DestructiveFarm/client
else
    mkdir -p -- farm_exports
fi

if [[ ! -f .env ]]; then
    umask 077
    USER_PASSWORD=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
    PCAP_PASSWORD=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
    # Refuse to overwrite a configuration created by another setup process.
    (
        set -o noclobber
        sed -e "s/^PKAPPA2_USER_PASSWORD=.*/PKAPPA2_USER_PASSWORD=$USER_PASSWORD/" \
            -e "s/^PKAPPA2_PCAP_PASSWORD=.*/PKAPPA2_PCAP_PASSWORD=$PCAP_PASSWORD/" \
            -e "s#^DESTRUCTIVE_FARM_CLIENT_DIR=.*#DESTRUCTIVE_FARM_CLIENT_DIR=$FARM_CLIENT_DIR#" \
            .env.example > .env
    )
    echo 'Created .env with separate random passwords; keep this file private.'
elif ! grep -q '^DESTRUCTIVE_FARM_CLIENT_DIR=' .env; then
    printf '\nDESTRUCTIVE_FARM_CLIENT_DIR=%s\n' "$FARM_CLIENT_DIR" >> .env
elif [[ "$FARM_CLIENT_DIR" == ../DestructiveFarm/client ]] && \
    grep -q '^DESTRUCTIVE_FARM_CLIENT_DIR=\./farm_exports$' .env; then
    sed -i 's#^DESTRUCTIVE_FARM_CLIENT_DIR=\./farm_exports$#DESTRUCTIVE_FARM_CLIENT_DIR=../DestructiveFarm/client#' .env
fi

# Give the unprivileged backend the host directory's existing group as a
# supplementary container group. The setgid bit keeps new files in that group.
CONFIGURED_FARM_DIR=$(sed -n 's/^DESTRUCTIVE_FARM_CLIENT_DIR=//p' .env | tail -n 1)
CONFIGURED_FARM_DIR=${CONFIGURED_FARM_DIR%$'\r'}
CONFIGURED_FARM_DIR=${CONFIGURED_FARM_DIR#\"}
CONFIGURED_FARM_DIR=${CONFIGURED_FARM_DIR%\"}
[[ -n "$CONFIGURED_FARM_DIR" ]] || { echo 'DESTRUCTIVE_FARM_CLIENT_DIR is empty' >&2; exit 1; }
mkdir -p -- "$CONFIGURED_FARM_DIR"
chmod g+rws -- "$CONFIGURED_FARM_DIR"
FARM_EXPORT_GID=$(stat -c '%g' -- "$CONFIGURED_FARM_DIR")
if grep -q '^PKAPPA2_FARM_EXPORT_GID=' .env; then
    sed -i "s/^PKAPPA2_FARM_EXPORT_GID=.*/PKAPPA2_FARM_EXPORT_GID=$FARM_EXPORT_GID/" .env
else
    printf 'PKAPPA2_FARM_EXPORT_GID=%s\n' "$FARM_EXPORT_GID" >> .env
fi

docker compose config --quiet
docker compose up -d --build
echo 'Monitoring started. Web port and login password are in .env; username: admin.'
