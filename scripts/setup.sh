#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$ROOT"
docker compose version >/dev/null

if [[ ! -f .env ]]; then
    umask 077
    USER_PASSWORD=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
    PCAP_PASSWORD=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
    # Refuse to overwrite a configuration created by another setup process.
    (
        set -o noclobber
        sed -e "s/^PKAPPA2_USER_PASSWORD=.*/PKAPPA2_USER_PASSWORD=$USER_PASSWORD/" \
            -e "s/^PKAPPA2_PCAP_PASSWORD=.*/PKAPPA2_PCAP_PASSWORD=$PCAP_PASSWORD/" \
            .env.example > .env
    )
    echo 'Created .env with separate random passwords; keep this file private.'
fi

docker compose config --quiet
docker compose up -d --build
echo 'Monitoring started. Web port and login password are in .env; username: admin.'
