#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
usage() {
    echo "Usage: sudo $0 add|remove|status INTERFACE PORT [PORT ...]"
    echo "Example: sudo $0 add eth0 7070 5001"
    exit 1
}
[[ $# -ge 3 ]] || usage
ACTION=$1
IFACE=$2
shift 2
[[ "$ACTION" == add || "$ACTION" == remove || "$ACTION" == status ]] || usage
[[ "$IFACE" =~ ^[a-zA-Z0-9_.:-]+$ ]] || { echo 'Invalid interface' >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo 'Run with sudo' >&2; exit 1; }
for PORT in "$@"; do
    [[ "$PORT" =~ ^[0-9]{1,5}$ ]] || usage
    PORT=$((10#$PORT))
    (( PORT >= 1 && PORT <= 65535 )) || usage
done
if [[ "$ACTION" == add ]]; then
    for dep in tcpdump curl flock systemctl ip; do
        command -v "$dep" >/dev/null || { echo "Missing dependency: $dep" >&2; exit 1; }
    done
    [[ "$IFACE" == any ]] || ip link show dev "$IFACE" >/dev/null
    # Install a stable copy: captures keep working if the repository moves.
    install -d -m 700 /opt/pkappa2-capture /etc/pkappa2-capture
    install -m 700 "$ROOT/scripts/capture.sh" /opt/pkappa2-capture/capture.sh
    if [[ -f "$ROOT/.env" ]]; then
        install -m 600 "$ROOT/.env" /etc/pkappa2-capture/monitor.env
    fi
fi
for PORT in "$@"; do
    PORT=$((10#$PORT))
    INSTANCE=$(systemd-escape "${IFACE}-${PORT}")
    UNIT="pkappa2-capture-${INSTANCE}.service"
    case "$ACTION" in
        add)
            CAPTURE_PATH="/var/lib/pkappa2-capture-$INSTANCE"
            LEGACY=false
            if [[ "$PORT" == 5001 ]]; then
                LEGACY_ENV=$(systemctl show pkappa2-capture5001.service -p Environment --value 2>/dev/null || true)
                if [[ " $LEGACY_ENV " == *" IFACE=$IFACE "* ]]; then
                    LEGACY=true
                    CAPTURE_PATH=/var/lib/pkappa2-capture5001
                fi
            fi
            cat > "/etc/systemd/system/$UNIT" <<UNITFILE
[Unit]
Description=Pkappa2 capture $IFACE port $PORT
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=simple
ExecStart=/opt/pkappa2-capture/capture.sh
Environment=ENV_FILE=/etc/pkappa2-capture/monitor.env
Environment=IFACE=$IFACE
Environment=PORT=$PORT
Environment=INTERVAL=10
Environment=CAPTURE_DIR=$CAPTURE_PATH
Restart=always
RestartSec=5
KillSignal=SIGINT
UMask=0077

[Install]
WantedBy=multi-user.target
UNITFILE
            systemctl daemon-reload
            if [[ "$LEGACY" == true ]]; then
                systemctl disable --now pkappa2-capture5001.service
                echo "Migrated legacy capture5001; pending captures preserved"
            fi
            systemctl enable "$UNIT"
            systemctl restart "$UNIT"
            systemctl --no-pager --full status "$UNIT"
            ;;
        remove)
            systemctl disable --now "$UNIT"
            rm -f -- "/etc/systemd/system/$UNIT"
            systemctl daemon-reload
            echo "Removed $UNIT; pending captures retained"
            ;;
        status) systemctl --no-pager --full status "$UNIT" ;;
    esac
done
