#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SELF=$(readlink -f -- "${BASH_SOURCE[0]}")
ENV_FILE=${ENV_FILE:-$ROOT/.env}
PORT=${PORT:-5001}
IFACE=${IFACE:-any}
INTERVAL=${INTERVAL:-10}
UPLOAD_URL=${UPLOAD_URL:-http://127.0.0.1:8080}
CAPTURE_DIR=${CAPTURE_DIR:-/var/lib/pkappa2-capture-$PORT}

# Read dotenv as data, without executing shell expressions.
PASSWORD=${PKAPPA2_PCAP_PASSWORD:-}
if [[ -z "$PASSWORD" && -f "$ENV_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == PKAPPA2_PCAP_PASSWORD=* ]]; then
            PASSWORD=${line#*=}
            PASSWORD=${PASSWORD%$'\r'}
            if [[ "$PASSWORD" == \"*\" || "$PASSWORD" == \'*\' ]]; then
                PASSWORD=${PASSWORD:1:${#PASSWORD}-2}
            fi
        fi
    done < "$ENV_FILE"
fi

upload_pending() {
    exec 9>"$CAPTURE_DIR/upload.lock"
    flock 9
    shopt -s nullglob
    for file in "$CAPTURE_DIR"/*.pcap; do
        if curl --silent --show-error --fail --connect-timeout 5 --max-time 30 \
            --user "admin:$PASSWORD" --data-binary "@$file" \
            "${UPLOAD_URL%/}/upload/$(basename -- "$file")"; then
            rm -- "$file"
        else
            echo "Upload failed; retained $file for the next attempt" >&2
            continue
        fi
    done
    flock -u 9
    exec 9>&-
}

if [[ ${1:-} == --upload ]]; then
    # Only closed captures become eligible for upload.
    mv -- "$2" "${2%.partial}.pcap"
    upload_pending
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: $SELF" >&2
    exit 1
fi
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || { echo "Invalid port" >&2; exit 1; }
[[ "$INTERVAL" =~ ^[0-9]+$ ]] && (( INTERVAL > 0 )) || { echo "Invalid interval" >&2; exit 1; }
mkdir -p -- "$CAPTURE_DIR"
chmod 700 -- "$CAPTURE_DIR"
exec 8>"$CAPTURE_DIR/capture.lock"
flock -n 8 || { echo 'Capture already running' >&2; exit 1; }
export IFACE INTERVAL UPLOAD_URL CAPTURE_DIR PORT ENV_FILE
shopt -s nullglob
for file in "$CAPTURE_DIR"/*.partial; do
    mv -- "$file" "${file%.partial}.pcap"
done
upload_pending
# tcpdump passes the closed filename as the sole argument to its callback.
CALLBACK="$CAPTURE_DIR/upload-closed.sh"
printf '#!/usr/bin/env bash\nexec %q --upload "$1"\n' "$SELF" > "$CALLBACK"
chmod 700 -- "$CALLBACK"
echo "Capturing port $PORT on $IFACE; uploading every $INTERVAL seconds"
tcpdump -i "$IFACE" -nn -s 0 -Z root -G "$INTERVAL" \
    -w "$CAPTURE_DIR/$(date +%s%N)_%Y%m%d_%H%M%S.partial" \
    -z "$CALLBACK" "tcp port $PORT or udp port $PORT" &
CAPTURE_PID=$!
stop_capture() {
    kill -INT "$CAPTURE_PID" 2>/dev/null || true
}
trap stop_capture INT TERM
set +e
wait "$CAPTURE_PID"
RESULT=$?
# A trapped signal can interrupt wait before tcpdump has closed its output.
if kill -0 "$CAPTURE_PID" 2>/dev/null; then
    wait "$CAPTURE_PID"
fi
set -e
shopt -s nullglob
for file in "$CAPTURE_DIR"/*.partial; do
    mv -- "$file" "${file%.partial}.pcap"
done
upload_pending
exit "$RESULT"
