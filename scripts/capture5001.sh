#!/usr/bin/env bash
# Compatibility with the existing port-5001 service.
export PORT=5001
export CAPTURE_DIR=${CAPTURE_DIR:-/var/lib/pkappa2-capture5001}
exec "$(dirname -- "${BASH_SOURCE[0]}")/capture.sh" "$@"
