#!/usr/bin/env bash
# Plant live leftovers on this host, run LinuxLinger, tear them down.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 "$SCRIPT_DIR/simulate_dirty_host.py"
