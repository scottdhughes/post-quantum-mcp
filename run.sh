#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prefer project-local liboqs (.vendor/liboqs-0.14) for version alignment.
# Falls back to ~/.local/lib and /usr/local/lib if vendor dir not present.
VENDOR_LIB="${SCRIPT_DIR}/.vendor/liboqs-0.14/lib"
if [ "$(uname)" = "Darwin" ]; then
    if [ -d "$VENDOR_LIB" ]; then
        export DYLD_LIBRARY_PATH="${VENDOR_LIB}:${DYLD_LIBRARY_PATH}"
    else
        export DYLD_LIBRARY_PATH="${HOME}/.local/lib:/usr/local/lib:${DYLD_LIBRARY_PATH}"
    fi
else
    if [ -d "$VENDOR_LIB" ]; then
        export LD_LIBRARY_PATH="${VENDOR_LIB}:${LD_LIBRARY_PATH}"
    else
        export LD_LIBRARY_PATH="${HOME}/.local/lib:/usr/local/lib:${LD_LIBRARY_PATH}"
    fi
fi

# Use the venv in the project directory if it exists, otherwise fall back to system python
if [ -f "${SCRIPT_DIR}/.venv/bin/python" ]; then
    exec "${SCRIPT_DIR}/.venv/bin/python" -m pqc_mcp_server "$@"
else
    exec python3 -m pqc_mcp_server "$@"
fi
