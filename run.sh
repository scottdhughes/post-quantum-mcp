#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Add common liboqs install locations to library path
if [ "$(uname)" = "Darwin" ]; then
    export DYLD_LIBRARY_PATH="${HOME}/.local/lib:/usr/local/lib:${DYLD_LIBRARY_PATH}"
else
    export LD_LIBRARY_PATH="${HOME}/.local/lib:/usr/local/lib:${LD_LIBRARY_PATH}"
fi

# Use the venv in the project directory if it exists, otherwise fall back to system python
if [ -f "${SCRIPT_DIR}/.venv/bin/python" ]; then
    exec "${SCRIPT_DIR}/.venv/bin/python" -m pqc_mcp_server "$@"
else
    exec python3 -m pqc_mcp_server "$@"
fi
