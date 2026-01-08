#!/bin/bash
export DYLD_LIBRARY_PATH="/Users/scott/.local/lib:$DYLD_LIBRARY_PATH"
exec /Users/scott/pqc-mcp-server/.venv/bin/python -m pqc_mcp_server "$@"
