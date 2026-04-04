#!/bin/bash
set -euo pipefail

# Install liboqs from source for post-quantum-mcp
# Usage: ./scripts/install-liboqs.sh [--prefix /usr/local] [--version 0.15.0]

PREFIX="/usr/local"
VERSION="0.14.0"  # Must match liboqs-python 0.14.1 — see README Tested Compatibility
TMPDIR="${TMPDIR:-/tmp}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --help) echo "Usage: $0 [--prefix /path] [--version 0.15.0]"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "Installing liboqs ${VERSION} to ${PREFIX}..."

# Install build dependencies
OS="$(uname)"
if [ "$OS" = "Darwin" ]; then
    if ! command -v cmake &>/dev/null || ! command -v ninja &>/dev/null; then
        echo "Installing cmake and ninja via Homebrew..."
        brew install cmake ninja
    fi
elif [ "$OS" = "Linux" ]; then
    if ! command -v cmake &>/dev/null || ! command -v ninja &>/dev/null; then
        echo "Installing cmake and ninja via apt..."
        sudo apt-get update && sudo apt-get install -y cmake ninja-build
    fi
else
    echo "Unsupported OS: $OS"
    exit 1
fi

# Clone and build
BUILD_DIR="${TMPDIR}/liboqs-build-$$"
echo "Cloning liboqs ${VERSION}..."
git clone --depth 1 --branch "${VERSION}" \
    https://github.com/open-quantum-safe/liboqs.git "${BUILD_DIR}"

cd "${BUILD_DIR}"
mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="${PREFIX}" ..
ninja

echo "Installing to ${PREFIX} (may require sudo)..."
if [ -w "${PREFIX}" ]; then
    ninja install
else
    sudo ninja install
fi

# Update library cache on Linux
if [ "$OS" = "Linux" ]; then
    sudo ldconfig
fi

# Clean up
rm -rf "${BUILD_DIR}"

echo "liboqs ${VERSION} installed to ${PREFIX}."
echo ""
echo "Set library path in your shell:"
if [ "$OS" = "Darwin" ]; then
    echo "  export DYLD_LIBRARY_PATH=\"${PREFIX}/lib:\${DYLD_LIBRARY_PATH}\""
else
    echo "  export LD_LIBRARY_PATH=\"${PREFIX}/lib:\${LD_LIBRARY_PATH}\""
fi
