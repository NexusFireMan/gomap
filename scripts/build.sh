#!/bin/bash
# build.sh - Build script for gomap with version information

VERSION="2.0.5"
BINARY_NAME="gomap"

echo "🔨 Building $BINARY_NAME v$VERSION..."
echo ""

# Clean Go cache to ensure fresh build
echo "🧹 Cleaning Go build cache..."
go clean -cache

# Build with -a flag to rebuild all dependencies and proper version embed
# -a: force rebuild of packages that are already up-to-date
# -ldflags=\"-s -w\": strip symbols and DWARF debug info for smaller binary
go build -a -ldflags="-s -w" -o "$BINARY_NAME" .

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Build successful!"
    echo "✓ Binary: $BINARY_NAME"
    ls -lh "$BINARY_NAME"
    echo ""
    echo "📝 Installation options:"
    echo "  1. Local: ./install.sh"
    echo "  2. Manual: sudo mv gomap /usr/local/bin/"
    echo "  3. PATH: export PATH=\$PATH:\$PWD"
else
    echo "✗ Build failed!"
    exit 1
fi
