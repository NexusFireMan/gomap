#!/bin/bash
# build.sh - Build script for gomap with version information

set -e

VERSION="2.0.5"
BINARY_NAME="gomap"

echo "🔨 Building $BINARY_NAME v$VERSION..."
echo ""

# Clean Go cache to ensure fresh build
echo "🧹 Cleaning Go build cache..."
go clean -cache

# Download and verify dependencies
echo "📥 Downloading dependencies..."
go mod download
go mod tidy

# Build with -a flag to rebuild all dependencies and proper version embed
# -a: force rebuild of packages that are already up-to-date
# -ldflags="-s -w": strip symbols and DWARF debug info for smaller binary
go build -a -ldflags="-s -w" -o "$BINARY_NAME" .

echo ""
echo "✓ Build successful!"
echo "✓ Binary: $BINARY_NAME"
ls -lh "$BINARY_NAME"
echo ""
echo "📝 Installation options:"
echo "  1. Local: ./install.sh"
echo "  2. Manual: sudo mv gomap /usr/local/bin/"
echo "  3. PATH: export PATH=\$PATH:\$PWD"
