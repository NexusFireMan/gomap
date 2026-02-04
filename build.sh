#!/bin/bash
# build.sh - Build script for gomap with version information

VERSION="2.0.2"
BINARY_NAME="gomap"

echo "🔨 Building $BINARY_NAME v$VERSION..."

# Build with ldflags to embed version (optional)
go build -ldflags="-s -w" -o "$BINARY_NAME" .

if [ $? -eq 0 ]; then
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
