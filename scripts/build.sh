#!/bin/bash
# build.sh - Build script for gomap with version information

set -e

BINARY_NAME="gomap"
VERSION="$(sed -n 's/.*Version = "\(.*\)".*/\1/p' cmd/gomap/version.go | head -n1)"
COMMIT="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X github.com/NexusFireMan/gomap/v2/cmd/gomap.Version=${VERSION} -X github.com/NexusFireMan/gomap/v2/cmd/gomap.Commit=${COMMIT} -X github.com/NexusFireMan/gomap/v2/cmd/gomap.Date=${BUILD_DATE}"

echo "🔨 Building $BINARY_NAME v$VERSION..."
echo ""

# Clean Go cache to ensure fresh build
echo "🧹 Cleaning Go build cache..."
go clean -cache

# Download and verify dependencies
echo "📥 Downloading dependencies..."
go mod download
go mod tidy

# Build with embedded version metadata.
go build -a -ldflags="$LDFLAGS" -o "$BINARY_NAME" .

echo ""
echo "✓ Build successful!"
echo "✓ Binary: $BINARY_NAME"
ls -lh "$BINARY_NAME"
echo ""
echo "📝 Installation options:"
echo "  1. Local: ./install.sh"
echo "  2. Manual: sudo mv gomap /usr/local/bin/"
echo "  3. PATH: export PATH=\$PATH:\$PWD"
