#!/bin/bash
# install.sh - Installation script for gomap
# This script builds and installs gomap to /usr/local/bin for system-wide access

set -e

VERSION="$(sed -n 's/.*Version = "\(.*\)".*/\1/p' cmd/gomap/version.go | head -n1)"
COMMIT="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X github.com/NexusFireMan/gomap/v2/cmd/gomap.Version=${VERSION} -X github.com/NexusFireMan/gomap/v2/cmd/gomap.Commit=${COMMIT} -X github.com/NexusFireMan/gomap/v2/cmd/gomap.Date=${BUILD_DATE}"

echo "🔨 Building gomap..."
echo ""

# Clean Go cache to ensure fresh build from scratch
echo "🧹 Cleaning Go build cache..."
go clean -cache

# Download dependencies
echo "📥 Downloading dependencies..."
go mod download
go mod tidy

# Build with embedded version metadata
go build -a -ldflags="$LDFLAGS" -o gomap .

echo ""
echo "📦 Installing to /usr/local/bin..."

# Primary: Install to /usr/local/bin (recommended for all users)
if sudo -n true 2>/dev/null; then
    # User has sudo without password
    sudo mv gomap /usr/local/bin/
    echo "✓ gomap installed to /usr/local/bin/gomap"
    echo "✓ Available for all system users"
elif sudo -v; then
    # User can use sudo (will prompt for password)
    sudo mv gomap /usr/local/bin/
    echo "✓ gomap installed to /usr/local/bin/gomap"
    echo "✓ Available for all system users"
else
    # No sudo access - try alternative locations
    if [ -w /usr/local/bin ]; then
        mv gomap /usr/local/bin/
        echo "✓ gomap installed to /usr/local/bin/gomap"
        echo "✓ Available for all system users"
    else
        # Fallback: install to home directory
        mkdir -p "$HOME/bin"
        mv gomap "$HOME/bin/"
        echo "⚠ Could not write to /usr/local/bin"
        echo "⚠ gomap installed to $HOME/bin/gomap (user only)"
        echo ""
        echo "To make it available system-wide, add to PATH or reinstall with sudo:"
        echo "  export PATH=\"\$PATH:\$HOME/bin\""
        echo ""
        echo "Or ask your system administrator to run:"
        echo "  sudo mv $HOME/bin/gomap /usr/local/bin/"
    fi
fi

echo ""
echo "✓ Installation complete!"
echo "✓ You can now use: gomap --help"
