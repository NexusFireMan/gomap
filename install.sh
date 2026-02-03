#!/bin/bash
# install.sh - Installation script for gomap
# This script builds and installs gomap to a system-accessible location

set -e

echo "🔨 Building gomap..."
go build -o gomap

echo "📦 Installing to system..."

# Try to install to /usr/local/bin (preferred)
if [ -w /usr/local/bin ]; then
    sudo mv gomap /usr/local/bin/
    echo "✓ gomap installed to /usr/local/bin/gomap"
# Try to install to /usr/bin
elif [ -w /usr/bin ]; then
    sudo mv gomap /usr/bin/
    echo "✓ gomap installed to /usr/bin/gomap"
# Fallback: install to home directory
else
    mkdir -p "$HOME/bin"
    mv gomap "$HOME/bin/"
    echo "⚠ gomap installed to $HOME/bin/gomap"
    echo "⚠ Add this to your ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"\$PATH:\$HOME/bin\""
fi

echo ""
echo "✓ Installation complete!"
echo "✓ You can now use: gomap --help"
