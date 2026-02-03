#!/bin/bash
# install.sh - Installation script for gomap
# This script builds and installs gomap to /usr/local/bin for system-wide access

set -e

echo "🔨 Building gomap..."
go build -o gomap

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
