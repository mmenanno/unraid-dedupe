#!/bin/bash
# Build script for generating Tailwind CSS
# This script downloads the Tailwind standalone CLI if needed and builds the CSS

set -e

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Map architecture names
if [ "$ARCH" = "x86_64" ]; then
    ARCH="x64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH="arm64"
fi

# Determine Tailwind CLI binary name
if [ "$OS" = "darwin" ]; then
    if [ "$ARCH" = "arm64" ]; then
        TAILWIND_BINARY="tailwindcss-macos-arm64"
    else
        TAILWIND_BINARY="tailwindcss-macos-x64"
    fi
elif [ "$OS" = "linux" ]; then
    if [ "$ARCH" = "arm64" ]; then
        TAILWIND_BINARY="tailwindcss-linux-arm64"
    else
        TAILWIND_BINARY="tailwindcss-linux-x64"
    fi
else
    echo "Unsupported OS: $OS"
    exit 1
fi

# Create bin directory if it doesn't exist
mkdir -p .bin

TAILWIND_PATH=".bin/tailwindcss"

# Download Tailwind CLI if not present
if [ ! -f "$TAILWIND_PATH" ]; then
    echo "Downloading Tailwind CSS standalone CLI (latest)..."
    curl -sL "https://github.com/tailwindlabs/tailwindcss/releases/latest/download/${TAILWIND_BINARY}" -o "$TAILWIND_PATH"
    chmod +x "$TAILWIND_PATH"
    echo "Tailwind CLI downloaded successfully!"
fi

# Build CSS
echo "Building Tailwind CSS..."
if [ "$1" = "--watch" ]; then
    echo "Watching for changes (press Ctrl+C to stop)..."
    "$TAILWIND_PATH" -i ./app/static/tailwind.src.css -o ./app/static/tailwind.generated.css --watch
else
    "$TAILWIND_PATH" -i ./app/static/tailwind.src.css -o ./app/static/tailwind.generated.css --minify
    echo "CSS built successfully at app/static/tailwind.generated.css"
fi

