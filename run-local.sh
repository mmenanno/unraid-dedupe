#!/bin/bash
# Local development server runner

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Check if Python dependencies are installed
echo "🔍 Checking Python dependencies..."
if ! python3 -c "import yaml" 2>/dev/null; then
    echo "📦 Installing Python dependencies..."
    pip3 install -r requirements.txt || {
        echo "❌ Failed to install dependencies"
        echo "💡 Try: pip3 install -r requirements.txt"
        exit 1
    }
fi

# Check if CSS is built
if [ ! -f "app/static/tailwind.generated.css" ]; then
    echo "🎨 Building Tailwind CSS..."
    ./build-css.sh || exit 1
fi

# Set SECRET_KEY if not already set
if [ -z "$SECRET_KEY" ]; then
    echo "🔑 Generating temporary SECRET_KEY for this session..."
    export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
fi

# Change to app directory and run
cd app || exit 1
echo ""
echo "🚀 Starting Unraid Dedupe Manager..."
echo "📍 Access the UI at http://localhost:5000"
echo ""
python3 web_ui.py

