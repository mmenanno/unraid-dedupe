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

# Set up local data directory for development
LOCAL_DATA_DIR="$SCRIPT_DIR/data"
mkdir -p "$LOCAL_DATA_DIR/config" "$LOCAL_DATA_DIR/reports" "$LOCAL_DATA_DIR/logs"
export DATA_DIR="$LOCAL_DATA_DIR"

# Set SECRET_KEY if not already set
if [ -z "$SECRET_KEY" ]; then
    echo "🔑 Generating temporary SECRET_KEY for this session..."
    export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
fi

# Set Flask debug mode for local development
export FLASK_DEBUG=true

# Change to app directory and run
cd app || exit 1
echo ""
echo "🚀 Starting Unraid Dedupe Manager (Development Mode)..."
echo "📍 Access the UI at http://localhost:5000"
echo "📁 Data directory: $DATA_DIR"
echo ""
python3 web_ui.py

