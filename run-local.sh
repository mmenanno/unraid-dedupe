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

# Build CSS on startup to ensure it's fresh
echo "🎨 Building Tailwind CSS..."
./build-css.sh || exit 1

# Start CSS watch process in background for auto-rebuild
echo "👀 Starting CSS watch process..."
./build-css.sh --watch > /dev/null 2>&1 &
CSS_WATCH_PID=$!

# Set up cleanup trap to kill watch process on exit
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    if [ ! -z "$CSS_WATCH_PID" ]; then
        kill $CSS_WATCH_PID 2>/dev/null
    fi
    exit
}
trap cleanup INT TERM EXIT

# Set up local data directory for development
LOCAL_DATA_DIR="$SCRIPT_DIR/data"
mkdir -p "$LOCAL_DATA_DIR/config" "$LOCAL_DATA_DIR/reports" "$LOCAL_DATA_DIR/logs"
export DATA_DIR="$LOCAL_DATA_DIR"

# Copy default config if it doesn't exist
if [ ! -f "$LOCAL_DATA_DIR/config/dedupe_config.yaml" ]; then
    echo "📋 Copying default configuration..."
    cp "$SCRIPT_DIR/config/dedupe_config.yaml" "$LOCAL_DATA_DIR/config/dedupe_config.yaml"
fi

# Set SECRET_KEY if not already set
if [ -z "$SECRET_KEY" ]; then
    echo "🔑 Generating temporary SECRET_KEY for this session..."
    export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
fi

# Set Flask configuration for local development
export FLASK_APP=web_ui.py
export FLASK_DEBUG=true

# Change to app directory and run
cd app || exit 1
echo ""
echo "🚀 Starting Unraid Dedupe Manager (Development Mode)..."
echo "📍 Access the UI at http://localhost:5001"
echo "📁 Data directory: $DATA_DIR"
echo ""
python3 -m flask run --host=0.0.0.0 --port=5001

