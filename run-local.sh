#!/bin/bash
# Local development server runner

# Change to app directory
cd "$(dirname "$0")/app" || exit 1

# Check if CSS is built
if [ ! -f "static/tailwind.generated.css" ]; then
    echo "❌ CSS not built! Running build script..."
    cd .. && ./build-css.sh && cd app
fi

# Set SECRET_KEY if not already set
if [ -z "$SECRET_KEY" ]; then
    echo "⚠️  SECRET_KEY not set. Generating temporary key for this session..."
    export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
fi

# Run the app
echo "🚀 Starting Unraid Dedupe Manager..."
echo "📍 Access the UI at http://localhost:5000"
echo ""
python web_ui.py

