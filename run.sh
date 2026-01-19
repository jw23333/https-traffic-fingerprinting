#!/bin/bash
# Auto-setup launcher - works on any machine without manual venv setup

set -e

VENV_DIR=".venv"
REQUIREMENTS="pandas scikit-learn joblib"

# Test if venv works
if [ -d "$VENV_DIR" ]; then
    if ! "$VENV_DIR/bin/python" --version &>/dev/null; then
        echo "⚠️  venv broken (different Python version), recreating..."
        rm -rf "$VENV_DIR"
    fi
fi

# Create venv if missing
if [ ! -d "$VENV_DIR" ]; then
    echo "📦 Creating venv with $(python3 --version)..."
    python3 -m venv "$VENV_DIR"
    echo "✅ venv created"
fi

# Install dependencies if needed
if ! "$VENV_DIR/bin/python" -c "import pandas, sklearn, joblib" &>/dev/null; then
    echo "📥 Installing dependencies..."
    "$VENV_DIR/bin/pip" install --quiet $REQUIREMENTS
    echo "✅ Dependencies installed"
fi

# Run the requested command or default to GUI
if [ $# -eq 0 ]; then
    echo "🚀 Launching GUI..."
    "$VENV_DIR/bin/python" gui_capture_app.py
else
    "$VENV_DIR/bin/python" "$@"
fi
