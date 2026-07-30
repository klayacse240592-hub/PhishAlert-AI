#!/bin/bash
echo "=========================================="
echo " PhishGuard - Starting Backend Server"
echo "=========================================="

cd backend

echo "Installing dependencies..."
pip3 install -r requirements.txt

echo ""
echo "Starting Flask server on http://localhost:5000"
echo ""
echo "Open frontend/index.html in your browser to use the app!"
echo "Press Ctrl+C to stop."
echo ""

python3 app.py
