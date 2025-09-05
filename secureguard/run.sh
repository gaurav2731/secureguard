#!/bin/bash
# SecureGuard Run Script
# Starts Flask + tails logs in real-time

# activate venv if exists
if [ -d "venv" ]; then
  source venv/bin/activate
fi

# ensure logs dir exists
mkdir -p logs

# start Flask app in background
echo "🚀 Starting SecureGuard..."
python3 app.py > logs/flask_output.log 2>&1 &

APP_PID=$!
echo "✅ Flask started (PID=$APP_PID)"
echo "📖 Showing live logs (Ctrl+C to stop)..."

# tail both Flask output + rotating firewall log
tail -f logs/flask_output.log logs/secureguard.log
