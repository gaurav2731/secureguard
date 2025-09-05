#!/bin/bash
# SecureGuard Run Script

# activate venv agar exist karta hai
if [ -d "venv" ]; then
  source venv/bin/activate
fi

# ensure logs dir exists
mkdir -p logs

# kill old flask process (if running)
if pgrep -f "app.py" > /dev/null; then
  echo "⚠️ Old SecureGuard process found. Killing..."
  pkill -f "app.py"
fi

# start Flask app in background
echo "🚀 Starting SecureGuard..."
python3 app.py > logs/flask_output.log 2>&1 &

APP_PID=$!
echo "✅ Flask started (PID=$APP_PID)"
echo "📖 Showing live logs (Ctrl+C to stop)..."

# tail both Flask output + secureguard log
tail -f logs/flask_output.log logs/secureguard.log
