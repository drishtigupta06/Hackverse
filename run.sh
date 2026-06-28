#!/bin/bash

# --- Configuration ---
FRONTEND_PORT=5175
BACKEND_PORT=8002
FLOWER_PORT=5555
REDIS_PORT=6379
MONGO_PORT=27017

echo "============================================"
echo "🛡️  CyberGuard Security Suite - Orchestrator"
echo "============================================"

# --- Cleanup ---
echo "🧹 Cleaning up existing processes..."
fuser -k $FRONTEND_PORT/tcp 2>/dev/null
fuser -k $BACKEND_PORT/tcp 2>/dev/null
fuser -k $FLOWER_PORT/tcp 2>/dev/null
pkill -f "celery worker" 1>/dev/null 2>&1
echo "✅ Port cleanup complete."

# --- Dependencies Check ---
echo "📦 Checking infrastructure dependencies..."

# Redis
if ! lsof -i:$REDIS_PORT > /dev/null; then
    echo "🔄 Starting Redis Server..."
    redis-server --daemonize yes
else
    echo "✅ Redis is already running."
fi

# MongoDB
if ! lsof -i:$MONGO_PORT > /dev/null; then
    echo "⚠️  MongoDB is NOT running. Attempting to start..."
    sudo systemctl start mongod 2>/dev/null || echo "❌ Failed to start MongoDB. Please start it manually (sudo systemctl start mongod)."
else
    echo "✅ MongoDB is already running."
fi

# --- Backend Setup ---
echo "🔌 Starting Backend API (Port $BACKEND_PORT)..."
cd "$(dirname "$0")/backend"
# Ensure dependencies are installed (optional, might take time)
# pip install -r requirements.txt 2>/dev/null
nohup python3 -m uvicorn main:app --host 0.0.0.0 --port $BACKEND_PORT > /tmp/cyberguard_api.log 2>&1 &
echo "✅ Backend started (Logs: /tmp/cyberguard_api.log)"

# --- Celery Worker ---
echo "👷 Starting Celery Worker..."
nohup celery -A celery_tasks worker --loglevel=info > /tmp/cyberguard_worker.log 2>&1 &
echo "✅ Celery Worker started (Logs: /tmp/cyberguard_worker.log)"

# --- Flower ---
echo "🌸 Starting Flower Monitor (Port $FLOWER_PORT)..."
nohup celery -A celery_tasks flower --port=$FLOWER_PORT --basic_auth=admin:cyberguard2024 > /tmp/cyberguard_flower.log 2>&1 &
echo "✅ Flower Monitor started (Logs: /tmp/cyberguard_flower.log)"

# --- Frontend Setup ---
echo "🌐 Starting Frontend (Port $FRONTEND_PORT)..."
cd "../frontend"
if [ ! -d "node_modules" ]; then
    echo "📥 node_modules not found. Installing frontend dependencies..."
    npm install
fi
nohup npm run dev -- --port $FRONTEND_PORT --host > /tmp/cyberguard_frontend.log 2>&1 &
echo "✅ Frontend started (Logs: /tmp/cyberguard_frontend.log)"

echo ""
echo "✨ ALL SYSTEMS ONLINE!"
echo "--------------------------------------------------"
echo "🔗 Access CyberGuard: http://localhost:$FRONTEND_PORT"
echo "🛠️  Backend Health:  http://localhost:$BACKEND_PORT/health"
echo "🌸 Task Monitor:    http://localhost:$FRONTEND_PORT/tasks"
echo "--------------------------------------------------"
echo "To stop everything, run: pkill -f uvicorn && pkill -f celery && fuser -k $FRONTEND_PORT/tcp"
