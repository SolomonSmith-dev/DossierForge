#!/bin/bash

# DossierForge Flask App Manager
# Usage: ./start_app.sh [start|stop|restart|status]

PORT=5001
APP_NAME="DossierForge"

# Function to find and kill processes on the port
kill_port() {
    local port=$1
    local pids=$(lsof -ti:$port 2>/dev/null)
    if [ ! -z "$pids" ]; then
        echo "Killing processes on port $port: $pids"
        kill -9 $pids
        sleep 1
    else
        echo "No processes found on port $port"
    fi
}

# Function to check if app is running
check_status() {
    local pids=$(lsof -ti:$PORT 2>/dev/null)
    if [ ! -z "$pids" ]; then
        echo "✅ $APP_NAME is running on port $PORT (PIDs: $pids)"
        echo "🌐 Access at: http://127.0.0.1:$PORT"
        return 0
    else
        echo "❌ $APP_NAME is not running on port $PORT"
        return 1
    fi
}

# Function to start the app
start_app() {
    echo "🚀 Starting $APP_NAME..."
    
    # Kill any existing processes on the port
    kill_port $PORT

    PYTHON_BIN=""
    if [ -n "$VIRTUAL_ENV" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
        PYTHON_BIN="$VIRTUAL_ENV/bin/python"
    else
        PYTHON_BIN=$(command -v python3 || command -v python)
    fi

    if [ -z "$PYTHON_BIN" ]; then
        echo "❌ Python interpreter not found. Activate your virtualenv or install Python."
        exit 1
    fi
    
    # Start the Flask app
    "$PYTHON_BIN" app.py &
    
    # Wait a moment and check if it started
    sleep 2
    if check_status; then
        echo "✅ $APP_NAME started successfully!"
        echo "🌐 Open your browser to: http://127.0.0.1:$PORT"
        echo "🛑 To stop: ./start_app.sh stop"
    else
        echo "❌ Failed to start $APP_NAME"
        exit 1
    fi
}

# Function to stop the app
stop_app() {
    echo "🛑 Stopping $APP_NAME..."
    kill_port $PORT
    echo "✅ $APP_NAME stopped"
}

# Function to restart the app
restart_app() {
    echo "🔄 Restarting $APP_NAME..."
    stop_app
    sleep 1
    start_app
}

# Main script logic
case "${1:-start}" in
    start)
        start_app
        ;;
    stop)
        stop_app
        ;;
    restart)
        restart_app
        ;;
    status)
        check_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        echo ""
        echo "Commands:"
        echo "  start   - Start the Flask app"
        echo "  stop    - Stop the Flask app"
        echo "  restart - Restart the Flask app"
        echo "  status  - Check if app is running"
        exit 1
        ;;
esac 
