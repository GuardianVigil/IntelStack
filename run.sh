#!/bin/bash

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Debug mode flag
DEBUG=false

# Parse command line arguments
for arg in "$@"
do
    case $arg in
        --debug)
        DEBUG=true
        shift
        ;;
    esac
done

# Function to execute command with optional debug output
execute_command() {
    local command="$1"
    local message="$2"
    local error_message="$3"
    
    echo -e "${GREEN}$message...${NC}"
    
    if [ "$DEBUG" = true ]; then
        eval $command
    else
        eval $command >/dev/null 2>&1
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}$error_message${NC}"
        exit 1
    fi
}

# Activate virtual environment
execute_command "source venv/bin/activate" \
    "Activating virtual environment" \
    "Failed to activate virtual environment"

# Set up log file with timestamp
LOG_DIR="logs"
LOG_FILE="$LOG_DIR/app_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"

# Function to handle cleanup on script exit
cleanup() {
    echo -e "${YELLOW}Stopping server...${NC}"
    kill $(jobs -p) 2>/dev/null
}

# Set up trap for cleanup
trap cleanup EXIT

# Check Redis server
if ! pgrep redis-server > /dev/null; then
    echo -e "${YELLOW}Redis server is not running. Starting Redis...${NC}"
    execute_command "sudo systemctl start redis-server" \
        "Starting Redis service" \
        "Failed to start Redis service"
fi

# Start the server with output to both console and log file
echo -e "${GREEN}Starting GuardianVigil/IntelStack server...${NC}"
echo -e "${GREEN}Log file: $LOG_FILE${NC}"

if [ "$DEBUG" = true ]; then
    python3 manage.py runserver 0.0.0.0:8000 2>&1 | tee -a "$LOG_FILE"
else
    python3 manage.py runserver 0.0.0.0:8000 2>&1 | tee -a "$LOG_FILE"
fi