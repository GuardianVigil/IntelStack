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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Welcome message
echo -e "${GREEN}Starting GuardianVigil/IntelStack installation...${NC}"

# Check if Python is installed
if ! command_exists python3; then
    echo -e "${RED}Python3 is not installed. Please install Python 3.8 or higher.${NC}"
    exit 1
fi

# Check if pip is installed
if ! command_exists pip3; then
    echo -e "${RED}pip3 is not installed. Please install pip3.${NC}"
    exit 1
fi

# Create and activate virtual environment
execute_command "python3 -m venv venv" \
    "Creating virtual environment" \
    "Failed to create virtual environment"

execute_command "source venv/bin/activate" \
    "Activating virtual environment" \
    "Failed to activate virtual environment"

# Upgrade pip
execute_command "pip install --upgrade pip" \
    "Upgrading pip" \
    "Failed to upgrade pip"

# Install requirements
execute_command "pip install -r requirements.txt" \
    "Installing requirements" \
    "Failed to install requirements"

# Install additional required packages for URL scanning
execute_command "pip install python-whois aiohttp" \
    "Installing URL scanning dependencies" \
    "Failed to install URL scanning dependencies"

# Install Redis
echo -e "${GREEN}Setting up Redis...${NC}"
if ! command_exists redis-server; then
    execute_command "sudo apt-get update && sudo apt-get install -y redis-server" \
        "Installing Redis" \
        "Failed to install Redis"
        
    execute_command "sudo systemctl start redis-server" \
        "Starting Redis service" \
        "Failed to start Redis service"
        
    execute_command "sudo systemctl enable redis-server" \
        "Enabling Redis service" \
        "Failed to enable Redis service"
else
    echo -e "${YELLOW}Redis is already installed${NC}"
fi

# Create necessary directories
execute_command "mkdir -p storage/screenshots" \
    "Creating screenshot storage directory" \
    "Failed to create screenshot storage directory"

execute_command "chmod 755 storage/screenshots" \
    "Setting screenshot directory permissions" \
    "Failed to set screenshot directory permissions"

# Create logs directory
execute_command "mkdir -p logs" \
    "Creating logs directory" \
    "Failed to create logs directory"

execute_command "chmod 755 logs" \
    "Setting logs directory permissions" \
    "Failed to set logs directory permissions"

# Add cron job for screenshot cleanup (30 days retention)
CRON_JOB="0 0 * * * find $(pwd)/storage/screenshots/* -type d -mtime +30 -exec rm -rf {} +"
(crontab -l 2>/dev/null | grep -Fv "screenshots") | crontab -
(crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
echo -e "${GREEN}Added screenshot cleanup cron job${NC}"

# Make run.sh executable
execute_command "chmod +x run.sh" \
    "Making run script executable" \
    "Failed to make run script executable"

# Run migrations
execute_command "./manage.py makemigrations" \
    "Creating database migrations" \
    "Failed to create database migrations"

execute_command "./manage.py migrate" \
    "Applying database migrations" \
    "Failed to apply database migrations"

execute_command "./manage.py collectstatic --noinput" \
    "Collecting static files" \
    "Failed to collect static files"

echo -e "${GREEN}Installation completed successfully!${NC}"
echo -e "${GREEN}Run './run.sh' to start the application${NC}"