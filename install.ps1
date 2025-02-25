# Colors
$GREEN = "[32m"
$YELLOW = "[33m"
$RED = "[31m"
$NC = "[0m"

# Debug mode flag
$DEBUG = $false

# Parse command line arguments
foreach ($arg in $args) {
    if ($arg -eq "--debug") {
        $DEBUG = $true
    }
}

# Function to execute command with optional debug output
function Execute-Command {
    param (
        [string]$command,
        [string]$message,
        [string]$errorMessage
    )

    Write-Host "$GREEN$message...$NC"

    if ($DEBUG) {
        Invoke-Expression $command
    } else {
        Invoke-Expression $command > $null 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Host "$RED$errorMessage$NC"
        exit 1
    }
}

# Welcome message
Write-Host "$GREEN Starting GuardianVigil/IntelStack installation...$NC"

# Check if Python is installed
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "$RED Python is not installed. Please install Python 3.8 or higher.$NC"
    exit 1
}

# Check if pip is installed
if (-not (Get-Command pip -ErrorAction SilentlyContinue)) {
    Write-Host "$RED pip is not installed. Please install pip.$NC"
    exit 1
}

# Create and activate virtual environment
Execute-Command "python -m venv venv" "Creating virtual environment" "Failed to create virtual environment"
Execute-Command ".\venv\Scripts\Activate.ps1" "Activating virtual environment" "Failed to activate virtual environment"

# Upgrade pip
Execute-Command "python -m pip install --upgrade pip" "Upgrading pip" "Failed to upgrade pip"

# Install requirements
Execute-Command "pip install -r requirements.txt" "Installing requirements" "Failed to install requirements"

# Install additional required packages for URL scanning
Execute-Command "pip install python-whois aiohttp" "Installing URL scanning dependencies" "Failed to install URL scanning dependencies"

# Install Redis
Write-Host "$GREEN Setting up Redis...$NC"
$redisPath = "C:\Program Files\Redis\redis-server.exe"
if (-not (Test-Path $redisPath)) {
    Write-Host "$YELLOW Redis is not installed. Please download and install Redis for Windows.$NC"
    exit 1
}

# Create necessary directories
Execute-Command "mkdir -Force storage\screenshots" "Creating screenshot storage directory" "Failed to create screenshot storage directory"

# Create logs directory
Execute-Command "mkdir -Force logs" "Creating logs directory" "Failed to create logs directory"

# Make run.ps1 executable
Execute-Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force" "Making run script executable" "Failed to make run script executable"

# Run migrations
Execute-Command "python manage.py makemigrations" "Creating database migrations" "Failed to create database migrations"
Execute-Command "python manage.py migrate" "Applying database migrations" "Failed to apply database migrations"


Write-Host "$GREEN Installation completed successfully!$NC"
Write-Host "$GREEN Run '.\run.ps1' to start the application$NC"