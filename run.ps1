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

# Activate virtual environment
Execute-Command ".\venv\Scripts\Activate.ps1" "Activating virtual environment" "Failed to activate virtual environment"

# Set up log file with timestamp
$LOG_DIR = "logs"
$LOG_FILE = "$LOG_DIR\app_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
mkdir -Force $LOG_DIR > $null 2>&1
echo "" > $LOG_FILE

# Function to handle cleanup on script exit
function Cleanup {
    Write-Host "$YELLOW Stopping server...$NC"
    Stop-Process -Id $SERVER_PID -Force -ErrorAction SilentlyContinue
}

# Set up trap for cleanup
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Cleanup }

# Check Redis server
$redisPath = "C:\Program Files\Redis\redis-server.exe"
if (-not (Get-Process redis-server -ErrorAction SilentlyContinue)) {
    Write-Host "$YELLOW Redis server is not running. Starting Redis...$NC"
    Execute-Command "Start-Process -FilePath '$redisPath' -NoNewWindow" "Starting Redis service" "Failed to start Redis service"
}

# Start the server with output to both console and log file
Write-Host "$GREEN Starting GuardianVigil/IntelStack server...$NC"
Write-Host "$GREEN Log file: $LOG_FILE$NC"

if ($DEBUG) {
    $process = Start-Process -FilePath "python" -ArgumentList "manage.py runserver 0.0.0.0:8000" -NoNewWindow -PassThru
} else {
    $process = Start-Process -FilePath "python" -ArgumentList "manage.py runserver 0.0.0.0:8000" -NoNewWindow -RedirectStandardOutput $LOG_FILE -PassThru
}

$SERVER_PID = $process.Id

# Wait for the server process to exit
Wait-Process -Id $SERVER_PID