# Colors
$GREEN = "[32m"
$YELLOW = "[33m"
$RED = "[31m"
$NC = "[0m"

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

    try {
        if ($DEBUG) {
            Invoke-Expression $command
        } else {
            Invoke-Expression $command > $null 2>&1
        }

        if ($LASTEXITCODE -ne 0) {
            throw "Command exited with code $LASTEXITCODE"
        }
    }
    catch {
        Write-Host "$RED$errorMessage$NC"
        Write-Host "$RED Error details: $_$NC"
        if ($DEBUG) {
            Write-Host "$RED Command was: $command$NC"
        }
        exit 1
    }
}

# Check if virtual environment is already activated
if (-not ($env:VIRTUAL_ENV)) {
    # Only activate if not already in a virtual environment
    if (Test-Path ".\venv\Scripts\Activate.ps1") {
        Execute-Command ".\venv\Scripts\Activate.ps1" "Activating virtual environment" "Failed to activate virtual environment"
    } else {
        Write-Host "$RED Virtual environment not found. Please create it using: python -m venv venv$NC"
        exit 1
    }
}

# Set up log file with timestamp
$LOG_DIR = "logs"
$LOG_FILE = "$LOG_DIR\app_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
if (-not (Test-Path $LOG_DIR)) {
    New-Item -ItemType Directory -Force -Path $LOG_DIR > $null
}
"" | Set-Content $LOG_FILE

# Function to handle cleanup on script exit
function Cleanup {
    if ($SERVER_PID) {
        Write-Host "$YELLOW Stopping server (PID: $SERVER_PID)...$NC"
        Stop-Process -Id $SERVER_PID -Force -ErrorAction SilentlyContinue
    }
}

# Set up trap for cleanup
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Cleanup }

# Check Redis server
$redisPath = "C:\Program Files\Redis\redis-server.exe"
if (-not (Test-Path $redisPath)) {
    Write-Host "$RED Redis server not found at: $redisPath$NC"
    Write-Host "$YELLOW Please ensure Redis is installed correctly$NC"
    exit 1
}

if (-not (Get-Process redis-server -ErrorAction SilentlyContinue)) {
    Write-Host "$YELLOW Redis server is not running. Starting Redis...$NC"
    try {
        Start-Process -FilePath $redisPath -NoNewWindow
        Start-Sleep -Seconds 2  # Give Redis time to start
        if (-not (Get-Process redis-server -ErrorAction SilentlyContinue)) {
            throw "Redis failed to start"
        }
    }
    catch {
        Write-Host "$RED Failed to start Redis service: $_$NC"
        exit 1
    }
}

# Start the server with output to both console and log file
Write-Host "$GREEN Starting GuardianVigil/IntelStack server...$NC"
Write-Host "$GREEN Log file: $LOG_FILE$NC"

try {
    if ($DEBUG) {
        $process = Start-Process -FilePath "python" -ArgumentList "manage.py runserver 0.0.0.0:8000" -NoNewWindow -PassThru
    } else {
        $process = Start-Process -FilePath "python" -ArgumentList "manage.py runserver 0.0.0.0:8000" -NoNewWindow -RedirectStandardOutput $LOG_FILE -PassThru
    }

    $SERVER_PID = $process.Id
    Write-Host "$GREEN Server started successfully with PID: $SERVER_PID$NC"

    # Wait for the server process to exit
    Wait-Process -Id $SERVER_PID
}
catch {
    Write-Host "$RED Failed to start server: $_$NC"
    Cleanup
    exit 1
}