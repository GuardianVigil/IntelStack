import os
import sys
import venv
import subprocess
import platform
import getpass

def print_colored(text, color):
    colors = {
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'RED': '\033[91m',
        'NC': '\033[0m'
    }
    print(f"{colors[color]}{text}{colors['NC']}")

def run_command(command, message):
    print_colored(f"{message}...", "GREEN")
    try:
        subprocess.run(command, check=True, shell=True, capture_output=not DEBUG)
        return True
    except subprocess.CalledProcessError as e:
        print_colored(f"Error: {e}", "RED")
        return False

def detect_django_settings():
    """Detect the correct Django settings module path"""
    possible_paths = [
        'Stack.settings',
        'IntelStack.settings',
        'config.settings',
        'core.settings'
    ]
    
    for path in possible_paths:
        module_parts = path.split('.')
        if os.path.exists(os.path.join(*module_parts) + '.py'):
            return path
    return None

def create_superuser(venv_python):
    # First detect the correct settings module
    settings_module = detect_django_settings()
    if not settings_module:
        print_colored("Could not detect Django settings module. Trying with manage.py...", "YELLOW")
        # Try using manage.py directly as fallback
        return create_superuser_with_manage_py(venv_python)

    while True:
        print_colored("Creating superuser for IntelStack admin...", "GREEN")
        username = input("Username: ")
        email = input("Email: ")
        password = getpass.getpass("Password: ")
        password2 = getpass.getpass("Confirm password: ")

        if password != password2:
            print_colored("Passwords do not match!", "RED")
            retry = input("Do you want to try again? (y/n): ").lower()
            if retry != 'y':
                print_colored("Superuser creation skipped.", "YELLOW")
                return False
            continue

        # Create superuser using manage.py directly
        cmd = f'"{venv_python}" manage.py createsuperuser --noinput --username "{username}" --email "{email}"'
        env = os.environ.copy()
        env['DJANGO_SUPERUSER_PASSWORD'] = password
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                env=env
            )
            
            if result.returncode == 0:
                print_colored("Superuser created successfully!", "GREEN")
                return True
            else:
                print_colored(f"Error: {result.stderr.strip()}", "RED")
                if DEBUG:
                    print_colored("Debug information:", "YELLOW")
                    print_colored(f"Return code: {result.returncode}", "YELLOW")
                    print_colored(f"Command output: {result.stdout}", "YELLOW")
                retry = input("Do you want to try again? (y/n): ").lower()
                if retry != 'y':
                    return False
                
        except Exception as e:
            print_colored(f"Error creating superuser: {str(e)}", "RED")
            if DEBUG:
                import traceback
                print_colored(traceback.format_exc(), "RED")
            retry = input("Do you want to try again? (y/n): ").lower()
            if retry != 'y':
                return False

def create_superuser_with_manage_py(venv_python):
    """Fallback method using manage.py createsuperuser command"""
    while True:
        print_colored("Creating superuser (using manage.py)...", "GREEN")
        username = input("Username: ")
        email = input("Email: ")
        password = getpass.getpass("Password: ")
        password2 = getpass.getpass("Confirm password: ")

        if password != password2:
            print_colored("Passwords do not match!", "RED")
            retry = input("Do you want to try again? (y/n): ").lower()
            if retry != 'y':
                return False
            continue

        cmd = f'"{venv_python}" manage.py createsuperuser --noinput'
        env = os.environ.copy()
        env['DJANGO_SUPERUSER_USERNAME'] = username
        env['DJANGO_SUPERUSER_EMAIL'] = email
        env['DJANGO_SUPERUSER_PASSWORD'] = password

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                env=env
            )
            
            if result.returncode == 0:
                print_colored("Superuser created successfully!", "GREEN")
                return True
            else:
                error_msg = result.stderr.strip() or result.stdout.strip()
                print_colored(f"Error: {error_msg}", "RED")
                retry = input("Do you want to try again? (y/n): ").lower()
                if retry != 'y':
                    return False
        except Exception as e:
            print_colored(f"Error: {str(e)}", "RED")
            retry = input("Do you want to try again? (y/n): ").lower()
            if retry != 'y':
                return False

def get_python_command():
    """Detect the correct Python command"""
    if IS_WINDOWS:
        # Try 'python' first, then 'py' on Windows
        try:
            subprocess.run(['python', '--version'], check=True, capture_output=True)
            return 'python'
        except (subprocess.CalledProcessError, FileNotFoundError):
            try:
                subprocess.run(['py', '--version'], check=True, capture_output=True)
                return 'py'
            except (subprocess.CalledProcessError, FileNotFoundError):
                print_colored("Python not found! Please install Python 3.8 or higher.", "RED")
                sys.exit(1)
    else:
        # Try 'python3' first, then 'python' on Unix
        try:
            subprocess.run(['python3', '--version'], check=True, capture_output=True)
            return 'python3'
        except (subprocess.CalledProcessError, FileNotFoundError):
            try:
                subprocess.run(['python', '--version'], check=True, capture_output=True)
                return 'python'
            except (subprocess.CalledProcessError, FileNotFoundError):
                print_colored("Python not found! Please install Python 3.8 or higher.", "RED")
                sys.exit(1)

if __name__ == "__main__":
    try:
        DEBUG = "--debug" in sys.argv
        IS_WINDOWS = platform.system() == "Windows"
        python_cmd = get_python_command()
        
        print_colored("Starting IntelStack installation...", "GREEN")
        print_colored(f"Using Python command: {python_cmd}", "GREEN")

        # Create directories
        os.makedirs("storage/screenshots", exist_ok=True)
        # Removed logs directory creation

        # Create and activate venv
        try:
            venv.create("venv", with_pip=True)
        except Exception as e:
            print_colored(f"Error creating virtual environment: {e}", "RED")
            sys.exit(1)
        
        # Set venv activation command based on platform
        if IS_WINDOWS:
            venv_python = os.path.join("venv", "Scripts", "python.exe")
            pip_cmd = f'"{venv_python}" -m pip install --upgrade pip'
            requirements_cmd = f'"{venv_python}" -m pip install -r requirements.txt'
        else:
            venv_python = os.path.join("venv", "bin", "python")
            pip_cmd = f'"{venv_python}" -m pip install --upgrade pip'
            requirements_cmd = f'"{venv_python}" -m pip install -r requirements.txt'

        # Install dependencies
        if not run_command(pip_cmd, "Upgrading pip"):
            print_colored("Failed to upgrade pip. Continuing with installation...", "YELLOW")

        if not run_command(requirements_cmd, "Installing requirements"):
            print_colored("Installation failed. Please check your internet connection and try again.", "RED")
            sys.exit(1)
        
        # Setup Redis
        if IS_WINDOWS:
            if not os.path.exists("C:\\Program Files\\Redis\\redis-server.exe"):
                print_colored("Please install Redis for Windows manually", "YELLOW")
        else:
            run_command("sudo apt-get update && sudo apt-get install -y redis-server", "Installing Redis")
            run_command("sudo systemctl start redis-server", "Starting Redis service")
            run_command("sudo systemctl enable redis-server", "Enabling Redis service")

        # Run migrations
        if not run_command(f'"{venv_python}" manage.py makemigrations', "Creating migrations"):
            print_colored("Migration creation failed. Please check your Django configuration.", "RED")
            sys.exit(1)

        if not run_command(f'"{venv_python}" manage.py migrate', "Applying migrations"):
            print_colored("Migration failed. Please check your database configuration.", "RED")
            sys.exit(1)
        
        # Create superuser with retry option
        superuser_created = create_superuser(venv_python)
        
        print_colored("Installation completed successfully!", "GREEN")
        if not superuser_created:
            print_colored("Note: Superuser was not created. You can create it later using 'python manage.py createsuperuser'", "YELLOW")
        print_colored("Run 'python run.py' to start the application", "GREEN")

    except KeyboardInterrupt:
        print_colored("\nInstallation interrupted by user.", "YELLOW")
        sys.exit(1)
    except Exception as e:
        print_colored(f"\nUnexpected error: {str(e)}", "RED")
        if DEBUG:
            raise
        sys.exit(1)
