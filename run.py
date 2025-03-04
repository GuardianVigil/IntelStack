import os
import sys
import signal
import platform
import subprocess
from datetime import datetime

def print_colored(text, color):
    colors = {
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'RED': '\033[91m',
        'NC': '\033[0m'
    }
    print(f"{colors[color]}{text}{colors['NC']}")

class IntelStackServer:
    def __init__(self):
        self.debug = "--debug" in sys.argv
        self.is_windows = platform.system() == "Windows"
        
        # Use virtual environment python
        if self.is_windows:
            self.venv_python = os.path.join("venv", "Scripts", "python.exe")
        else:
            self.venv_python = os.path.join("venv", "bin", "python")
        
        self.process = None
        self.port = "8000"  # Default port

    def check_redis(self):
        if self.is_windows:
            redis_path = "C:\\Program Files\\Redis\\redis-server.exe"
            if not os.path.exists(redis_path):
                print_colored("Redis server not found!", "RED")
                return False
        else:
            try:
                subprocess.run(
                    ["systemctl", "is-active", "--quiet", "redis-server"]
                )
            except subprocess.CalledProcessError:
                print_colored("Starting Redis server...", "YELLOW")
                subprocess.run(["sudo", "systemctl", "start", "redis-server"])
        return True

    def start(self):
        if not self.check_redis():
            return

        print_colored("\n" + "="*50, "GREEN")
        print_colored("Starting IntelStack server...", "GREEN")
        base_url = f"http://localhost:{self.port}"
        print_colored(f"\nApplication URLs:", "GREEN")
        print_colored(f"  Main URL:  {base_url}", "GREEN")
        print_colored(f"  Admin URL: {base_url}/admin", "GREEN")
        print_colored("\nPress Ctrl+C to stop the server", "YELLOW")
        print_colored("="*50 + "\n", "GREEN")

        # Build command using venv python directly
        server_cmd = f'"{self.venv_python}" manage.py runserver 0.0.0.0:{self.port}'
        
        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = os.getcwd()
            
            if self.debug:
                # In debug mode, show output directly in console
                self.process = subprocess.Popen(
                    server_cmd,
                    shell=True,
                    env=env
                )
            else:
                # In normal mode, suppress output
                self.process = subprocess.Popen(
                    server_cmd,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env
                )
            
            self.process.wait()

        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            print_colored(f"Error starting server: {str(e)}", "RED")
            if self.debug:
                import traceback
                print_colored(traceback.format_exc(), "RED")
            self.stop()

    def stop(self):
        if self.process:
            print_colored("\nStopping IntelStack server...", "YELLOW")
            if self.is_windows:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(self.process.pid)])
            else:
                self.process.terminate()
            self.process.wait()
            print_colored("Server stopped", "GREEN")

if __name__ == "__main__":
    server = IntelStackServer()
    signal.signal(signal.SIGINT, lambda sig, frame: server.stop())
    server.start()
