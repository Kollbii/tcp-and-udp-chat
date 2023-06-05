import socket
import threading
import signal
import sys
from functools import partial

BUFF=1024

clients = list()

def signal_handler(signal, frame, server_socket, clients):
    print("Closing server...")

    for client_socket in clients:
        client_socket.sendall("[Server shutdown]".encode('utf-8'))
        client_socket.close()
        print(client_socket, "[Server shutdown]")

    server_socket.close()
    sys.exit(0)

def handle_client(client_socket):
    while True:
        try:
            data = client_socket.recv(BUFF).decode('utf-8')
            if not data:
                break

            if data == 'Bye':
                print(client_socket, "[Client shutdown]")
                break

            for client in clients:
                if client != client_socket:
                    client.sendall(data.encode('utf-8'))
        except Exception as e:
            print(f"Error: {e}")
            break
        
    client_socket.close()
    clients.remove(client_socket)

def start_serv():
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Create a UDP socket
    # PLACEHOLDER

    # Bind the socket to a specific address and port
    server_address = ('', 4001)
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(5)
    print("Server started. Waiting for connections...")

    # Signal handler for termination
    signal_handler_partial = partial(signal_handler, server_socket=server_socket, clients=clients)
    signal.signal(signal.SIGINT, signal_handler_partial)

    while True:
        try:
            # Accept a new connection
            client_socket, client_address = server_socket.accept()
            print(f"New connection from {client_address}")

            clients.append(client_socket)

            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
        except KeyboardInterrupt:
            break

    server_socket.close()

#TODO make options 
if __name__ == '__main__':
    start_serv()