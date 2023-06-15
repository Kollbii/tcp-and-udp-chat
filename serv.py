import socket
import threading
import signal
import sys
import struct
from functools import partial

BUFF=1024
MDSCV_PORT=5454
MDSCV_ADDR='224.0.0.251'
MDSCV_THREAD = True

clients = list()

def signal_handler(signal, frame, server_socket, clients, mdns_socket):
    print("Closing server...")

    try:
        mdns_socket.shutdown(socket.SHUT_RD)
    except OSError:
        mdns_socket.close()
    
    for client_socket in clients:
        client_socket.sendall("[Server shutdown]".encode('utf-8'))
        client_socket.close()
        print(client_socket, "[Server shutdown]")

    server_socket.close()
    sys.exit(0)

def send_ip_address_mdns(mdns_sock, server_name="chat_server"):
    while True:
        try:
            data, address = mdns_sock.recvfrom(BUFF)

            if address != None:
                print(f"mDNS query from: {str(address)}")
            
            if not data:
                break

            if data.decode() == f"Hi, are you {server_name}?":               
                mdns_sock.sendto("Yup".encode(), address)

        except Exception as e:
            print(f"Error: {e}, MDNS")
            break

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

    # Create a UDP socket (for mDNS)
    mdns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    mdns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mdns_sock.bind(('', MDSCV_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(MDSCV_ADDR), socket.INADDR_ANY)
    mdns_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Bind the socket to a specific address and port
    server_address = ('', 4001)
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(5)
    print("Server started. Waiting for connections...")

    # mDNS thread
    mdns_thread = threading.Thread(target=send_ip_address_mdns, args=(mdns_sock,))
    mdns_thread.start()

    # Signal handler for termination
    signal_handler_partial = partial(signal_handler, server_socket=server_socket, clients=clients, mdns_socket=mdns_sock)
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