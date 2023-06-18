import socket
import threading
import signal
import sys
import struct
import random
import argparse
from functools import partial

BUFF=1024
UDP_CHAT_PORT=3434
MDSCV_PORT=5454
MDSCV_ADDR='224.0.0.251'

mc_groups = dict()
clients = list()

def signal_handler(signal, frame, server_socket, clients, mdns_socket):
    '''
    Handles signal. Used only with *partial* package.

    Args:
        server_socket: Server socket on which actions are performed.
        clients: List of clients socket.
        mdns_socket: Multicast socket for managing multicast group.
    Returns:
        Exits program with code 0

    Example:
        >>> signal_handler_partial = partial(signal_handler, server_socket=server_socket, clients=clients, mdns_socket=mdns_sock)
        >>> signal.signal(signal.SIGINT, signal_handler_partial)
    '''
    print("Closing server...")

    # Closing mDNS UDP socket
    try:
        mdns_socket.shutdown(socket.SHUT_RD)
    except OSError:
        mdns_socket.close()
    
    # Closing tcp client sockets
    for client_socket in clients:
        client_socket.sendall("[SERVER_SHUTDOWN]".encode('utf-8'))
        client_socket.close()
        print(client_socket, "[Server shutdown]")

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    # Closing multicasts groups + TCP clients sockets (used for multicast managing)
    print("Deleting multicast groups...")
    for mc_group in mc_groups.keys():
        udp_sock.sendto("[SERVER_SHUTDOWN]".encode('utf-8'), (mc_group, UDP_CHAT_PORT))
        print(mc_group, "[Server shutdown]")
        
        for client_socket in mc_groups[mc_group][1]:
            try:
                client_socket.shutdown(socket.SHUT_RD)
            except Exception:
                pass
    
    udp_sock.close()
    server_socket.close()
    sys.exit(0)

def send_ip_address_mdns(mdns_sock, server_name):
    '''
    Sends IP addres when requested from client. Used with threading module.

    Args:
        mdns_sock: Multicast socket for listening for queries and answering them.
        server_name: Server name.
    Returns:
        None

    Example:
        >>> mdns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        >>> mdns_sock.bind(('', 8484))
        >>> mdns_thread = threading.Thread(target=send_ip_address_mdns, args=(mdns_sock,))
        >>> mdns_thread.start()
    '''
    while True:
        try:
            data, address = mdns_sock.recvfrom(BUFF)

            if address != None:
                print(f"mDNS query from: {str(address)}")
            
            if not data:
                break
            
            if data.decode('utf-8') == f"Hi, are you {server_name}?":               
                mdns_sock.sendto("Yup".encode(), address)

        except Exception as e:
            print(f"Error: {e}, MDNS")
            break

def manage_multicast_group(client_socket, client_address, mc_group):
    '''
    Manages multicast grops. The first client to connect is given secret code to share with the others.

    Args:
        client_socket: Client socket.
        client_address: Client address.
        mc_group: Multicast group client wants to join.
    Returns:
        None

    Example:
        >>> manage_multicast_group(client_socket, client_address, mc_group)
    '''
    if not mc_group in mc_groups.keys(): # First user - Adding multicast group, generating code
        secret_code = "".join([str(random.randint(0,9)) for _ in range(0,6)])
        mc_groups[mc_group] = [secret_code, []]
        mc_groups[mc_group][1].append(client_socket)
        client_socket.sendall(f"[NEW_GROUP]:{secret_code}".encode('utf-8'))
        print(client_address, f"[Client switched to multicast group: {mc_group}]")

    else: # The group exists - checking secret code
        client_socket.sendall("[CODE_REQUIRED]".encode('utf-8'))
        code = client_socket.recv(BUFF).decode('utf-8')

        if code == mc_groups[mc_group][0]:
            client_socket.sendall("[CORRECT_CODE]".encode('utf-8'))
            mc_groups[mc_group][1].append(client_socket)
            print(client_address, f"[Client switched to multicast group: {mc_group}]")
        else:
            client_socket.sendall("[WRONG_CODE]".encode('utf-8'))
            print(client_socket, "[Client shutdown]")
    
    while True: # Client shutdown
        try:
            data = client_socket.recv(BUFF).decode('utf-8')

            if data == '[CLIENT_SHUTDOWN]':
                print(client_address, "[Client shutdown]")
                mc_groups[mc_group][1].remove(client_socket)
                break
            
            if not data:
                break

        except Exception as e:
            print(f"Error: {e}")
            break
    
    client_socket.close()

def handle_client(client_socket, client_address):
    '''
    Handles and manages client connections.

    Args:
        client_socket (socket): The client socket object.
        client_address (tuple): The client address (IP, port).
    Returns:
        None

    Example:
        >>> handle_client(client_socket, client_address)

    Description:
        This function is responsible for handling and managing client connections.
        It continuously receives data from the client socket, processes the data,
        and sends it to other connected clients.

        If the received data starts with "[JOIN_MC_GROUP]", indicating a multicast request,
        the function removes the client socket from the list of clients, extracts the multicast
        group information, and calls the 'manage_multicast_group' function.

        If the received data is "[CLIENT_SHUTDOWN]", the function prints a message indicating
        that the client has shutdown, and breaks the loop to exit.
    '''
    while True:
        try:
            data = client_socket.recv(BUFF).decode('utf-8')
            if not data:
                break
            
            if data.startswith("[JOIN_MC_GROUP]"): # Multicast request
                clients.remove(client_socket)
                mc_group = data.split(":")[1]
                manage_multicast_group(client_socket, client_address, mc_group)
                break
                

            if data == '[CLIENT_SHUTDOWN]':
                print(client_address, "[Client shutdown]")
                break

            for client in clients:
                if client != client_socket:
                    client.sendall(data.encode('utf-8'))
        
        except Exception as e:
            print(f"Error: {e}")
            break
        
    client_socket.close()   
    try:
        clients.remove(client_socket)
    except ValueError: # Client removed during joining multicast group
        pass

def start_serv():
    '''
    Starts server. Creates TCP and UDP socket. Starts threads for client handlers.
    '''
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
    if args.mdns:
        mdns_thread = threading.Thread(target=send_ip_address_mdns, args=(mdns_sock, args.mdns))
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

            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address,))
            client_thread.start()
        except KeyboardInterrupt:
            break

    server_socket.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Choose method of starting server.")
    parser.add_argument('-m', '--mdns', help="Enable mDNS discovery [Name is optional]", nargs='?', action='store', const='chat_server')
    args = parser.parse_args()
    print(args)
    start_serv()