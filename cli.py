import socket
import threading
import signal
import sys
import struct
import ipaddress
from functools import partial
import argparse

BUFF=1024
UDP_CHAT_PORT=3434
MDNS_PORT=5454
MDNS_ADDR='224.0.0.251'

def signal_handler(signal, frame, client_socket, udp_client_socket):
    print("Closing client...")

    try:
        udp_client_socket.shutdown(socket.SHUT_RD)
    except OSError:
        udp_client_socket.close()

    try:
        client_socket.sendall('[CLIENT_SHUTDOWN]'.encode('utf-8'))
    except OSError as e:
        if e.errno == 9:
            sys.exit()
        else:
            print(f"Error: {e}")

    client_socket.close()
    sys.exit(0)

def get_server_ip_mdns(server_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    sock.sendto(f"Hi, are you {server_name}?".encode('utf-8'), (MDNS_ADDR, MDNS_PORT))

    sock.settimeout(10)
    ip_address = None

    while True:
        try:
            data, addr = sock.recvfrom(BUFF)
        except socket.timeout:
            print("Failed to find the server via mulitcast")
            break
        else:
            if data.decode('utf-8') == 'Yup':
                ip_address = addr[0]
                break

    sock.close()
    return ip_address

def get_ip_address(domain_name):
    try:
        result = socket.getaddrinfo(domain_name, None, socket.AF_INET)        
        ip_address = result[0][4][0]
        
        return ip_address
    except socket.gaierror:
        print("Failed to resolve IP address for the domain:", domain_name)
        return None

def join_multicast_group(client_socket):
    success = 0
    msg = "[JOIN_MC_GROUP]:" + args.multicast_group
    client_socket.sendall(msg.encode('utf-8'))
    
    resp = client_socket.recv(BUFF).decode('utf-8')
    if resp.startswith("[NEW_GROUP]"):
        print(f"A new private group chat has been created! The secret code to join this group is: {resp.split(':')[1]}")
        success = 1
    
    elif resp.startswith("[CODE_REQUIRED]"):
        secret_code = input("A secret code to join this group is required: ")
        client_socket.sendall(secret_code.encode('utf-8'))

        resp2 =  client_socket.recv(BUFF).decode('utf-8')

        if resp2 == "[CORRECT_CODE]":
            print("You have successfully joined the private group chat")
            success = 1
        else:
            print("Wrong secret code! Quitting...")
    
    return success

def udp_chat(udp_client_socket, multicast_group, username):
    udp_client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    udp_client_socket.bind(('', UDP_CHAT_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(multicast_group), socket.INADDR_ANY)
    udp_client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Start a thread to receive messages from the server
    receive_thread = threading.Thread(target=receive_multicast_msg, args=(udp_client_socket, username))
    receive_thread.start()

    while True:
        try:
            # Read user input
            message = input()
            message = f"{username}: " + message

            # Becasue input() is blocking function it willl always return bad FD after closed connection. It may be overcome by using input() in threading functions.
            if udp_client_socket.fileno() < 0:
                break

            # Send the message to the server
            udp_client_socket.sendto(message.encode('utf-8'), (multicast_group, UDP_CHAT_PORT))
        except KeyboardInterrupt:
            break
    
    # Close the client socket
    udp_client_socket.close()

def receive_multicast_msg(udp_client_socket, username):
    prev = ""
    while True:
        try:
            data, addr = udp_client_socket.recvfrom(BUFF)
            data = data.decode('utf-8')
            
            if not data:
                break
            
            if data == '[SERVER_SHUTDOWN]':
                print(data, "\nPress enter to close the program")
                break
            
            if data.split(":")[0] != username and data != prev:  # Simple self-duplicates and other duplicates prevention
                print(data)
                prev = data

        except Exception as e:
            print(f"Error: {e}")
            break

    udp_client_socket.close()
    sys.exit(0)


def tcp_chat(client_socket, username):
    # Start a thread to receive messages from the server
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    while True:
        try:
            # Read user input
            message = input()
            message = f"{username}: " + message

            # Becasue input() is blocking function it willl always return bad FD after closed connection. It may be overcome by using input() in threading functions.
            if client_socket.fileno() < 0:
                break

            # Send the message to the server
            client_socket.sendall(message.encode('utf-8'))
        except KeyboardInterrupt:
            break
    
    # Close the client socket
    client_socket.close()

def receive_messages(client_socket):
    while True:
        try:
            data = client_socket.recv(BUFF).decode('utf-8')
            if not data:
                break
            
            if data == '[SERVER_SHUTDOWN]':
                print(data, "\nPress enter to close the program")
                break

            print(data)
        except Exception as e:
            print(f"Error: {e}")
            break

    client_socket.close()
    sys.exit(0)

def start_cli(args):
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Create a UDP socket
    udp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Find server using DNS api
    if args.dns:
        ip_address = get_ip_address(str(args.dns))
        if ip_address == None:
            sys.exit(0)
        print("Got IP from getaddrinfo():", ip_address)
    
    #Find server using multicast (custom mDNS)
    elif args.mdns:
        ip_address = get_server_ip_mdns(args.mdns)
        if ip_address == None:
            sys.exit(0)
        print("Got IP from mDNS:", ip_address)
    else:
        ip_address = args.addr
    
    username = input("Your username: ")

    # Connect to the server 
    server_address = (ip_address, 4001)
    client_socket.connect(server_address)
    print("Connected to the server.")
    
    # Signal handler for termination
    signal_handler_partial = partial(signal_handler, client_socket=client_socket, udp_client_socket=udp_client_socket)
    signal.signal(signal.SIGINT, signal_handler_partial)

    # Joining multicast group
    if args.multicast_group:
        if not ipaddress.ip_address(args.multicast_group).is_multicast:
            print("Invalid multicast address")
            sys.exit(0)
        
        if join_multicast_group(client_socket):
            udp_chat(udp_client_socket, args.multicast_group, username)
        
    else:
        tcp_chat(client_socket, username)
    
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Choose method of connection and sending messages.")
    parser.add_argument('-a','--addr', help="Server IP address.")
    parser.add_argument('-d','--dns', help="Use DNS query to find server's IP address.")
    parser.add_argument('-m', '--mdns', help="Use custom mDNS to find server's IP address [Name is optional, only if server requires]", nargs='?', action='store', const='chat_server')
    parser.add_argument('-g', '--multicast_group', help="Join a selected multicast group.")
    args = parser.parse_args()
    print(args)
    start_cli(args)