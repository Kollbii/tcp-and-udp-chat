import socket
import threading
import signal
import sys
from functools import partial
import argparse

BUFF=1024

def signal_handler(signal, frame, client_socket):
    print("Closing client...")

    try:
        client_socket.sendall('Bye'.encode('utf-8'))
    except OSError as e:
        if e.errno == 9:
            sys.exit()
        else:
            print(f"Error: {e}")

    client_socket.close()
    sys.exit(0)

def get_ip_address(domain_name):
    try:
        result = socket.getaddrinfo(domain_name, None, socket.AF_INET)
        
        ip_address = result[0][4][0]
        
        return ip_address
    except socket.gaierror:
        print("Failed to resolve IP address for the domain:", domain_name)
        return None

def receive_messages(client_socket):
    while True:
        try:
            data = client_socket.recv(BUFF).decode('utf-8')
            if not data:
                break
            
            if data == '[Server shutdown]':
                print(data)
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

    # Find server using DNS api
    if args.dns:
        ip_address = get_ip_address(str(args.dns))
        if ip_address == None:
            sys.exit(0)
        print("Got IP from getaddrinfo()", ip_address)
    else:
        ip_address = args.addr
        
    # Connect to the server 
    server_address = (ip_address, 4001)
    client_socket.connect(server_address)
    print("Connected to the server.")

    # Signal handler for termination
    signal_handler_partial = partial(signal_handler, client_socket=client_socket)
    signal.signal(signal.SIGINT, signal_handler_partial)

    # Start a thread to receive messages from the server
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    while True:
        try:
            # Read user input
            message = input()
            message = "UserName: " + message

            # Becasue input() is blocking function it willl always return bad FD after closed connection. It may be overcome by using input() in threading functions.
            if client_socket.fileno() < 0:
                break

            # Send the message to the server
            client_socket.sendall(message.encode('utf-8'))
        except KeyboardInterrupt:
            break
    
    # Close the client socket
    client_socket.close()
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Choose method of connection and sending messages")
    parser.add_argument('-a','--addr', help="Server IP address.")
    parser.add_argument('-d','--dns', help="Use DNS query to find IP address.")
    parser.add_argument('-m', '--multicast', help="Create UDP client socket and connect to multicas group.")
    args = parser.parse_args()
    print(args)
    start_cli(args)