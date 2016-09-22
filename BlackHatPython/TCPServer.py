import socket
import threading

bind_ip = "0.0.0.0"
bind_port = 1111 # my favorite port

# Because I always forget
# AF_INET says we'll use standard IPV4
# SOCK_STREAM just indicates that it's TCP instead of SOCK_DGRAM for UDP
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((bind_ip, bind_port))

# How many connections it will hold
server.listen(5)

# Client handler

def handle_client(client_socket):
    
    # Get the request
    request = client_socket.recv(1024)
    
    print "[+] Received: {}".format(request)
    
    # Send a packet
    client_socket.send("Oh Hi")
    
    client_socket.close()
    
while True:
    
    # When a new client connects, we pull some of its info
    client, addr = server.accept()
    
    print "[+] Accepted connection from: {}:{}".format(addr[0], addr[1])
    
    # Start the client thread to handle the data
    
    client_handler = threading.Thread(target = handle_client, args = (client, ))
    client_handler.start()
