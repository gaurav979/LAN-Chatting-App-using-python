# import socket library
import socket
import os
import tqdm
import threading

# Choose a port that is free
PORT = 5000

# An IPv4 address is obtained
# for the server.
SERVER = socket.gethostbyname(socket.gethostname())

# Address is stored as a tuple
ADDRESS = (SERVER, PORT)

# the format in which encoding
# and decoding will occur
FORMAT = "utf-8"

# Lists that will contains
# all the clients connected to
# the server and their names.
clients, names = [], []

# Create a new socket for
# the server
server = socket.socket(socket.AF_INET,
					socket.SOCK_STREAM)

# bind the address of the
# server to the socket
server.bind(ADDRESS)

# function to start the connection

####################


def receive():
    
    # device's IP address
    #SERVER_HOST = "0.0.0.0"
    #SERVER_PORT = 5000
    # receive 4096 bytes each time
    BUFFER_SIZE = 4096
    SEPARATOR = "<SEPARATOR>"
    # create the server socket
    # TCP socket
    s = socket.socket()
    # bind the socket to our local address
    s.bind((SERVER, PORT))
    # enabling our server to accept connections
    # 5 here is the number of unaccepted connections that
    # the system will allow before refusing new connections
    s.listen(5)
    print(f"[*] Listening as {SERVER}:{PORT}")
    # accept connection if there is any
    client_socket, address = s.accept() 
    # if below code is executed, that means the sender is connected
    print(f"[+] {address} is connected.")
    # receive the file infos
    # receive using client socket, not server socket
    received = client_socket.recv(BUFFER_SIZE).decode()
    filename, filesize = received.split(SEPARATOR)
    # remove absolute path if there is
    filename = os.path.basename(filename)
    # convert to integer
    filesize = int(filesize)
    # start receiving the file from the socket
    # and writing to the file stream
    progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "wb") as f:
        while True:
            # read 1024 bytes from the socket (receive)
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:    
                # nothing is received
                # file transmitting is done
                break
            # write to the file the bytes we just received
            f.write(bytes_read)
            # update the progress bar
            progress.update(len(bytes_read))

    # close the client socket
    client_socket.close()
    # close the server socket
    s.close()
    
    return






##############################
def startChat():

	print("server is working on " + SERVER)

	# listening for connections
	server.listen()
	#receive()

	while True:  
#######################################




#############################################
		#receive()
		# accept connections and returns
		# a new connection to the client
		# and the address bound to it
		conn, addr = server.accept()
		conn.send("NAME".encode(FORMAT))

		# 1024 represents the max amount
		# of data that can be received (bytes)
		name = conn.recv(1024).decode(FORMAT)

		# append the name and client
		# to the respective list
		names.append(name)
		clients.append(conn)

		print(f"Name is :{name}")

		# broadcast message
		broadcastMessage(f"{name} has joined the chat!".encode(FORMAT))

		conn.send('Connection successful!'.encode(FORMAT))

		# Start the handling thread
		thread = threading.Thread(target=handle,
								args=(conn, addr))
		thread.start()

		# no. of clients connected
		# to the server
		print(f"active connections {threading.activeCount()-1}")
        
  
  ###################################################################




  
  ############################################

# method to handle the
# incoming messages


def handle(conn, addr):

	print(f"new connection {addr}")
	connected = True

	while connected:
		# receive message
		message = conn.recv(1024)

		# broadcast message
		broadcastMessage(message)

	# close the connection
	conn.close()

# method for broadcasting
# messages to the each clients


def broadcastMessage(message):
	for client in clients:
		client.send(message)

####################


##################
# call the method to
# begin the communication
startChat()
