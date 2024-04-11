#server.py
from socket import *
import sys


#set up server in a try block
try:
	#prepare a server socket
	serverSocket = socket(AF_INET, SOCK_STREAM)

	#set serverPort to user given port number from command line
	serverPort = int(sys.argv[1])

	#check if port number is valid
	if serverPort <= 1023 or serverPort > 65535:

		print("Error: Please enter a valid port number between 1024 - 65535, preferrably higher than 5000")

		#shutdown server
		sys.exit()

	#bind the socket to the localhost and serverPort
	serverSocket.bind(('', serverPort))

	#start listening for incoming requests, buffer up to 5 connections
	serverSocket.listen(5)

	#print to command prompt
	print("The server is ready to receive")

#check for KeyboardInterrupt and close socket before exiting
except KeyboardInterrupt:

	print("KeyboardInterrupt: Closing socket and shutting down server!") 
	serverSocket.close()
	sys.exit()

#check if the user passed an argument for port number
except IndexError as e:

	print("Error: Server could not be started, provide port number to be used for server")
	print(e)
	serverSocket.close()
	sys.exit()

#go into an infinite while loop that will wait for connections
while True:

	print("Ready to serve..")

	try:
		#new socket is created & a connection is set up with the client making the request
		connectionSocket, addr = serverSocket.accept()	

		#message contains the request from the client
		message = connectionSocket.recv(1024)
		
		print(f'recieved message: {message}')
		
		response = f'Server recieved your message: {message}'
		
		connectionSocket.send((response).encode())
		
		connectionSocket.close()


	#check for KeyboardInterrupt and close sockets before exiting
	except KeyboardInterrupt:

		print("KeyboardInterrupt: Closing sockets and shutting down server!") 

		#close socket to client
		connectionSocket.close()

		#close socket that server is listening on
		serverSocket.close()

		#shutdown server
		sys.exit()


	except FileNotFoundError as e:

		#print("The file indicated was not found in the server folder\nException thrown:", e)

		#create response to client
		response = 'HTTP/1.0 404 Not Found\r\n'

		#send response to client
		connectionSocket.send(response.encode())

		#close the connection to the client
		connectionSocket.close()



