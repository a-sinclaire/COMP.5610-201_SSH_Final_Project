#server.py
from socket import *
import sys
import ast

#set up server in a try block
try:
	#prepare a server socket
	serverSocket = socket(AF_INET, SOCK_STREAM)

	#set serverPort to user given port number from command line
	serverPort = 22

	#bind the socket to the localhost and serverPort
	serverSocket.bind(('', serverPort))

	#start listening for incoming requests, buffer up to 5 connections
	serverSocket.listen(5)

	#print to command prompt
	print("The server is ready to receive")

	#server public key
	serverKey = "456789"

#check for KeyboardInterrupt and close socket before exiting
except KeyboardInterrupt:

	print("KeyboardInterrupt: Closing socket and shutting down server!") 
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

		#check if  registration request, send publicKey
		if message.decode() == "REG":

			response = serverKey
			connectionSocket.send((response).encode())

			#receive file data
			data = connectionSocket.recv(2048)

			#datalist contain a list of the data from the request
			datalist = data.decode().split()
	
			#get the username
			username = datalist[0]

			#get the key
			publicKey = datalist[1]

			#check if nothing is received, break
			#if not data:
				

			#open file in read mode, and get a list of usernames in the system
			f = open('keys.txt', "r")
			x = ast.literal_eval(f.read())
			usernames = x.keys()
			print(usernames)
			print(x)
				
			#check if username is already in the file.
			if username in usernames:

				if x[username] == publicKey:
				
					print("User has registered before.")
					response = 'User is already registered.\r\n\r\n'
				else:
							
					print("Username is not available")
					response = 'Username is already in use by another user'
			else:

				print("The username will be added to our system")
						
				#close file that was opened in read mode
				f.close()
						
				#Add new username and key to file
				x[username] = publicKey
				print(x)
				f = open('keys.txt', "w")
				f.write(str(x))
				f.close()
				response = 'The user have been registered\r\n\r\n'

			#send response
			connectionSocket.send((response).encode())

			#close the connection socket
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
