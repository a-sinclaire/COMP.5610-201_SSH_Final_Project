#client.py
from socket import *
import sys
	
#set up client in try block
try:	
	#get server name from command line input
	serverName = sys.argv[1]
	
	#get server port number from commandline
	serverPort = int(sys.argv[2])

	#check if port number is valid
	if serverPort < 0  or serverPort > 65535:

		print("Error: Please enter a valid port number between 0 - 65535")

		#shutdown client
		sys.exit()
		
	m = input()

	#prepare a client socket
	clientSocket = socket(AF_INET, SOCK_STREAM)

	#connect to the provided server name with the provided server port
	clientSocket.connect((serverName, serverPort))
	
	#send request to server
	clientSocket.send(m.encode())
	
	response = clientSocket.recv(1024).decode()

	print(response)

	#close the connection to the server
	clientSocket.close()

except IndexError as e:

	print("Error: Client could not be started, provide host, port number,request type, and filename in the command line\nException thrown:", e)
	
	#shutdown client
	sys.exit()

except FileNotFoundError as e:

	print("Error: The file indicated was not found in the client folder\nException thrown:", e)

	#shutdown client
	sys.exit()
	
except gaierror as e:

	print("Error: Enter a valid host name or IP address\nException thrown:", e)

	#shutdown client
	sys.exit()

except ConnectionRefusedError:

	print("Error: The connection was refused. Try again later\nException thrown:", e)

	#close the connection to the server
	clientSocket.close()	

	#shutdown client
	sys.exit()

except ValueError:
	
	print("Error: Enter a number between 0 and 65535 for the port number.")

	#shutdown client
	sys.exit()
	
