#client.py
from socket import *
import sys
	
#set up client in try block
try:	
	#get server name from command line input
	serverName = sys.argv[1]
	
	#get server port number from commandline
	serverPort = 22
		
	#m = input()

	#get request type
	requestType = sys.argv[2]

	#verify request type is REG or NOR
	if requestType != "REG" and requestType != "NOR":

		print("Error: Enter a valid request, REG or NOR")

		#shutdown client
		sys.exit()

	#get username
	username = sys.argv[3]

	#get public key
	publicKey = "123456"

	#prepare a client socket
	clientSocket = socket(AF_INET, SOCK_STREAM)

	#connect to the provided server name with the provided server port
	clientSocket.connect((serverName, serverPort))
	
	#send request to server
	#clientSocket.send(m.encode())

	#create request to server
	request = requestType
	request2 = username + " " + publicKey
	
	#send request to server
	clientSocket.send(request.encode())

	#check if request type is GET
	if requestType == "REG":

		#get servers public key and then send username and client key
		try:
			#get response from server
			response = clientSocket.recv(1024)
			print(response.decode())

		#check for exceptions thrown
		except IOError as e:
			print("Exception thrown: \r\n", e)

		#send username and key
		clientSocket.send(request2.encode())
			
		try:
			#get response from server
			response = clientSocket.recv(1024)

			print(response.decode())

		#check for exceptions thrown
		except IOError as e:
			print("Exception thrown: \r\n", e)	
	
		#close socket once all data is received from server
		clientSocket.close()
	
		#shutdown client
		sys.exit()

except IndexError as e:

	print("Error: Client could not be started, provide host, request type, and username  in the command line\nException thrown:", e)
	
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
