#client.py
from socket import *
import sys
import ast
import CNSec_RSA as rsa

#get public key from client file
	
#get username
username = sys.argv[3]

#get public key
#open file in read mode, and get a list of usernames in the system
f = open('client_keys.txt', "r")
x = ast.literal_eval(f.read())
	

usernames = x.keys()
print(x)
			
#check if username is already in the file.
if username in usernames:

	publicKey_client = x[username]

else:	
		
	print("Username has been added to client file")
	d, e, n = rsa.generate_key()
	

	#close file that was opened in read mode
	f.close()
						
	#Add new username and key to file
	x[username] = str(e) + "," + str(n)
	x[username + "r"] = str(d)
	publicKey_client = x[username]
	print(x)
	f = open('client_keys.txt', "w")
	f.write(str(x))
	f.close()
	
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

	#prepare a client socket
	clientSocket = socket(AF_INET, SOCK_STREAM)

	#connect to the provided server name with the provided server port
	clientSocket.connect((serverName, serverPort))
	
	#send request to server
	#clientSocket.send(m.encode())

	#create request to server
	request = requestType
	request2 = username + " " + publicKey_client
	
	#send request to server
	clientSocket.send(request.encode())

	#check if request type is GET
	if requestType == "REG":

		#get servers public key and then send username and client key
		try:
			#get response from server
			response = clientSocket.recv(1024)
			publicKey_server = response.decode()
			print(publicKey_server)

			#get public key
		
			#open file in read mode, and get a list of usernames in the system
			f = open('client_keys.txt', "r")
			x = ast.literal_eval(f.read())
			usernames = x.keys()
			
			#check if username is already in the file.
			if serverName not in usernames:

				x[serverName] = publicKey_server

				#close file that was opened in read mode
				f.close()
				print(x)
				f = open('client_keys.txt', "w")
				f.write(str(x))
				f.close() 

			else:	
		
				#verify we have the correct public key for the server
				if x[serverName] == publicKey_server:

					print("servers public key is verified")
				else:
			
					print("The server's public key does not match")

				# we need to decide how to handle this case, either terminate connection or update the file to have the new server key

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
