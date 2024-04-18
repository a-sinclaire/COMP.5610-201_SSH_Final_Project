# clientSSH.py
from socket import *
import sys
import ast
import CNSec_RSA as rsa
import os
	
# get username
username = sys.argv[2]

# get client public key
directory = os.path.dirname(os.path.abspath(__file__))
client_keys_filename = os.path.join(directory, 'client_keys.txt')
# create the file to store client keys if it does not exist
if not os.path.exists(client_keys_filename):
    with open(client_keys_filename, 'w') as f:
        f.write('{}')
# open file in read mode, and get a list of usernames and corresponding keys in the system
with open(client_keys_filename, "r") as f:
	x = ast.literal_eval(f.read())
	
# list of just usernames saved in client keys file
usernames = x.keys()
print(f'Usernames in client_keys.txt: {list(usernames)}')


#check if username is already in client_keys.txt
if username in usernames:
	print(f'Username {username} found in client_keys.txt')
	publicKey_client = x[username]  # get public key from client file
else:
	print(f'Username {username} not found in client_keys.txt')
	# username not in client_keys.txt
	# generate a new public and private key for this user
	print('Generating new keys for this user...')
	d, e, n = rsa.generate_key()
						
	# add new username and key(s) to file
	x[username] = str(e) + "," + str(n)
	x[username + "r"] = str(d)  # TODO: check to see if this has any issues if a user chooses the same username as another user, but with just an r on the end
	publicKey_client = x[username]
	with open('client_keys.txt', "w") as f:
		f.write(str(x))
	print(f"Username {username} has been added to client file")
	#print(f'Updated client_keys.txt: {x}')
	
# set up client in try block
try:	
	# get server name from command line input
	serverName = sys.argv[1]
	
	# server port 22 bc 22 is reserved for ssh
	serverPort = 22

	#prepare a client socket
	clientSocket = socket(AF_INET, SOCK_STREAM)

	#connect to the provided server name with the provided server port
	clientSocket.connect((serverName, serverPort))

	# Attempt to register myself with the server
	request = 'REG'
	request2 = username + " " + publicKey_client
	
	
	# Get server's public key
	clientSocket.send(request.encode())  # requesting server pub key
	try:
		print(f'Requesting {serverName}\'s public key...')
		response = clientSocket.recv(1024)
		publicKey_server = response.decode()
		print(f'Recieved {serverName}\'s public key!')
		# print(f'Server public key: {publicKey_server}')
	
		# read in saved usernames and keys from client_keys.tct
		with open('client_keys.txt', "r") as f:
			x = ast.literal_eval(f.read())
		usernames = x.keys()
		
		#check if server's username is already in the file.
		if serverName not in usernames:
			print(f'{serverName}\'s public key not saved in client_keys.txt')
			# server's username and pub key isn't saved in client_keys.txt
			x[serverName] = publicKey_server

			print(f'Adding server public key for {serverName} to client_keys.txt')
			with open('client_keys.txt', "w") as f:
				f.write(str(x))
			#print(f'Updated client_keys.txt: {x}')
		else:
			print(f'{serverName}\'s public key found in client_keys.txt')
			# server's username and pub key is saved in client_keys.txt
			# verify we have the correct public key for the server
			if x[serverName] == publicKey_server:
				print("Server's public key is verified.")
			else:
				print("The server's public key does not match!!!")
				# TODO: we need to decide how to handle this case,
				# either terminate connection or update the file to
				# have the new server key
	except IOError as e:
		print("Exception thrown: \r\n", e)


	# Register my username with the server
	# send username and key
	clientSocket.send(request2.encode())  # registering with server
	try:
		#get response from server
		response = clientSocket.recv(1024)
		print(f'SERVER: {response.decode()}')
	#check for exceptions thrown
	except IOError as e:
		print("Exception thrown: \r\n", e)	

	
	#####################################################################
	# Now that it is all set up and we are registered (or already were) #
	# We can process requests!											#
	#####################################################################
	print()
	while True:
		print('> ', end='')
		m = input()

		# TODO: encrypt m and also send SHA fingerprint
		norRequest = username + ' ' + publicKey_client + ' ' + m
		clientSocket.send(norRequest.encode())
		
		#get response from server
		response = clientSocket.recv(1024)
		print(f'SERVER: {response.decode()}')
		
		if m == 'exit':
			break
	

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
