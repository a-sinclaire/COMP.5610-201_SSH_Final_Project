# clientSSH.py
from socket import *
import sys
import ast
import CNSec_RSA as rsa
import CNSec_SHA2 as sha
import os

# get username
username = sys.argv[1]

while ',' in username or len(username) < 6:

    username = input("Please enter a username with a length greater than 5 and no comma in it:")

#get request type
requestType = sys.argv[3]

#verify request type is NOR or SCP or HELP
if requestType != "NOR" and requestType != "SCP" and requestType != "HELP":

    print("Error: Enter a valid request, REG, NOR, SCP, HELP")

    #shutdown client
    sys.exit()

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

#check if username is already in client_keys.txt
if username in usernames:

    publicKey_client = x[username]  # get public key from client file
    publicKey_client_e, publicKey_client_n = [int(_) for _ in publicKey_client.split(',')]
    privateKey_client = int(x[username + ',r'])

else:

    # username not in client_keys.txt
    # generate a new public and private key for this user
    print('Generating new keys for this user...')
    d, e, n = rsa.generate_key()

    # add new username and key(s) to file
    x[username] = str(e) + "," + str(n)
    x[username + ",r"] = str(d)
    publicKey_client = x[username]
    publicKey_client_e, publicKey_client_n = [int(_) for _ in publicKey_client.split(',')]
    privateKey_client = int(x[username + ',r'])

    with open('client_keys.txt', "w") as f:
       	f.write(str(x))

    print(f"Username {username} has been added to client file")

# set up client in try block
try:
    # get server name from command line input
    serverName = sys.argv[2]

    # server port 22 bc 22 is reserved for ssh
    serverPort = 22

    #prepare a client socket
    clientSocket = socket(AF_INET, SOCK_STREAM)

    #connect to the provided server name with the provided server port
    clientSocket.connect((serverName, serverPort))

    # Get request type
    request = requestType
    request = len(request).to_bytes(4, 'big', signed=False) + request.encode()

    # Get server's public key
    clientSocket.send(request)  # requesting server pub key

    mlen = clientSocket.recv(4)
    mlen = int.from_bytes(mlen, 'big', signed=False)
    response = clientSocket.recv(mlen)

    publicKey_server = response.decode()
    publicKey_server_e, publicKey_server_n = [int(_) for _ in publicKey_server.split(',')]

    # read in saved usernames and keys from client_keys.tct
    with open('client_keys.txt', "r") as f:
        x = ast.literal_eval(f.read())

    usernames = x.keys()

    #check if server's username is already in the file.
    if serverName not in usernames:

        print(f'{serverName}\'s public key not saved in client_keys.txt')
        x[serverName] = publicKey_server

        print(f'Adding server public key for {serverName} to client_keys.txt')
        with open('client_keys.txt', "w") as f:
            f.write(str(x))

    else:

        #server's username and pub key is saved in client_keys.txt
        #verify we have the correct public key for the server

        if x[serverName] == publicKey_server:

            print("Server's public key is verified.")

        else:

            print("The server's public key does not match!!! Closing connection")

            #close socket if server's key does not match
            clientSocket.close()

            #shutdown client
            sys.exit()

    # Register my username with the server
    # send username, key, and file destination if SCP
    encrypted_username = rsa.encrypt(username, publicKey_server_e, publicKey_server_n)
    encrypted_publicKey_client = rsa.encrypt(publicKey_client, publicKey_server_e, publicKey_server_n)
    request2 = str(len(encrypted_username)) + ' ' + ' '.join(encrypted_username) + ' ' + str(len(encrypted_publicKey_client)) + ' ' + ' '.join(encrypted_publicKey_client)

    if requestType == 'SCP':

        try:

            filename = sys.argv[4]
            destination = sys.argv[5]
            encrypted_destination = rsa.encrypt(destination, publicKey_server_e, publicKey_server_n)
            request2 += ' ' + str(len(encrypted_destination)) + ' ' + ' '.join(encrypted_destination)

        except Exception as e:

                print("Provide a filename/path for the file, and the destination") 
                print("Exception thrown: \r\n", e)

                #close socket to client
                clientSocket.close()

    request2 = len(request2).to_bytes(4, 'big', signed=False) + request2.encode()
    clientSocket.send(request2)

    #get response from server
    mlen = clientSocket.recv(4)
    mlen = int.from_bytes(mlen, 'big', signed=False)
    response = clientSocket.recv(mlen).decode()
    response = response.split(' ')
    response = rsa.decrypt(response, privateKey_client, publicKey_client_n)
	
    #####################################################################
    # Now that it is all set up and we are registered (or already were) #
    # We can process requests!                                            #
    #####################################################################

    if requestType == 'NOR':
    
        while True:

	    #get current working directory from server
            mlen = clientSocket.recv(4)
            mlen = int.from_bytes(mlen, 'big', signed=False)
            response = clientSocket.recv(mlen).decode()
            response = response.split(' ')
            response = rsa.decrypt(response, privateKey_client, publicKey_client_n)
            m = input(f'({username}@{serverName}){response} $>')

            # Encrypt the message, encrypt the hash of the message, and send these both
            encmhash = rsa.encrypt(sha.sha256(m), privateKey_client, publicKey_client_n)
            menc = rsa.encrypt(m, publicKey_server_e, publicKey_server_n)
            norRequest = str(len(menc)) + ' ' + ' '.join(menc) + ' ' + str(len(encmhash)) + ' ' + ' '.join(encmhash)
            norRequest = len(norRequest).to_bytes(4, 'big', signed=False) + norRequest.encode()
            clientSocket.send(norRequest)

            if m == 'exit':
                break

            #get response from server
            mlen = clientSocket.recv(4)
            mlen = int.from_bytes(mlen, 'big', signed=False)
            response = clientSocket.recv(mlen).decode()
            response = rsa.decrypt(response.split(' '), privateKey_client, publicKey_client_n)
            print(f'SERVER: {response}')

        #close socket once all data is received from server
        clientSocket.close()

        #shutdown client
        sys.exit()

    elif requestType == 'SCP':

        #copy file
        with open(filename, "r") as f:
            x = (f.read())        

        #receive response from server
        mlen = clientSocket.recv(4)
        mlen = int.from_bytes(mlen, 'big', signed=False)
        response = clientSocket.recv(mlen).decode()
        response = rsa.decrypt(response.split(' '), privateKey_client, publicKey_client_n)

	# Encrypt the message, encrypt the hash of the message, and send these both
        filehash = rsa.encrypt(sha.sha256(x), privateKey_client, publicKey_client_n)
        encrypted_file = rsa.encrypt(x, publicKey_server_e, publicKey_server_n)
        scpRequest = str(len(encrypted_file)) + ' ' + ' '.join(encrypted_file) + ' ' + str(len(filehash)) + ' ' + ' '.join(filehash)
        scpRequest = len(scpRequest).to_bytes(4, 'big', signed=False) + scpRequest.encode()
        clientSocket.send(scpRequest)

	#close the connection to the server
        clientSocket.close()

    elif requestType == "HELP":

        #receive response from server
        mlen = clientSocket.recv(4)
        mlen = int.from_bytes(mlen, 'big', signed=False)
        response = clientSocket.recv(mlen).decode()
        response = rsa.decrypt(response.split(' '), privateKey_client, publicKey_client_n)
        print(f'{response}') 

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
