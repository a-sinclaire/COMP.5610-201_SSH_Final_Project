# clientSSH.py
from socket import *
import sys
import ast
import CNSec_RSA as rsa
import CNSec_SHA2 as sha
import os

# get username
username = sys.argv[1]

while ',' in username:

    username = input("username can't have a ',' in it")

#get request type
requestType = sys.argv[3]

#verify request type is REG or NOR or SCP
if requestType != "REG" and requestType != "NOR" and requestType != "SCP":

    print("Error: Enter a valid request, REG, NOR, SCP")

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
print(f'Usernames in client_keys.txt: {list(usernames)}')


#check if username is already in client_keys.txt
if username in usernames:

    print(f'Username {username} found in client_keys.txt')
    publicKey_client = x[username]  # get public key from client file
    publicKey_client_e, publicKey_client_n = [int(_) for _ in publicKey_client.split(',')]
    privateKey_client = int(x[username + ',r'])  # TODO: same issue as below ('r' suffix)

else:

    print(f'Username {username} not found in client_keys.txt')
    # username not in client_keys.txt
    # generate a new public and private key for this user
    print('Generating new keys for this user...')
    d, e, n = rsa.generate_key()

    # add new username and key(s) to file
    x[username] = str(e) + "," + str(n)
    x[username + ",r"] = str(d)  # TODO: check to see if this has any issues if a user chooses the same username as another user, but with just an r on the end
    publicKey_client = x[username]
    publicKey_client_e, publicKey_client_n = [int(_) for _ in publicKey_client.split(',')]

    with open('client_keys.txt', "w") as f:
       	f.write(str(x))

    print(f"Username {username} has been added to client file")
    #print(f'Updated client_keys.txt: {x}')

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

    print(f'Requesting {serverName}\'s public key...')
    mlen = clientSocket.recv(4)
    mlen = int.from_bytes(mlen, 'big', signed=False)
    response = clientSocket.recv(mlen)

    publicKey_server = response.decode()
    publicKey_server_e, publicKey_server_n = [int(_) for _ in publicKey_server.split(',')]
    print(f'Received {serverName}\'s public key!')
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

    else:

        print(f'{serverName}\'s public key found in client_keys.txt')
        #server's username and pub key is saved in client_keys.txt
        #verify we have the correct public key for the server

        if x[serverName] == publicKey_server:

            print("Server's public key is verified.")

        else:

            print("The server's public key does not match!!!")
            # TODO: we need to decide how to handle this case,
            # either terminate connection or update the file to
            # have the new server key

            publicKey_server = x[serverName]

    # Register my username with the server
    # send username and key
    encrypted_username = rsa.encrypt(username, publicKey_server_e, publicKey_server_n)
    encrypted_publicKey_client = rsa.encrypt(publicKey_client, publicKey_server_e, publicKey_server_n)
    request2 = str(len(encrypted_username)) + ' ' + ' '.join(encrypted_username) + ' ' + str(len(encrypted_publicKey_client)) + ' ' + ' '.join(encrypted_publicKey_client)
    request2 = len(request2).to_bytes(4, 'big', signed=False) + request2.encode()
    clientSocket.send(request2)

    #get response from server
    mlen = clientSocket.recv(4)
    mlen = int.from_bytes(mlen, 'big', signed=False)
    response = clientSocket.recv(mlen).decode()
    response = response.split(' ')
    response = rsa.decrypt(response, privateKey_client, publicKey_client_n)
    print(f'SERVER: {response}')
	
    #####################################################################
    # Now that it is all set up and we are registered (or already were) #
    # We can process requests!                                            #
    #####################################################################

    if requestType == "NOR":
    
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

    if requestType == "SCP":

        #copy file
        filename = sys.argv[4]
        with open(filename, "r") as f:
            x = (f.read())

        #print(outputdata)

	#send file to server
	# send username and key
        encrypted_file = rsa.encrypt(x, publicKey_server_e, publicKey_server_n)
        encrypted_publicKey_client = rsa.encrypt(publicKey_client, publicKey_server_e, publicKey_server_n)
        file = str(len(encrypted_file)) + ' ' + ' '.join(encrypted_file) + ' ' + str(len(encrypted_publicKey_client)) + ' ' + ' '.join(encrypted_publicKey_client)
        file = len(file).to_bytes(4, 'big', signed=False) + file.encode()
        clientSocket.send(file)

	#receive response from server
        mlen = clientSocket.recv(4)
        mlen = int.from_bytes(mlen, 'big', signed=False)
        response = clientSocket.recv(mlen).decode()
        response = rsa.decrypt(response.split(' '), privateKey_client, publicKey_client_n)
        print(f'SERVER: {response}')

	#close the connection to the server
        clientSocket.close()

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
