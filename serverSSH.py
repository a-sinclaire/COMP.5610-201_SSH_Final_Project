#server.py
from socket import *
import sys
import ast
import CNSec_RSA as rsa
import CNSec_SHA2 as sha
import os
import subprocess

#get public key
directory = os.path.dirname(os.path.abspath(__file__))
server_keys_filename = os.path.join(directory, 'server_keys.txt')

# create the file if it does not exist
if not os.path.exists(server_keys_filename):

    with open(server_keys_filename, 'w') as f:
        f.write('{}')

#open file in read mode, and get a list of usernames in the system
with open('server_keys.txt', "r") as f:
    x = ast.literal_eval(f.read())

usernames = x.keys()

#check if username is already in the file.
if "admin" in usernames:

    publicKey_server = x["admin"]
    publicKey_server_e, publicKey_server_n = [int(_) for _ in publicKey_server.split(',')]
    privateKey = int(x["admin,r"])    

else:

    print("The server now has its private and public keys")
    d, e, n = rsa.generate_key()

    #Add new username and key to file
    x["admin"] = str(e) + "," + str(n)
    x["admin,r"] = str(d)
    publicKey_server = x["admin"]
    publicKey_server_e, publicKey_server_n = [int(_) for _ in publicKey_server.split(',')]
    privateKey = int(x["admin,r"])
    print(x)
    with open('server_keys.txt', "w") as f:
       	f.write(str(x))

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
    #check for KeyboardInterrupt and close socket before exiting

except KeyboardInterrupt:

    print("KeyboardInterrupt: Closing socket and shutting down server!")
    serverSocket.close()
    sys.exit()

# go into an infinite while loop that will wait for connections
while True:

    print("Ready to serve..")

    try:
        # new socket is created & a connection is set up with the client making the request
        connectionSocket, addr = serverSocket.accept()

        #message contains the request from the client
        mlen = connectionSocket.recv(4)
        mlen = int.from_bytes(mlen, 'big', signed=False)
        requestType = connectionSocket.recv(mlen).decode()

        #check if user had registered before, send publicKeyr
        response = publicKey_server
        response = len(response).to_bytes(4, 'big', signed=False) + response.encode()
        connectionSocket.send(response)

        #receive file data
        mlen = connectionSocket.recv(4)
        mlen = int.from_bytes(mlen, 'big', signed=False)
        data = connectionSocket.recv(mlen)

        #datalist contain a list of the data from the request
        datalist = data.decode().split(' ')
        msg_index = 0  # Indexer used to check how much of the message we've processed so far

        #get the username
        number_of_username_chunks = int(datalist[msg_index])
        msg_index += 1
        username = rsa.decrypt(datalist[msg_index:msg_index+number_of_username_chunks], privateKey, publicKey_server_n)
        msg_index += number_of_username_chunks

        #get the key
        number_of_key_chunks = int(datalist[msg_index])
        msg_index += 1
        publicKey_client = rsa.decrypt(datalist[msg_index:msg_index+number_of_key_chunks], privateKey, publicKey_server_n)
        msg_index += number_of_key_chunks

        #open file in read mode, and get a list of usernames in the system
        with open('server_keys.txt', "r") as f:
            x = ast.literal_eval(f.read())

        usernames = x.keys()
#print(f'usernames on server: {usernames}')
        #print(f'keys on server: {x}')

        #check if username is already in the file.
        if username in usernames:

            if x[username] == publicKey_client:
	
                print(f"User {username} has registered before.")
                response = f'User {username} has registered before.'

            else:

                print(f"Username {username} is not available")
                response = f'Username {username} is not available'
                response = ' '.join(rsa.encrypt(response, publicKey_client_e, publicKey_client_n))
                response = len(response).to_bytes(4, 'big', signed=False) + response.encode()
                connectionSocket.send(response)
                #connectionSocket.close()

        else:
                	
            print(f"The username {username} will be added to our system")

            #Add new username and key to file
            x[username] = publicKey_client
#print(f'updated keys on server: {x}')
            with open('server_keys.txt', "w") as f:
                f.write(str(x))

            response = f'The user {username} has been registered\r\n\r\n'

        publicKey_client_e, publicKey_client_n = [int(_) for _ in publicKey_client.split(',')]
        #send response
        response = ' '.join(rsa.encrypt(response, publicKey_client_e, publicKey_client_n))
        response = len(response).to_bytes(4, 'big', signed=False) + response.encode()
        connectionSocket.send(response)

        try:

            if requestType == "NOR":

                while True:

                    response = f'{os.getcwd()}'
                    response = ' '.join(rsa.encrypt(response, publicKey_client_e, publicKey_client_n))
                    response = len(response).to_bytes(4, 'big', signed=False) + response.encode()
                    connectionSocket.send(response)

                    mlen = connectionSocket.recv(4)
                    mlen = int.from_bytes(mlen, 'big', signed=False)
                    m = connectionSocket.recv(mlen).decode().split()
                    msg_index = 0  # Indexer used to check how much of the message we've processed so far

                    # Decrypt the message
                    number_of_content_chunks = int(m[msg_index])
                    msg_index += 1
                    message = rsa.decrypt(m[msg_index:msg_index + number_of_content_chunks], privateKey, publicKey_server_n)
                    msg_index += number_of_content_chunks

                    # Decrypt the hash of the message
                    number_of_hash_chunks = int(m[msg_index])
                    msg_index += 1
                    message_hash = rsa.decrypt(m[msg_index:msg_index + number_of_key_chunks], publicKey_client_e, publicKey_client_n)
                    msg_index += number_of_hash_chunks

                    if sha.sha256(message) != message_hash:

                        output = "Invalid hash fingerprint -- authentication failed"

                    elif message == 'exit':

                        break

                    elif message.split()[0] == 'cd':

                        if len(message.split()) > 1:

                            os.chdir(' '.join(message.split()[1:]))

                        output = ' '

                    else :

                        output = subprocess.getoutput(message)

                    output = ' '.join(rsa.encrypt(output, publicKey_client_e, publicKey_client_n))
                    output = len(output).to_bytes(4, 'big', signed=False) + output.encode()
                    connectionSocket.send(output)

#print(f'received normal message: {message}')

                connectionSocket.close()
            

            elif requestType == "SCP":

	        #create response to client
                response = 'File Copied'

	        #send response to client
                response = 'File Copied'
                response = ' '.join(rsa.encrypt(response, publicKey_client_e, publicKey_client_n))
                response = len(response).to_bytes(4, 'big', signed=False) + response.encode()
                connectionSocket.send(response)

                #go into a loop until all data from file is received
                while True:

	            #receive file data
                    data =''

                    mlen = connectionSocket.recv(4)
                    mlen = int.from_bytes(mlen, 'big', signed=False)
                    m = connectionSocket.recv(mlen).decode().split()

                    #check if nothing is received, break
                    if not m:
                        break

                    msg_index = 0  # Indexer used to check how much of the message we've processed so far

                    # Decrypt the message
                    number_of_content_chunks = int(m[msg_index])
                    msg_index += 1
                    message = rsa.decrypt(m[msg_index:msg_index + number_of_content_chunks], privateKey, publicKey_server_n)
                    msg_index += number_of_content_chunks

                    # Decrypt the hash of the message
                    number_of_hash_chunks = int(m[msg_index])
                    msg_index += 1
                    message_hash = rsa.decrypt(m[msg_index:msg_index + number_of_key_chunks], publicKey_client_e, publicKey_client_n)
                    msg_index += number_of_hash_chunks

                    if sha.sha256(message) != message_hash:

                        output = "Invalid hash fingerprint -- authentication failed"
                        break

                    #with open('cd \\' + filename, "w") as f:
                    #    f.write(str(x))

                    data += message
                print("Bingo")
                #copy the file to the server
                with open('cd \\' + filename, "w") as f:
                    f.write(data)

	        #open file in read mode
	        #f = open(filename, "r")
				
	        #print file to verify it was created
	        #print(f.read())

	        #close the file
	        #f.close()

	        #close the connection to the client
                connectionSocket.close()

            else:

                print("Invalid request. Shutting down connection!")
				
	        #close the connection to the client
                connectionSocket.close()

        except Exception as e:

                print("Exception thrown: \r\n", e)

                #close socket to client
                connectionSocket.close()

                #close socket that server is listening on
                #serverSocket.close()

                #shutdown server
                #sys.exit()
	
    #check for KeyboardInterrupt and close sockets before exiting
    except KeyboardInterrupt:

        print("KeyboardInterrupt: Closing sockets and shutting down server!")

        #close socket to client
        connectionSocket.close()

        #close socket that server is listening on
        serverSocket.close()

        #shutdown server
        sys.exit()

    except IOError as e:

        print("Exception thrown: \r\n", e)

        #close socket to client
        connectionSocket.close()

        #close socket that server is listening on
        serverSocket.close()

        #shutdown server
        #sys.exit()

    except Exception as e:

        print("Exception thrown: \r\n", e)

        #close socket to client
        connectionSocket.close()

        #close socket that server is listening on
        #serverSocket.close()

        #shutdown server
        #sys.exit()
