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

        #check if user had registered before, send publicKey_server
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

        if requestType == 'SCP':

            #get the destination
            number_of_file_destination_chunks = int(datalist[msg_index])
            msg_index += 1
            file_destination = rsa.decrypt(datalist[msg_index:msg_index+number_of_file_destination_chunks], privateKey, publicKey_server_n)
            msg_index += number_of_file_destination_chunks

        #open file in read mode, and get a list of usernames in the system
        with open('server_keys.txt', "r") as f:
            x = ast.literal_eval(f.read())

        usernames = x.keys()

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
                connectionSocket.close()

        else:
                	
            print(f"The username {username} will be added to our system")

            #Add new username and key to file
            x[username] = publicKey_client

            with open('server_keys.txt', "w") as f:
                f.write(str(x))

            response = f'The user {username} has been registered'

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
                    message_hash = rsa.decrypt(m[msg_index:msg_index + number_of_hash_chunks], publicKey_client_e, publicKey_client_n)
                    msg_index += number_of_hash_chunks

                    if sha.sha256(message) != message_hash:

                        output = "Invalid hash fingerprint -- authentication failed"
                        print(output)
                        break

                    if message == 'exit':

                        break

                    elif message.split()[0] == 'cd':

                        if len(message.split()) > 1:

                            os.chdir(' '.join(message.split()[1:]))

                        output = ' '

                    else :

                        output = subprocess.getoutput(message)

                    print(output)
                    output = ' '.join(rsa.encrypt(output, publicKey_client_e, publicKey_client_n))
                    output = len(output).to_bytes(4, 'big', signed=False) + output.encode()
                    connectionSocket.send(output)

                connectionSocket.close()
                os.chdir(directory)
            

            elif requestType == "SCP":

	        #create response to client
                response = 'File is being copied'

	        #send response to client
                response = ' '.join(rsa.encrypt(response, publicKey_client_e, publicKey_client_n))
                response = len(response).to_bytes(4, 'big', signed=False) + response.encode()
                connectionSocket.send(response)

                msg_index = 0  # Indexer used to check how much of the message we've processed so far

                #go into a loop until all data from file is received
                while True:

	            #receive file data
                    mlen = connectionSocket.recv(4)
                    mlen = int.from_bytes(mlen, 'big', signed=False)
                    m = connectionSocket.recv(mlen).decode().split()

                    #check if nothing is received, break
                    if not m:
                        break

                    # Decrypt the message
                    number_of_content_chunks = int(m[msg_index])
                    msg_index += 1
                    message = rsa.decrypt(m[msg_index:msg_index + number_of_content_chunks], privateKey, publicKey_server_n)
                    msg_index += number_of_content_chunks

                    # Decrypt the hash of the message
                    number_of_hash_chunks = int(m[msg_index])
                    msg_index += 1
                    message_hash = rsa.decrypt(m[msg_index:msg_index + number_of_hash_chunks], publicKey_client_e, publicKey_client_n)
                    msg_index += number_of_hash_chunks

                    if sha.sha256(message) != message_hash:

                        output = "Invalid hash fingerprint -- authentication failed"
                        print(output)
                        break

                # create the file to store client keys if it does not exist
                if not os.path.exists(file_destination):

                    with open(file_destination, 'w') as f:
                        f.write(message)

                else:

                    #copy the file to the server
                    with open(file_destination, "w") as f:
                        f.write(message)

	        #close the connection to the client
                connectionSocket.close()

            elif requestType == "HELP":

                m = ("\r\nHow to run clientSSH\r\npython3 clientSSH.py <username> <servername or IP address> <request type> <filename> <destination> \r\nFilename and path are only needed for SCP.\r\n\r\nValid request types: \r\nNOR\tRemote shell to the server.\r\nSCP\tTransfer text file to server. Must give filename/path and destination.\r\nHELP\tPrints out help screen.\r\n")
                m = ' '.join(rsa.encrypt(m, publicKey_client_e, publicKey_client_n))
                m = len(m).to_bytes(4, 'big', signed=False) + m.encode()
                connectionSocket.send(m)

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

    except Exception as e:

        print("Exception thrown: \r\n", e)

        #close socket to client
        connectionSocket.close()
