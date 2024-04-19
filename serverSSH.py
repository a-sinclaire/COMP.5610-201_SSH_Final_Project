#server.py
from socket import *
import sys
import ast
import CNSec_RSA as rsa
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
    privateKey = int(x["adminr"])
else:
    print("The server now has its private and public keys")
    d, e, n = rsa.generate_key()

    #Add new username and key to file
    x["admin"] = str(e) + "," + str(n)
    x["adminr"] = str(d)
    publicKey_server = x["admin"]
    publicKey_server_e, publicKey_server_n = [int(_) for _ in publicKey_server.split(',')]
    privateKey = int(x["adminr"])
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
        message = connectionSocket.recv(1024)

        print(f'recieved message: {message}')

        #check if  registration request, send publicKey
        if message.decode() == "REG":

            response = publicKey_server
            connectionSocket.send((response).encode())

            #receive file data
            data = connectionSocket.recv(2048)

            #datalist contain a list of the data from the request
            datalist = data.decode().split(' ')
            msg_index = 0  # Indexor used to check how much of the message we've processed so far

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

            #check if nothing is received, break
            #if not data:


            #open file in read mode, and get a list of usernames in the system
            with open('server_keys.txt', "r") as f:
                x = ast.literal_eval(f.read())
            usernames = x.keys()
            print(f'usernames on server: {usernames}')
            print(f'keys on server: {x}')

            #check if username is already in the file.
            if username in usernames:
                if x[username] == publicKey_client:
                    print(f"User {username} has registered before.")
                    response = f'User {username} is already registered.\r\n\r\n'
                else:
                    print(f"Username {username} is not available")
                    response = f'Username {username} is already in use by another user'
            else:
                print(f"The username {username} will be added to our system")

                #Add new username and key to file
                x[username] = publicKey_client
                print(f'updated keys on server: {x}')
                with open('server_keys.txt', "w") as f:
                    f.write(str(x))
                response = f'The user {username} has been registered\r\n\r\n'

            publicKey_client_e, publicKey_client_n = [int(_) for _ in publicKey_client.split(',')]
            #send response
            response = ' '.join(rsa.encrypt(response, publicKey_client_e, publicKey_client_n))
            connectionSocket.send(response.encode())
            #connection.close()

            while True:
                try:
                    m = connectionSocket.recv(2048).decode().split()
                    username = m[0]
                    pubkey = m[1]
                    message = ' '.join(m[2:])

                    output = "output:\n"
                    output += subprocess.getoutput(message)

                    connectionSocket.send(output.encode())

                    print(f'recieved normal message: {message}')
                    print(f'recieved normal message: {output}')
                    connectionSocket.send(message.encode())

                    if message == 'exit':
                        connectionSocket.close()
                        break
                except:
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
