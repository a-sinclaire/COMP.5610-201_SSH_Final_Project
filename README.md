# How to run a Server
Use python to run the `serverSSH.py` file.
It takes no command line arguments.

# How to run a Client
Use pythin to run the `clientSSH.py` file.
It takes 3 command line arguments:
1. username
2. server address
3. request type
   
An example:
`python3 clientSSH.py amelia 127.0.0.1 NOR`

## How to use the different request types:
### NOR
The `NOR` request type allows you to remote shell into the server.

`python3 clientSSH.py amelia 127.0.0.1 NOR`

Once the command has been run you will be able to send commands to the server shell and recieve output from it.

### SCP
The `SCP` request type allows you to transfer a text file to the server. You must give the filename path and destination in that order.

`python3 clientSSH.py amelia 127.0.0.1 SCP notes.txt servernotes.txt`

This command will transfer the text file to the server.

### HELP
The `HELP` request type will provide information on how to use the `clientSSH.py` file.

`python3 clientSSH.py amelia 127.0.0.1 HELP`
