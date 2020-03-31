# DataProcessingApp-Crypto
Cryptography methods implementaion in C

Instructions before executing the code.

1.	Download the zip file.
2.	Unzip the zip file.
3.	The zip file contains 
a.	Server side program (SSL-Server.c)
b.	Client Side program(SSL-Client.c)
c.	Certificate (MyCert1.pem)

4.	Create 3 folders by name “cloud” , “ hmac”,”download” inside the unzipped file.
5.	Open the Server Side program and edit the file path as per your system
Line 70 : Server side program (path of folder cloud)

6.	Open the Client side program and the file path as per your system.
Line 106 : client side program (path of folder hmac)
Line 250 : client side program (path of folder download)

7.	Copy the file that you want to upload into the unzipped folder
8.	Login as super user before compiling the code.
9.	Compile the server side program as below, (ignore warnings)
Compile: gcc -Wall -o ssl-server SSL-Server.c -L/usr/lib -lssl -lcrypto Run : ./ssl-server <port-number> 
10.  Open another terminal and login as super user before compiling the code, Use below instructions to compile the client side program.
Compile : gcc -Wall -o ssl-client SSL-Client.c -L/usr/lib -lssl -lcrypto Run : ./ssl-client localhost <port-num>



** Incase you need to create your own Certificate Please use the command below**

openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem
