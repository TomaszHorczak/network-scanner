# network-scanner
Holds all the necessary files to run my network scanner.

About:
This program allows you to scan the network of an IP Address to find information about that network 
(user mac addresses, the specific IP addresses of a computer on the network, and how many computers are connected to that network). 
Additionally you can also scan for open ports, by giving your desired range of ports that you would like to scan.
The port scanner implements threading to increase the speed of the scan
Additionally you have the option to choose if you would like the port scan to be a full scan using the 3way handshake of TCP, 
or whats commonly refered to as a SYN scan which does not fully complete the handshake inorder to protect your anonymity.
You can also change your Mac address manually or have it set to a new random one if you choose.
I am still actively working on this project to clean up the code, and hopefully add features in the future.

What I hope to improve:
Currently my implementation of argsparse is not as clean as I would like it to be, 
due to the fact that given certain arguements you will be later prompted to input more arguements at the terminal, 
I did this so I could implement user input validation 
but I may remove it in the future in favor of a cleaner solution.
The actual arguement syntax could also use sprucing up

Why I made it?
This program is essentally my clone of nmap but with less functionallity
I made it for strictly educational purposes
It gave me an opporitunity to explore how python can be used in the cybersecurity field, 
learn about general purpose & networking specific python packages such as argsparse, scapy, and socket that may be useful in the future. 

How to use:
Like mentioned earlier this program utilizes argsparse to allow the user to provide arguements prior to running it.
By default given no arguements, 
the program will scan your computer's network and print out the information of those computers
No port scanning, your mac address will stay the same, and the results of the scan will not be saved

The arguements:
"-m" or"--mac": to change your mac address
followed by "y" to change the mac address manually at the terminal when prompted
or followed by "r" to have your mac address changed to a new random one

"-n" or "--nscan": to perform a network scan
followed by "y" to scan an outside network that you will type the IP address of at the terminal when prompted
or followed by "m" to scan your network

"-p" or "-pscan": to perform a port scan
followed by "tcp" and "syn" will perform their respective scans on well known ports (1-1024)
or followed by "tcpC" and "synC" will perform their respective scans on a range of ports that you will input

"-s" or "--save"
followed by the name that you wish to save the file as, ex: -s result
The program will save the results as a json file, it will add the ".json" extension automatically
