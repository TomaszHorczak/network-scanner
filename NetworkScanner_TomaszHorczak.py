#!/usr/bin/env python3

import subprocess
import re
import psutil
import random
import argparse
import socket
import threading
import json
from queue import Queue
import scapy.all as scapy


class Userdata:
    """The class that gets all user input based on the users terminal arguements"""

    def __init__(self):
        """defines which variables are necessary to accomplish the users command"""
        self.correct_mac = re.compile(self.gen_mac())
        self.args = self.term_settings()
        self.interface, self.user_ip = self.find_interface_ip()
        self.user_mac = self.get_current_mac()
        # The dictionary where all user items are held
        self.user_stuff = {
            "Interface": self.interface,
            "Mac Address": self.user_mac,
            "Your IP": self.user_ip,
        }

    def term_settings(self):
        """terminal options that a user can provide"""
        parser = argparse.ArgumentParser(
            description="Choose what features of the program you would like to run \nWithout arguements you will run a network and portscan of your network"
        )
        # optional arguements
        parser.add_argument(
            "-m",
            "--mac",
            type=str,
            required=False,
            metavar="",
            default=None,
            choices=["y", "r"],
            help='This option is if you want to change your mac address: "y" for you to manually type the mac address, "r" for a random one to be assigned',
        )
        parser.add_argument(
            "-n",
            "--nscan",
            type=str,
            required=False,
            metavar="",
            default=None,
            choices=["y", "m"],
            help='Choose if you want to do a network scan. \n"y": for scanning an outside network, \n"m": your network',
        )
        parser.add_argument(
            "-p",
            "--pscan",
            type=str,
            required=False,
            metavar="",
            default=None,
            choices=["tcp", "syn", "tcpC", "synC"],
            help='Choose what type of port scan you would like to do, the "C" option dictates if you would like to input a custom range',
        )
        parser.add_argument(
            "-s",
            "--save",
            type=str,
            required=False,
            metavar="",
            default=None,
            help="To save the results of your scan, use this command followed by the name of the file without an extension (it will be saved to a json file)",
        )
        # Compiling the arguements
        # all arguements added can be called using args.attribute
        args = parser.parse_args()
        return args

    def gen_mac(self):
        """Generates a random mac address"""
        mac = [
            0x00,
            0x16,
            0x3E,
            random.randint(0x00, 0x7F),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
        ]
        return ":".join(map(lambda x: "%02x" % x, mac))

    def find_interface_ip(self):
        """Finds the interface card that is currently being used
        by checking to see which interface has a valid IP address"""
        ipv4_regex = re.compile(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
        # using psutil.net_if_addrs() to collect all avaible network card information
        all_interfaces = psutil.net_if_addrs()
        for key, value in all_interfaces.items():
            # using getattr(value[0], 'address') to identify the ip address of the network address
            # value[0] because the ip address is contained within the 0th index of the namedtuple
            ip = str(getattr(value[0], "address"))
            match = ipv4_regex.match(ip)
            # ip 127.0.0.1 is always the default of the lo card
            # The program must avoid that card
            if match and ip != "127.0.0.1":
                interface = str(key)
                return interface, ip

    def get_current_mac(self):
        """Checks the mac address of the given interface card by calling ifconfig"""
        # getting all of the output of our active network card
        output = str(subprocess.check_output(["ifconfig", self.user_ip]))
        interface_current_mac_result = re.search(self.correct_mac, output)
        interface_current_mac = interface_current_mac_result.group(0)
        # getting only the mac address output of the regex
        return interface_current_mac

    def get_save_file(self):
        filename = self.args.save
        while True:
            # This if statement is to accomadate if the user decides to not give a save arguement
            if self.args.save != None:
                try:
                    with open(f"{filename}.json", "w+") as user_file:
                        json.dump(self.user_stuff, user_file)
                except:
                    print("It looks like you did not type a proper file name")
                    filename = input(
                        "Type the name that you want to use for the file (The .json extension will be automatically be added for you, please don't add it): "
                    )
                else:
                    print("Your file has been saved!")
                    break
            else:
                print("Your results are not going to be saved!")
                break


class ChangeMAC:
    def __init__(self, mac_choice, interface):
        self.correct_mac = re.compile(self.gen_mac())
        self.mac_choice = mac_choice
        self.interface = interface
        # mac depending on if the user provided one
        # no mac address but user specified that they want a new
        if self.mac_choice == "y":
            self.new_mac = self.user_mac_m()
        else:
            self.new_mac = self.gen_mac()

    def gen_mac(self):
        """Generates a random mac address"""
        mac = [
            0x00,
            0x16,
            0x3E,
            random.randint(0x00, 0x7F),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
        ]
        return ":".join(map(lambda x: "%02x" % x, mac))

    def user_mac_m(self):
        """Allow the user to manually type a mac address
        Also checks that the address is valid"""
        while True:
            new_mac = input(
                'Type a valid mac address such as "00:11:22:33:44:66": '
            ).strip()
            match = re.search(self.correct_mac, new_mac)
            if match:
                return new_mac

    def change_mac(self):
        """The function that actually changes the mac address"""
        # disable the interface
        subprocess.call(["sudo", "ifconfig", str(self.interface), "down"])
        print(f"{self.interface} is down...")
        # change mac address
        print(
            f"MAC address for interface {self.interface} is being changed to {self.new_mac}"
        )
        subprocess.call(
            ["sudo", "ifconfig", str(self.interface), "hw", "ether", self.new_mac]
        )
        # bring interface back up
        subprocess.call(["sudo", "ifconfig", str(self.interface), "up"])
        print(f"{self.interface} is up...\n")


class NetworkScan:
    def __init__(self, target_ip_choice, user_ip):
        self.target_ip_choice = target_ip_choice
        self.user_ip = user_ip
        self.target_ip = self.get_target_ip()
        self.ip_range = self.get_ip_range()
        self.client_list = self.get_network_users()

    def get_target_ip(self):
        if self.target_ip_choice == "y":
            ipv4_regex = re.compile(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
            while True:
                target_ip = input("Type the IPv4 Address that you would like to scan: ")
                match = ipv4_regex.match(target_ip)
                if match:
                    return target_ip
                else:
                    print("You did not type a valid IP Adress")
        elif self.target_ip_choice == "m":
            target_ip = self.user_ip
            print("We will scan your network")
            return target_ip

    def get_ip_range(self):
        """Get the ip range based off the ip of the user's network card
        Then get its whole subnet so the it can be scanned
        Scans by creating an ARP request directed to broadcast address asking for a specific IP
        That IP responds and its information is stored
        """
        lis = self.target_ip.split(".")
        lis[-1] = "1/24"
        ip_range = ".".join(lis)
        print(ip_range)
        return ip_range

    def get_network_users(self):
        arp_request = scapy.ARP(pdst=self.ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list, _ = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)
        clients_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)
        return clients_list

    def print_network_users(self):
        print(
            "The Network scan is complete is is the information of the users the network:"
        )
        print(
            "----------------------------------------------------------------------------"
        )
        for client in self.client_list:
            print(f"IP: {client['ip']}")
            print(f"MAC: {client['mac']}")


class PortScan:
    """TCP port scan, that implements threading for increased speed"""

    def __init__(self, user_choice, target_ip, amount_of_threading=10):
        self.q = Queue()
        self.user_choice = user_choice
        # target_ip from the network scan if it exists otherwise get a new one
        if target_ip != None:
            self.target_ip = target_ip
        else:
            self.target_ip = self.get_target_ip()
        self.port_list = self.get_port_range()
        # range(1,1024) is default because those are well-known ports
        self.amount_of_threading = amount_of_threading
        # threading increases the speed of the scanning
        # default is 10 because most computers can handle that amount
        self.open_ports = self.implement_threading()

    def get_port_range(self):
        """Getting the range of ports that will be scanned based on the user's input
        Will continue to ask until a valid range of ports is inputed"""
        if self.user_choice == "tcpC" or self.user_choice == "synC":
            print("I need the port range to scan")
            while True:
                try:
                    starting_port = int(
                        input("Type the first port that you would like to scan: ")
                    )
                    last_port = int(
                        input("Type the last port that you would like to scan")
                    )
                except:
                    print("You did not type a number")
                else:
                    if (
                        starting_port > 0
                        and last_port > 0
                        and last_port >= starting_port
                    ):
                        break
                    else:
                        print("The port range you typed was not valid")
            port_range = list(range(starting_port, last_port + 1))
        else:
            print("Ok we will scan the registered ports so 1-1023")
            port_range = list(range(1, 1024))
        return port_range

    def get_target_ip(self):
        ipv4_regex = re.compile(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
        while True:
            target_ip = input("Type the IPv4 Address that you would like to scan: ")
            match = ipv4_regex.match(target_ip)
            if match:
                return target_ip
            else:
                print("You did not type a valid IP Adress")

    def check_target_ip_up(self):
        """Uses the subprocess module to check the availability of the target IP
        Need to test if this method will even work"""
        p = subprocess.Popen(f"ping {self.target_ip}", stdout=subprocess.PIPE)
        # stdout=subprocess.PIPE hides the output so I can put my custom output
        p.wait()
        if p.poll():
            print(f"{self.target_ip} is down")
            print("Can't do a port scan on this IP")
            continue_scan = False
        else:
            continue_scan = True
        return continue_scan

    def tcpscan(self, port):
        """tcp scan"""
        try:
            # AF_INET says that this is an internet port
            # SOCK_STREAM says that this is TCP NOT UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.target_ip, port))
            return True
        except:
            return False

    def synscan(self, port):
        """SYN scan"""
        try:
            sock = scapy.sr1(
                scapy.IP(dst=self.target_ip) / scapy.TCP(dport=port, flags="S"),
                verbose=0,
            )
            if sock.getlayer(scapy.TCP).flags == "SA":
                return True
        except:
            return False

    def complete_list(self):
        """Goes through the queue 
        calls the desired portscan type to get the result"""
        while not self.q.empty():
            # .get() get the next port in the list
            port = self.q.get()
            if self.user_choice == "tcp" or self.user_choice == "tcpC":
                result = self.tcpscan(port)
            else:
                result = self.synscan(port)
            if result:
                print(f"Port {{port}} is open...")
                self.open_ports.append(port)

    def implement_threading(self):
        for port in self.port_list:
            self.q.put(port)
        open_ports = []
        thread_list = []
        # 10 ports per second
        # threads per second limited by cpu power
        for t in range(self.amount_of_threading):
            # refering to the worker function without actually calling it
            thread = threading.Thread(target=self.complete_list)
            thread_list.append(thread)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()
        return open_ports

    def print_open_ports(self):
        print("These are the open ports")
        for port in self.open_ports:
            print(f"Port {port}")


#####################################
# Intergrate argsparse in the future#
#####################################
def main():
    """The purpose of this program is to allow the user to learn about their network & the devices on it"""
    # Getting default user data
    your_data = Userdata()
    # Changing the users mac address if they choose to
    if your_data.args.mac != None:
        your_new_mac = ChangeMAC(your_data.args.mac, your_data.interface)
        your_new_mac.change_mac()
        your_data.user_stuff["Mac Address"] = your_new_mac.new_mac
    # Scanning the desired Network
    if your_data.args.nscan != None:
        your_network_scan = NetworkScan(your_data.args.nscan, your_data.user_ip)
        your_network_scan.print_network_users()
        your_data.user_stuff["Network Clients"] = your_network_scan.client_list
    # Portscan
    if your_data.args.pscan != None:
        try:
            port_target_ip = your_network_scan.target_ip
        except:
            port_target_ip = None
        finally:
            your_port_scan = PortScan(your_data.args.pscan, port_target_ip)
            your_port_scan.print_open_ports()
            your_data.user_stuff["Open Ports"] = your_port_scan.open_ports
    # default behavior of the program if no arguements are provided
    if (
        your_data.args.mac == None
        and your_data.args.nscan == None
        and your_data.args.pscan == None
    ):
        print("No arguements provided, will complete default behavior")
        your_network_scan = NetworkScan("m", your_data.user_ip)
        your_network_scan.print_network_users()

    your_data.get_save_file()
    print("Program by Tomasz Horczak!")


if __name__ == "__main__":
    main()
