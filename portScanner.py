#!/bin/python3

import os, sys
import socket
import netaddr  # install it in kali
from datetime import datetime
import iptc  # install it in kali
import yagmail
from scapy.all import *
import smtplib

def tcpScan():
    op = input("[1] Range of IPS\n[2] Only one IP\nEnter your option: ")
    if op == '2':
        ipStart = ipEnd = input("Enter IP: ")
    else:
        # get user input for range in form xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx and xx-xx
        ipStart, ipEnd = input("Enter IP-IP: ").split("-")
    # define IP range
    iprange = netaddr.IPRange(ipStart, ipEnd)
    # get user input for port range in form xxx-xxx
    portStart, portEnd = input("Enter start port-end port like that 1-100:").split("-")

    for ip in iprange:
        # Add a pretty banner
        print("-" * 50)
        print("scanning target " + str(ip))
        print("Time started: " + str(datetime.now()))
        print("-" * 50)

        try:
            ports = []
            portsStr = ""
            for port in range(int(portStart), int(portEnd) + 1):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                result = s.connect_ex((str(ip), port))  # returns an error indicator
                #print("checking port {}".format(port))
                if result == 0:
                    print("port {} is open".format(port))
                    ports.append(str(port))
                s.close()
            #print(ports)
            portsStr = ','.join(ports)
            #print(portsStr)
            os.system("nmap -T4 -v -sC -sV -oN output.txt -p{} --append-output ".format(portsStr) + str(ip))
        except keyboardInterrupt:
            print("\nExiting program.")
            sys.exit()

        except socket.gaierror:
            print("Hostname couldn't be resolved.")
            sys.exit()

        except socket.error:
            print("Couldn't connect to server.")
            sys.exit()


def udpScan():
    op = input("[1] Range of IPS\n[2] Only one IP\nEnter your option: ")
    if op == '2':
        ipStart = ipEnd = input("Enter IP: ")
    else:
        # get user input for range in form xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx and xx-xx
        ipStart, ipEnd = input("Enter IP-IP: ").split("-")
    # define IP range
    iprange = netaddr.IPRange(ipStart, ipEnd)
    # get user input for port range in form xxx-xxx
    portStart, portEnd = input("Enter start port-end port like that 1-100:").split("-")
    for ip in iprange:
        # Add a pretty banner
        print("-" * 50)
        print("scanning target " + str(ip))
        print("Time started: " + str(datetime.now()))
        print("-" * 50)
        try:
            for port in range(int(portStart), int(portEnd) + 1):
                MESSAGE = "ping"
                portOpen = False
                for _ in range(5):  # udp is unreliable.Packet loss may occur
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                        sock.settimeout(3)
                        sock.sendto(MESSAGE.encode('utf_8'), (str(ip), port))
                        data, addr = sock.recvfrom(1024)
                        print("data = {}".format(data))
                        sock.close()
                        portOpen = True
                        break
                    except socket.timeout:
                        pass
                if portOpen:
                    print('port open!')
                else:
                    print('port closed!')
                '''client.sendto(MESSAGE.encode('utf_8'), (target, port))
                sock1.settimeout(1)
                data, addr = sock1.recvfrom(1024)'''

        except keyboardInterrupt:
            print("\nExiting program.")
            sys.exit()

        except socket.gaierror:
            print("Hostname couldn't be resolved.")
            sys.exit()

        except socket.error:
            print("Couldn't connect to server.")
            sys.exit()


def listen():
    # get my ip address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    myIP = s.getsockname()[0]
    s.close()
    print("My IP is: {}".format(myIP))
    wellknown = [1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53,
                 69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143,
                 150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080]
    for port in range(1, 1024):
        if port not in wellknown:
            print("Current listening unknown port: {}".format(port))
            # make sure hereeeeeeeeeeeeeeee!!!!!!!
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            info = (myIP, port)
            soc.bind(info)
            soc.listen(7)
            current_soc, client = soc.accept()

            rule = iptc.Rule()
            rule.in_interface = "eth0"
            rule.src = client[0]
            rule.protocol = "tcp"
            rule = iptc.Rule()
            m = rule.create_match("tcp")
            t = rule.create_target("DROP")
            print("Blocking ip: {}".format(client[0]))
            #recived = current_soc.recv(2048)
            #print(recived)
            receiver = input("Enter Your email to recive blocking IPs on it: ")
            body = "Hello there this ip: {} tried to connect".format(client[0])
            sender = "kholouditi41@gmail.com"
            password = "&Qz-u7E:"
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.ehlo()
            server.starttls()
            server.login(sender, password)
            print("login success")
            server.sendmail(sender,receiver, body)
            server.quit()

            '''receiver = "kholoudsamy666@gmail.com"
            sender = "kholouditi41@gmail.com"
            body = "Hello there this ip: {} tried to connect".format(client[0])
            password = "&Qz-u7E:"

            yag = yagmail.SMTP(user = sender, password = password)
            yag.send(to=receiver,subject='Blocking IPs',contents=body)'''


def sniffing():
    from collections import Counter
    from scapy.all import sniff

    ## Create a Packet Counter
    packet_counts = Counter()

    ## Define our Custom Action function
    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
        packet_counts.update([key])
        return f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}"

    ## Setup sniff, filtering for IP traffic
    sniff(filter="ip", prn=custom_action, count=10)

    ## Print out packet count per A <--> Z address pair
    print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))


if __name__ == '__main__':
    print('Please make your selection')
    print(' ')
    print('[1] Scan')
    print('[2] Listen on unknown Ports')
    print('[3] Sniffing')
    option = input('Choose your Option:')
    if option == '1':
        print('[1] TCP Scan')
        print('[2] UDP Scan')
        option = input('Choose your Scanning Option:')
        if option == '1':
            tcpScan()
        else:
            udpScan()

    elif option == '2':
        listen()
    else:
        sniffing()
    '''inp = int(input("Press 1 to TCP Scan or 2 to UDP"))
    if inp == 1:
        tcpScan()
    else:
        udpScan()'''
    # listen()
    # sniffing()
    # range_ports = input("Enter start port range-end port range like that 1-100:")

