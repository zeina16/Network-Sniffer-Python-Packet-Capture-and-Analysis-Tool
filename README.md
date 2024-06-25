# Network-Sniffer-Python-Packet-Capture-and-Analysis-Tool
from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP src: {ip_src} --> IP dst: {ip_dst}")

print("Starting network sniffer...")
sniff(prn=packet_callback, count=10)
