# WiFi-Sniffer-using-Scapy
It’ll capture WiFi packets flying through the air like gossip at a high school lunch table.
from scapy.all import *
import os

def packet_handler(packet):
    if packet.haslayer(Dot11):
        mac_src = packet[Dot11].addr2
        mac_dst = packet[Dot11].addr1
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore') if packet.haslayer(Dot11Elt) else ''
        print(f"📶 Packet: {mac_src} ➡️ {mac_dst} | SSID: {ssid}")

if __name__ == "__main__":
    iface = input("Enter your WiFi interface in monitor mode (e.g., wlan0mon): ")
    print("🔍 Sniffing WiFi packets... Press Ctrl+C to stop.\n")
    sniff(iface=iface, prn=packet_handler, store=0)
