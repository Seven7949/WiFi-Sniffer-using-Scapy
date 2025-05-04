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

Run the script:
sudo python3 wifi_sniffer.py
Then enter:

Enter your WiFi interface in monitor mode (e.g., wlan0mon):
🚨 Example Output

📶 Packet: 84:3a:4b:8f:10:cd ➡️ ff:ff:ff:ff:ff:ff | SSID: Starbucks_Wifi
📶 Packet: a4:fc:77:1c:dd:50 ➡️ 00:11:22:33:44:55 | SSID: EvilTwin
💡 Tips

Use in combination with airodump-ng for deeper exploration.
Try identifying open networks or probe request floods.
⚠️ LEGAL WARNING

This script is for educational purposes only.
Sniffing WiFi traffic without consent is illegal in many regions. Use responsibly and ethically.

👩‍💻 Author

Crafted with chaos & curiosity by Seventhetic

🧾 License

MIT — because open source > closed doors.

