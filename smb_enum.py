import scapy.all as scapy
import os
from datetime import datetime

def packet_callback(packet):
    if packet.haslayer(scapy.TCP) and packet.getlayer(scapy.TCP).flags == 2:  # SYN flag set
        tcp_packet = packet.getlayer(scapy.TCP)
        if tcp_packet.dport in [445, 139]:  # Destination port 445 (SMB)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            summary = packet.summary()
            log_entry = f"[{timestamp}] {summary}\n"
            with open("logs/smb_enum_logs.txt", "a") as file:
                file.write(log_entry)
            print(f"[+] SMB enumeration detected: {summary}")

def detect_smb_enumeration():
    print("[*] Starting SMB Enumeration Detection on all network interfaces...")
    scapy.sniff(prn=packet_callback, store=0, iface="Ethernet", filter="tcp")

if __name__ == "__main__":
    log_directory = "logs"
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)
    detect_smb_enumeration()
