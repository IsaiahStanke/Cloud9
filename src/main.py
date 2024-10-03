import hashlib
import requests
import time
from scapy.all import *
from scapy.all import sniff, get_if_list
from collections import defaultdict
import scapy.all as scapy
import os
from datetime import datetime
import socket
import threading  # Import threading module

# Get the hostname of the machine
hostname = socket.gethostname()

# Secure API URL and API key from environment variables
DASHBOARD_URL = os.getenv('DASHBOARD_URL', 'https://192.168.1.121:5000/data')
API_KEY = '772a97281008478a1e13d078d477ccf5d5818e3134f02cea1e8a0ce7c10a80f2'  # Ensure this is set in the environment
VIRUSTOTAL_API_KEY = '9b0652630a34dfe2b474c969914fe3030b7055165dc04115f63fd41a1ea41c3c' # VirusTotal API key

# Function to send data to the dashboard
def send_data_to_dashboard(data):
    headers = {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY  # Add the API key to the headers
    }
    data['hostname'] = hostname  # Add hostname to the data
    try:
        # Map the detection data to the correct fields expected by the dashboard
        data['detection_type'] = data.pop('type', None)  # Rename 'type' to 'detection_type'
        data['details'] = data.pop('message', None)  # Rename 'message' to 'details'

        response = requests.post(DASHBOARD_URL, json=data, headers=headers, verify=False)
        if response.status_code == 200:
            print(f"Successfully sent data to dashboard: {data}", flush=True)
        else:
            print(f"Failed to send data: {response.status_code} - {response.text}", flush=True)
    except Exception as e:
        print(f"An error occurred while sending data: {e}", flush=True)

# ###################### Port Scan Detection ###################### #
def port_scan_detection():
    SCAN_THRESHOLD = 20  # Number of distinct ports/services in the time window to consider a scan
    TIME_WINDOW = 30  # Time window in seconds

    connection_tracker = defaultdict(list)
    last_reported_scan = defaultdict(float)
    last_reported_ping = defaultdict(float)

    def detect_port_scan(pkt):
        if pkt.haslayer('IP'):
            src_ip = pkt['IP'].src
            dst_ip = pkt['IP'].dst
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            current_time = time.time()

            # Check for different protocol layers: TCP, UDP, ICMP
            if pkt.haslayer('TCP'):
                proto = 'TCP'
                dst_port = pkt['TCP'].dport
            elif pkt.haslayer('UDP'):
                proto = 'UDP'
                dst_port = pkt['UDP'].dport
            elif pkt.haslayer('ICMP'):
                if pkt['ICMP'].type == 8:  # ICMP Echo Request (ping)
                    if current_time - last_reported_ping[src_ip] > TIME_WINDOW:
                        print(f"Ping detected from {src_ip}", flush=True)
                        last_reported_ping[src_ip] = current_time
                        send_data_to_dashboard({
                            "type": "ping",
                            "src_ip": src_ip,
                            "timestamp": timestamp,
                            "message": f"Ping detected from {src_ip}"
                        })
                return  # Skip further checks for ICMP packets

            connection_tracker[src_ip].append((proto, dst_port, current_time))
            connection_tracker[src_ip] = [(proto, port, t) for proto, port, t in connection_tracker[src_ip] if current_time - t < TIME_WINDOW]
            unique_services = set([(proto, port) for proto, port, _ in connection_tracker[src_ip]])

            if len(unique_services) > SCAN_THRESHOLD:
                if current_time - last_reported_scan[src_ip] > TIME_WINDOW:
                    print(f"Port scan detected from {src_ip} to {dst_ip}", flush=True)
                    last_reported_scan[src_ip] = current_time
                    send_data_to_dashboard({
                        "type": "port_scan",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "ports_scanned": [int(port) for proto, port in unique_services],
                        "timestamp": timestamp,
                        "message": f"Port scan detected from {src_ip} to {dst_ip}"
                    })

    print("Starting network sniffing on all interfaces for port scanning...", flush=True)
    sniff(filter="ip", prn=detect_port_scan, store=0, timeout=60)

# ###################### Hash Checker ###################### #
def hash_checker():
    # Function to calculate file hash
    def calculate_hash(data, hash_algo='sha256'):
        hash_func = hashlib.new(hash_algo)
        hash_func.update(data)
        return hash_func.hexdigest()

    def check_hash_virustotal(hash_value):
        url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}

        print(f"Checking hash: {hash_value}", flush=True)
        analysis_results = {"hash": hash_value}
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                json_response = response.json()
                if 'data' in json_response:
                    attributes = json_response['data'].get('attributes', {})
                    stats = attributes.get('last_analysis_stats', {})
                    if stats.get('malicious', 0) > 0:
                        analysis_results.update({
                            "malicious_engines": stats['malicious'],
                            "type": "malware_detection",
                            "timestamp": timestamp,
                            "message": f"Detected by {stats['malicious']} engines as malicious."
                        })
                        print(f"Detected by {stats['malicious']} engines as malicious.", flush=True)
                        send_data_to_dashboard(analysis_results)
                    else:
                        print("No malware detected.", flush=True)
            else:
                print(f"Error: {response.status_code}", flush=True)
        except Exception as e:
            print(f"An error occurred: {e}", flush=True)

    def extract_files(packet):
        if packet.haslayer(Raw):
            data = bytes(packet[Raw])
            if data:
                file_hash = calculate_hash(data)
                print("Hash of extracted file:", file_hash, flush=True)
                check_hash_virustotal(file_hash)

    print("Starting network sniffing for file hash checking...", flush=True)
    sniff(prn=extract_files, store=0, timeout=60)

# ###################### SMB Enumeration ###################### #
def smb_enum():
    last_reported_smb = defaultdict(float)
    TIME_WINDOW = 30

    def packet_callback(packet):
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag set
            tcp_packet = packet[TCP]
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            current_time = time.time()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if tcp_packet.dport in [445, 139]:
                if current_time - last_reported_smb[src_ip] > TIME_WINDOW:
                    last_reported_smb[src_ip] = current_time
                    summary = packet.summary()

                    print(f"[+] SMB enumeration detected: {summary}", flush=True)
                    smb_data = {
                        "type": "smb_enum",
                        "timestamp": timestamp,
                        "message": summary,
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "destination_port": tcp_packet.dport
                    }
                    send_data_to_dashboard(smb_data)
                else:
                    print(f"[+] Duplicate SMB enumeration from {src_ip} ignored", flush=True)

    print("Starting SMB Enumeration Detection...", flush=True)
    sniff(prn=packet_callback, store=0, filter="tcp port 445 or tcp port 139", timeout=60)

# Main Execution
if __name__ == "__main__":
    port_scan_thread = threading.Thread(target=port_scan_detection)
    hash_checker_thread = threading.Thread(target=hash_checker)
    smb_enum_thread = threading.Thread(target=smb_enum)

    port_scan_thread.start()
    hash_checker_thread.start()
    smb_enum_thread.start()

    port_scan_thread.join()
    hash_checker_thread.join()
    smb_enum_thread.join()
