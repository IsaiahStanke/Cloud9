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
import subprocess
import platform
import hmac
import uuid

# Get the hostname of the machine
hostname = socket.gethostname()

# Secure API URL and API key from environment variables
DASHBOARD_URL = os.getenv('DASHBOARD_URL', 'https://IP:PORT/data')
API_KEY = 'EXAMPLE'

SECRET_KEY = os.getenv('SECRET_KEY', 'EXAMPLE SECRET KEY')  # Replace 'your-default-secret-key' with a strong key

# Cache to store sent data hashes and timestamps
sent_data_cache = {}
CACHE_EXPIRATION_INTERVAL = 300  # 5 minutes

sent_nonces = {}  # Initialize the global sent_nonces dictionary

def has_data_been_sent_recently(data_hash):
    current_time = time.time()
    if data_hash in sent_data_cache:
        last_sent_time = sent_data_cache[data_hash]
        if current_time - last_sent_time < CACHE_EXPIRATION_INTERVAL:
            return True
    return False

def update_cache(data_hash):
    sent_data_cache[data_hash] = time.time()

def calculate_data_hash(data):
    data_string = str(data)
    return hashlib.sha256(data_string.encode()).hexdigest()

# Generate a unique nonce
def generate_nonce():
    return str(uuid.uuid4())

# Sign the message with a shared secret key (use a strong secret key)
def sign_message(data, secret_key):
    message = f"{data['timestamp']}-{data['nonce']}-{data['hostname']}-{data['details']}"
    signature = hmac.new(secret_key.encode(), message.encode(), digestmod=hashlib.sha256).hexdigest()
    return signature

def send_data_to_dashboard(data, secret_key, is_scheduled_task=False, is_host_entry=False, is_service_highlight=False):
    headers = {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
    }

    # Ensure necessary fields are present in the data
    data['hostname'] = data.get('hostname', hostname)  # Default to the local hostname
    data['nonce'] = data.get('nonce', generate_nonce())
    data['timestamp'] = data.get('timestamp', int(time.time()))  # Default to current Unix timestamp
    data['details'] = data.get('details', 'No details provided')  # Ensure details field is present

    data_hash = calculate_data_hash(data)

    # Check if this data has already been sent recently
    if has_data_been_sent_recently(data_hash):
        print(f"[DEBUG] Skipping duplicate data: {data}")
        return

    # Sign the message
    data['signature'] = sign_message(data, secret_key)

    try:
        # Send to appropriate endpoint
        url = DASHBOARD_URL
        if is_scheduled_task:
            url = DASHBOARD_URL.replace('/data', '/scheduled_tasks')
        elif is_host_entry:
            url = DASHBOARD_URL.replace('/data', '/hosts_entries')
        elif is_service_highlight:
            url = DASHBOARD_URL.replace('/data', '/non_microsoft_services')

        response = requests.post(url, json=data, headers=headers, verify=False)
        if response.status_code == 200:
            print(f"[DEBUG] Successfully sent data to dashboard: {data}")
            update_cache(data_hash)
        else:
            print(f"[ERROR] Failed to send data: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[ERROR] Exception occurred: {e}")

# ###################### Port Scan Detection ###################### #
PORT_SCAN_REPORT_INTERVAL = 300  # 5 minutes
last_reported_port_scans = {}

def port_scan_detection():
    SCAN_THRESHOLD = 20  # Number of distinct ports/services in the time window to consider a scan
    TIME_WINDOW = 30  # Time window in seconds

    connection_tracker = defaultdict(list)
    last_reported_ping = defaultdict(float)

    def detect_port_scan(pkt):
        if pkt.haslayer('IP'):
            src_ip = pkt['IP'].src
            dst_ip = pkt['IP'].dst
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            current_time = time.time()

            # Initialize dst_port with a default value
            dst_port = None

            # Check for different protocol layers: TCP, UDP, ICMP
            if pkt.haslayer('TCP'):
                proto = 'TCP'
                dst_port = pkt['TCP'].dport
            elif pkt.haslayer('UDP'):
                proto = 'UDP'
                dst_port = pkt['UDP'].dport
            elif pkt.haslayer('ICMP'):
                proto = 'ICMP'
                if pkt['ICMP'].type == 8:  # ICMP Echo Request (ping)
                    if current_time - last_reported_ping[src_ip] > TIME_WINDOW:
                        print(f"[DEBUG] Ping detected from {src_ip}", flush=True)
                        last_reported_ping[src_ip] = current_time
                        send_data_to_dashboard({
                            "detection_type": "ping",  # Set detection type for ping
                            "src_ip": src_ip,
                            "timestamp": timestamp,
                            "details": f"Ping detected from {src_ip}"
                        }, secret_key=SECRET_KEY)  # Pass the secret key
                return  # Skip further checks for ICMP packets
            else:
                proto = 'Other'
                dst_port = 'Unknown'  # Set a default value for unknown protocols

            connection_tracker[src_ip].append((proto, dst_port, current_time))
            connection_tracker[src_ip] = [(proto, port, t) for proto, port, t in connection_tracker[src_ip] if current_time - t < TIME_WINDOW]
            unique_services = set([(proto, port) for proto, port, _ in connection_tracker[src_ip]])

            # Check if the port scan exceeds the threshold and hasn't been recently reported
            if len(unique_services) > SCAN_THRESHOLD:
                if src_ip not in last_reported_port_scans or (current_time - last_reported_port_scans[src_ip]) > PORT_SCAN_REPORT_INTERVAL:
                    print(f"[DEBUG] Port scan detected from {src_ip} to {dst_ip}", flush=True)
                    last_reported_port_scans[src_ip] = current_time  # Update last reported time for this IP

                    send_data_to_dashboard({
                        "detection_type": "port_scan",  # Set detection type for port scan
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "ports_scanned": [int(port) for proto, port in unique_services if isinstance(port, int)],  # Ensure ports are integers
                        "timestamp": timestamp,
                        "details": f"Port scan detected from {src_ip} to {dst_ip}"
                    }, secret_key=SECRET_KEY)  # Pass the secret key

    print("[DEBUG] Starting network sniffing on all interfaces for port scanning...", flush=True)
    sniff(filter="ip", prn=detect_port_scan, store=0, timeout=60)

# ###################### Service Enumeration (Suspicious Services) ###################### #
def get_suspicious_services():
    """
    Enumerates services running on the machine and identifies potentially suspicious services (non-Microsoft based).
    """
    os_type = platform.system()

    try:
        if os_type == "Windows":
            # Use PowerShell to get services, filtering out Microsoft-based ones
            cmd = 'Get-Service | Where-Object { $_.DisplayName -notlike "*Microsoft*" } | Select-Object DisplayName, Status, ServiceType'
            result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
            services = result.stdout.splitlines()

            suspicious_services = [svc for svc in services if 'Stopped' not in svc]  # Filter running suspicious services

        elif os_type == "Linux":
            # Use systemctl to list services and filter out known safe services
            cmd = "systemctl list-units --type=service --all | grep -vE '(microsoft|systemd)'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            services = result.stdout.splitlines()

            suspicious_services = [svc for svc in services if 'running' in svc]  # Only track running services
        else:
            print(f"[DEBUG] Unsupported OS: {os_type}", flush=True)
            return

        # If suspicious services are found, send data to the dashboard
        if suspicious_services:
            print(f"[DEBUG] Suspicious services found: {suspicious_services}", flush=True)
            send_data_to_dashboard({
                "hostname": hostname,
                "details": "\n".join(suspicious_services),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }, secret_key=SECRET_KEY, is_service_highlight=True)

    except Exception as e:
        print(f"[ERROR] An error occurred while retrieving services: {e}", flush=True)


def periodically_check_suspicious_services():
    """
    Periodically checks for suspicious services running on the machine.
    """
    while True:
        print("[DEBUG] Checking for suspicious services...", flush=True)
        get_suspicious_services()
        time.sleep(300)  # Check every 5 minutes


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

                    print(f"[DEBUG] [+] SMB enumeration detected: {summary}", flush=True)
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
                    print(f"[DEBUG] [+] Duplicate SMB enumeration from {src_ip} ignored", flush=True)

    print("[DEBUG] Starting SMB Enumeration Detection...", flush=True)
    sniff(prn=packet_callback, store=0, filter="tcp port 445 or tcp port 139", timeout=60)

# ###################### Scheduled Tasks ###################### #
SCHEDULED_TASK_CHECK_INTERVAL = 60

def periodically_check_scheduled_tasks():
    """
    Periodically check for suspicious scheduled tasks on the system (Windows/Linux).
    """
    while True:
        print("[DEBUG] Checking for new scheduled tasks...", flush=True)
        get_scheduled_tasks()  # Call the function that checks for scheduled tasks
        time.sleep(SCHEDULED_TASK_CHECK_INTERVAL)  # Wait for the specified interval before checking again

def get_scheduled_tasks():
    """
    Retrieves and displays all scheduled tasks on the local machine, 
    whether it is Windows (using PowerShell) or Linux (using crontab).
    """
    os_type = platform.system()

    if os_type == "Windows":
        return get_windows_scheduled_tasks()
    elif os_type == "Linux":
        return get_linux_scheduled_tasks()
    else:
        print(f"[DEBUG] Unsupported operating system: {os_type}", flush=True)
        return False

# Keep track of already sent suspicious tasks
sent_scheduled_tasks = set()

def get_windows_scheduled_tasks():
    """
    Retrieves and checks for suspicious scheduled tasks on a Windows machine using PowerShell.
    """
    try:
        # PowerShell command to get all scheduled tasks
        cmd = 'Get-ScheduledTask | Select-Object TaskName, TaskPath, State, LastRunTime, NextRunTime'
        
        # Run the PowerShell command using subprocess
        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
        
        if result.returncode == 0:
            # Successfully retrieved the scheduled tasks, print them
            print("[DEBUG] Scheduled Tasks on Windows:\n")
            tasks = result.stdout.splitlines()

            suspicious_tasks = []

            # Filter out system tasks and look for potentially suspicious tasks
            for task in tasks:
                if ('AppData' in task or 'Temp' in task or 'C:\\Users' in task) and 'Microsoft' not in task:
                    # Only add task if it hasn't been sent before
                    if task not in sent_scheduled_tasks:
                        suspicious_tasks.append(task)
                        sent_scheduled_tasks.add(task)

            if suspicious_tasks:
                print(f"[DEBUG] Suspicious tasks found: {suspicious_tasks}", flush=True)
                # Send suspicious tasks data
                send_data_to_dashboard({
                    "details": "\n".join(suspicious_tasks),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }, is_scheduled_task=True, secret_key=SECRET_KEY)
            else:
                print("[DEBUG] No new suspicious tasks found on Windows.", flush=True)

        else:
            print(f"[ERROR] Failed to retrieve scheduled tasks. Error: {result.stderr}", flush=True)
            return False

        return True

    except Exception as e:
        print(f"[ERROR] An error occurred while retrieving scheduled tasks: {e}", flush=True)
        return False

def get_linux_scheduled_tasks():
    """
    Retrieves and checks for suspicious cron jobs for the current user on a Linux machine.
    """
    try:
        # Use crontab command to list scheduled cron jobs
        cmd = "crontab -l"
        
        # Run the crontab command using subprocess
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[DEBUG] Scheduled Cron Jobs on Linux:\n", flush=True)
            cron_jobs = result.stdout.splitlines()

            suspicious_cron_jobs = []

            # Filter out root/system cron jobs, look for user-level or suspicious cron jobs
            for cron_job in cron_jobs:
                if '/tmp/' in cron_job or '/var/tmp/' in cron_job or 'curl' in cron_job or 'wget' in cron_job:
                    # Only add cron job if it hasn't been sent before
                    if cron_job not in sent_scheduled_tasks:
                        suspicious_cron_jobs.append(cron_job)
                        sent_scheduled_tasks.add(cron_job)

            if suspicious_cron_jobs:
                print(f"[DEBUG] Suspicious cron jobs found: {suspicious_cron_jobs}", flush=True)
                # Send suspicious cron jobs data
                send_data_to_dashboard({
                    "details": "\n".join(suspicious_cron_jobs),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }, is_scheduled_task=True, secret_key=SECRET_KEY)
            else:
                print("[DEBUG] No new suspicious cron jobs found on Linux.", flush=True)

        else:
            print("[DEBUG] No cron jobs found or failed to retrieve cron jobs.", flush=True)
            return False

        return True

    except Exception as e:
        print(f"[ERROR] An error occurred while retrieving cron jobs: {e}", flush=True)
        return False

# ###################### Hosts File Check ###################### #

DEFAULT_HOSTS_ENTRIES = [
    "127.0.0.1",  # Localhost IPv4
    "::1",        # Localhost IPv6
    "localhost"
]

def check_hosts_file():
    """
    Checks the hosts file for non-default or suspicious entries on both Linux and Windows.
    """
    os_type = platform.system()
    hosts_path = ""

    if os_type == "Windows":
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    elif os_type == "Linux":
        hosts_path = "/etc/hosts"
    else:
        print(f"Unsupported operating system: {os_type}")
        return

    try:
        with open(hosts_path, 'r') as file:
            hosts_content = file.readlines()

        # Extract and clean each line (remove comments and blank lines)
        non_default_entries = []
        for line in hosts_content:
            line = line.strip()

            # Ignore comments and blank lines
            if line.startswith("#") or line == "":
                continue

            # Check if the line is a default entry
            if not any(default in line for default in DEFAULT_HOSTS_ENTRIES):
                non_default_entries.append(line)

        if non_default_entries:
            print("Non-default entries found in hosts file:\n", non_default_entries)
            # Send host file data to the dashboard, passing is_host_entry=True
            send_data_to_dashboard({
                "type": "hosts_file_check",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "details": "Non-default entries found in hosts file",
                "non_default_entries": non_default_entries
            }, is_host_entry=True, secret_key=SECRET_KEY)  # Ensure is_host_entry=True is passed

    except Exception as e:
        print(f"Error reading hosts file: {e}")

    except Exception as e:
        print(f"Error reading hosts file: {e}")

def periodically_check_hosts_file():
    """
    Periodically checks the hosts file for non-default entries.
    """
    while True:
        check_hosts_file()  # Check the hosts file
        time.sleep(300)  # Check every 5 minutes


if __name__ == "__main__":
    port_scan_thread = threading.Thread(target=port_scan_detection)
    smb_enum_thread = threading.Thread(target=smb_enum)
    scheduled_tasks_thread = threading.Thread(target=periodically_check_scheduled_tasks)
    hosts_file_check_thread = threading.Thread(target=periodically_check_hosts_file)
    suspicious_services_thread = threading.Thread(target=periodically_check_suspicious_services)

    port_scan_thread.start()
    smb_enum_thread.start()
    scheduled_tasks_thread.start()
    hosts_file_check_thread.start()
    suspicious_services_thread.start() 

    port_scan_thread.join()
    smb_enum_thread.join()
    scheduled_tasks_thread.join()
    hosts_file_check_thread.join()
    suspicious_services_thread.join()
