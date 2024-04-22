import hashlib
import requests
import time
from scapy.all import *


API_KEY = '9b0652630a34dfe2b474c969914fe3030b7055165dc04115f63fd41a1ea41c3c'

# Function to calculate file hash
def calculate_hash(data, hash_algo='sha256'):
    hash_func = hashlib.new(hash_algo)
    hash_func.update(data)
    return hash_func.hexdigest()

# Function to check hash using VirusTotal API
def check_hash_virustotal(hash_value):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {'x-apikey': API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            if 'data' in json_response:
                data = json_response['data']
                if 'attributes' in data:
                    attributes = data['attributes']
                    print(f"Hash: {hash_value}")
                    
                    if 'last_analysis_stats' in attributes:
                        stats = attributes['last_analysis_stats']
                        if stats.get('malicious') is not None:
                            print(f"Detected by {stats['malicious']} engines as malicious.")
                        else:
                            print("No malware detected.")
                    else:
                        print("No analysis statistics available.")
                    print(f"Link: {data['links']['self']}")
                else:
                    print("No data found for this hash.")
            else:
                print("No data found for this hash.")
        elif response.status_code == 404:
            print("No data found for this hash.")
        else:
            print(f"Error: {response.status_code}")
    except Exception as e:
        print(f"An error occurred: {e}")


# Function to extract files from network packets
def extract_files(packet):
    if packet.haslayer(Raw):
        data = bytes(packet[Raw])
        if data:
            # Calculate file hash
            file_hash = calculate_hash(data)
            print("Hash of extracted file:", file_hash)
            # Check hash using VirusTotal API
            check_hash_virustotal(file_hash)
            # Do further processing if needed

# Main function to listen to network traffic
def listen_to_traffic(packet_count):
    sniff(count=packet_count, prn=extract_files)


if __name__ == "__main__":
    packet_count = 100  # Number of packets to capture
    listen_to_traffic(packet_count)
