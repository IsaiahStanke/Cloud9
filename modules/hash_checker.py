import requests

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
API_KEY = '9b0652630a34dfe2b474c969914fe3030b7055165dc04115f63fd41a1ea41c3c'

def check_hash(hash_value):
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
        else:
            print(f"Error: {response.status_code}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    hash_value = input("Enter the hash value to check: ")
    check_hash(hash_value)