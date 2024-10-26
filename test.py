import requests
import json

# Set the URL and API key
url = 'https://192.168.1.121:5000/data'
headers = {
    'Content-Type': 'application/json',
    'x-api-key': '772a97281008478a1e13d078d477ccf5d5818e3134f02cea1e8a0ce7c10a80f2'
}

# Create the data you want to send
data = {
    "detection_type": "test_detection",
    "details": "Test port scan detected",
    "src_ip": "192.168.1.100",
    "dst_ip": "192.168.1.101",
    "ports_scanned": [80, 443],
    "timestamp": "2024-10-20 00:47:01",
    "message": "Test port scan detected"
}

# Send the POST request
response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)

# Print the response from the server
print("Status Code:", response.status_code)
print("Response Text:", response.text)
