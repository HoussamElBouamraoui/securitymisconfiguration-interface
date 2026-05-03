import requests
import json

# Test the scan API
url = "http://127.0.0.1:8000/auth/token"
response = requests.get(url)
token_data = response.json()
token = token_data["token"]

print(f"Got token: {token[:20]}...")

# Test scan
scan_url = "http://127.0.0.1:8000/scan"
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {token}"
}
data = {
    "target": "https://cryptomh.vercel.app"
}

try:
    response = requests.post(scan_url, headers=headers, json=data, timeout=30)
    print(f"Status code: {response.status_code}")
    print(f"Response: {response.text[:500]}...")
    
    if response.status_code == 200:
        result = response.json()
        print(f"Scan ID: {result.get('scan_id')}")
        print(f"Status: {result.get('status')}")
    else:
        print(f"Error response: {response.text}")
        
except Exception as e:
    print(f"Exception: {e}")
