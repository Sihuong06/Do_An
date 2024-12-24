import requests

url = "http://localhost:8000/keypair/generate-keypair/"
data = {
    "verification_code": "SI001",
    "algorithm": "RSA",
    "bit_size": 2048
}
response = requests.post(url, json=data)

if response.status_code == 201:
    print("Success:", response.json())
else:
    print("Error:", response.json())
