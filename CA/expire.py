import requests

# URL của API (thay đổi localhost nếu cần)
url = "http://localhost:8000/keypair/expire-keypair/"

# Dữ liệu gửi đến API
data = {
    "verification_code_expire": "SI001"
}

# Gửi POST request
response = requests.post(url, json=data)

# Xử lý phản hồi
if response.status_code == 200:
    print("Success:", response.json())
else:
    print("Error:", response.json())
