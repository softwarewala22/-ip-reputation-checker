# import requests

# API_KEY = "a8a8893b5da83d2959309cd7473024864ebdad2cd0a2f1e9e22a0aeccb5756aafe665ac9d90ab6a9"



# url = "https://api.abuseipdb.com/api/v2/check"

# headers = {
#     "Key": API_KEY,
#     "Accept": "application/json"
# }

# params = {
#     "ipAddress": "189.8.8.8",
#     "maxAgeInDays": 90
# }

# response = requests.get(url, headers=headers, params=params)

# print("Status Code:", response.status_code)
# print("Response:", response.json())

#for virus total

# import requests

# API_KEY = "c5bd3dba3d6819a738b3b983555ca0b879ba3eb73a0d943bc8063ec0f09c39ab"
# ip = "8.8.8.8"

# url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# headers = {
#     "x-apikey": API_KEY
# }

# response = requests.get(url, headers=headers)

# print(response.json())
import requests
import os

PROXYCHECK_API_KEY = os.getenv("PROXYCHECK_API_KEY")
IPQS_API_KEY = os.getenv("IPQS_API_KEY")


def check_proxycheck(ip):
    print("[VPN] ProxyCheck start")
    url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_API_KEY}&vpn=1"
    res = requests.get(url, timeout=5)
    data = res.json()

    print("[VPN] ProxyCheck response:", data)
    
    
check_proxycheck("191.97.96.244")