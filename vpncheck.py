import requests
import os
from dotenv import load_dotenv

load_dotenv()

PROXYCHECK_API_KEY = os.getenv("PROXYCHECK_API_KEY")
IPQS_API_KEY = os.getenv("IPQS_API_KEY")


# 🔥 PROXYCHECK (PRIMARY - PROXY BASED)
def check_proxycheck(ip):
    print("[VPN] ProxyCheck start")
    # print("Prxycheck api key", PROXYCHECK_API_KEY)

    try:
        url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_API_KEY}&vpn=1"
        res = requests.get(url, timeout=5)
        data = res.json()

        print("[VPN] ProxyCheck response:", data)

        ip_data = data.get(ip, {})

        proxy = ip_data.get("proxy")
        type_ = ip_data.get("type")

        print("[VPN] Parsed ProxyCheck:", proxy, type_)

        # 🔥 LOGIC
        if proxy == "yes":
            return {
                "vpn": True,    # treat proxy as vpn
                "proxy": True,
                "tor": False,   # v2 does not provide TOR
                "type": type_ or "Proxy"
            }

        return {
            "vpn": False,
            "proxy": False,
            "tor": False
        }

    except Exception as e:
        print("[VPN ERROR] ProxyCheck failed:", e)
        return {
            "vpn": False,
            "proxy": False,
            "tor": False
        }


# 🔥 IPQUALITYSCORE (OPTIONAL - ADVANCED DETECTION)
def check_ipqs(ip):
    print("[VPN] IPQS start")
    # print("IPQS KEY:", IPQS_API_KEY)

    try:
        url = f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}"
        res = requests.get(url, timeout=5)
        data = res.json()

        print("[VPN] IPQS response:", data)

        return {
            "vpn": data.get("vpn", False),
            "proxy": data.get("proxy", False),
            "tor": data.get("tor", False),
            "fraud_score": data.get("fraud_score", 0)
        }

    except Exception as e:
        print("[VPN ERROR] IPQS failed:", e)
        return {
            "vpn": False,
            "proxy": False,
            "tor": False,
            "fraud_score": 0
        }