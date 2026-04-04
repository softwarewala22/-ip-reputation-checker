from flask import Flask, render_template, request, jsonify
import requests
import os
from dotenv import load_dotenv
import ipaddress
import pycountry

from db_ops import create_table, get_ip_data, save_ip_data, save_request_log
from vpncheck import check_proxycheck, check_ipqs
from time import time
from db_ops import cleanup_old_data

# 🔥 Load env first
load_dotenv()

# 🔥 First create tables
create_table()

# 🔥 Then cleanup
cleanup_old_data()

last_request = {}


ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__)

# 🔥 Create tables
create_table()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/check_ip', methods=['POST'])
def check_ip():
    data = request.get_json()
    check_vpn = data.get("check_vpn", False)
    print("[DEBUG] Checkbox VPN:", check_vpn)
    ip = data.get('ip', '').strip()

    # ✅ Validation
    try:
        valid_ip = str(ipaddress.ip_address(ip))

        ip_obj = ipaddress.ip_address(valid_ip)

        # 🔥 PRIVATE / INTERNAL / SPECIAL IP CHECK (IPv4 + IPv6)
        if (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_reserved or
            ip_obj.is_multicast or
            ip_obj.is_link_local
        ):
            return jsonify({
                "ip": valid_ip,
                "type": "internal",
                "message": "Internal/Reserved IP detected",
                "risk_score": 0,
                "country": "Local Network",
                "isp": "Internal"
            })
    
    except:
        return jsonify({"error": "Invalid IP"}), 400
    
        

    

    # 🔥 USER INFO
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get('User-Agent')

    # 🔥 CHECK CACHE FIRST
    cached = get_ip_data(valid_ip)
    if cached:
        print(f"[CACHE HIT] {valid_ip}")
        save_request_log(valid_ip, user_ip, user_agent)
        return jsonify(cached)

    try:
        # 🔥 ABUSEIPDB
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": valid_ip,
            "maxAgeInDays": 90
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            abuse_data = response.json().get('data', {})
            print(abuse_data)
            
            # 🌍 GEO LOCATION (ADD HERE)
            # 🌍 GEO LOCATION (DUAL API + REGION)
            city = "N/A"
            region = ""

            # 🔥 PRIMARY (ip-api)
            try:
                geo_url = f"http://ip-api.com/json/{valid_ip}?fields=status,city,regionName"
                geo_res = requests.get(geo_url, timeout=5)
                geo_json = geo_res.json()

                print("[GEO1]:", geo_json)

                if geo_json.get("status") == "success":
                    city = geo_json.get("city", "N/A")
                    region = geo_json.get("regionName", "")

            except Exception as e:
                print("[GEO1 ERROR]:", e)

            # 🔁 FALLBACK (ipapi)
            if city == "N/A" or not city:
                try:
                    geo_url2 = f"https://ipapi.co/{valid_ip}/json/"
                    geo_res2 = requests.get(geo_url2, timeout=5)
                    geo_json2 = geo_res2.json()

                    print("[GEO2]:", geo_json2)

                    city = geo_json2.get("city", "N/A")
                    region = geo_json2.get("region", "")

                except Exception as e:
                    print("[GEO2 ERROR]:", e)

        except:
            abuse_data = {}

        # 🔥 VIRUSTOTAL
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{valid_ip}"
        vt_headers = {
            "x-apikey": VT_API_KEY
        }

        try:
            vt_response = requests.get(vt_url, headers=vt_headers, timeout=5)
            vt_json = vt_response.json()
        except:
            vt_json = {}

        vt_results = vt_json.get("data", {}).get("attributes", {}).get("last_analysis_results") or {}

        malicious = 0
        suspicious = 0
        vendors = []

        for vendor, result in vt_results.items():
            if not isinstance(result, dict):
                continue

            category = result.get("category")

            if category == "malicious":
                malicious += 1
                vendors.append(vendor)

            elif category == "suspicious":
                suspicious += 1
                vendors.append(vendor)

        total = len(vt_results)

        vt_summary = {
            "total": total,
            "flagged_total": malicious + suspicious,
            "vendors": vendors[:5]
        }

# 🌍 COUNTRY FULL NAME FIX
        country_code = abuse_data.get("countryCode")

        try:
            country_obj = pycountry.countries.get(alpha_2=country_code)
            full_country = country_obj.name if country_obj else country_code
        except Exception as e:
            print("Country Error:", e)
            full_country = country_code or "N/A"
        print("DEBUG COUNTRY CODE:", abuse_data.get("countryCode"))
        print("DEBUG FULL COUNTRY:", full_country)
        
    # 🔥 VPN CHECK
        proxycheck_result  = check_proxycheck(valid_ip)

        ipqs_result = {}

        if check_vpn:
            ipqs_result = check_ipqs(valid_ip)

        # 🔥 COMBINE LOGIC (IMPORTANT FIX)
        vpn = proxycheck_result.get("vpn", False) or ipqs_result.get("vpn", False)
        proxy = proxycheck_result.get("proxy", False) or ipqs_result.get("proxy", False)
        tor = proxycheck_result.get("tor", False) or ipqs_result.get("tor", False)

    

        
     # 🔥 SCORING (VPN, pProxy, TOR)
        vpn_score = 0
        proxy_score = 0
        tor_score = 0

        # ProxyCheck
        if proxycheck_result.get("vpn"):
            vpn_score += 1

        if proxycheck_result.get("proxy"):
            proxy_score += 1


        # 🔥 IPQS
        if check_vpn and ipqs_result:
            ipqs = ipqs_result

            if ipqs.get("vpn"):
                vpn_score += 1

            if ipqs.get("proxy"):
                proxy_score += 1

            if ipqs.get("tor"):
                tor_score += 1

        # 🔥 ProxyCheck TOR (type based)
        if proxycheck_result.get("type") == "TOR":
            print("[VPN] ProxyCheck TOR detected")
            tor_score += 1

        # 🔥 AbuseIPDB TOR
        if abuse_data.get("isTor"):
            print("[VPN] AbuseIPDB TOR detected")
            tor_score += 1

        print("[VPN] FINAL SCORES:", vpn_score, proxy_score, tor_score)

        vpn_result = {
            "vpn": vpn,
            "proxy": proxy,
            "tor": tor,
            "ipqs": ipqs_result,
            "vpn_score": vpn_score,
            "proxy_score": proxy_score,
            "tor_score": tor_score
        }
        # ✅ NOW debug print
        print("[DEBUG] FINAL VPN RESULT:", vpn_result)

             
        result = {
            "ip": abuse_data.get("ipAddress", valid_ip),
            "risk_score": abuse_data.get("abuseConfidenceScore", 0),
            "country": full_country,
            # "country": geo_data.get("country", "N/A"),
            "city": f"{city}, {region}" if region else city,
            "isp": abuse_data.get("isp", "N/A"),
            "usage": abuse_data.get("usageType", "N/A"),
            "total_reports": abuse_data.get("totalReports", 0),
            "is_tor": abuse_data.get("isTor", False),
            "vpn_data": vpn_result,
            "is_whitelisted": abuse_data.get("isWhitelisted", False),
            "hostnames": abuse_data.get("hostnames", []),
            "vt": vt_summary,
              # 🔥 ADD HERE (INSIDE DICT)
            "copy_text": (
                f"IP belongs to ISP: {abuse_data.get('isp', 'N/A')}\n"
                f"City: {city + (', ' + region if region else '')}, Country: {full_country}\n"
                f"VPN: {'Yes' if vpn_result.get('vpn') else 'No'}, "
                f"Proxy: {'Yes' if vpn_result.get('proxy') else 'No'}, "
                f"TOR: {'Yes' if vpn_result.get('tor') else 'No'}")
        }

        

        # 🔥 SAVE TO DB
        save_ip_data(valid_ip, result)
        save_request_log(valid_ip, user_ip, user_agent)

        return jsonify(result)

    except Exception as e:
        print(f"[ERROR] {valid_ip}: {e}")
        return jsonify({
    "error": "API Erro! ⚠️ Service temporarily unavailable. Please try again later."
}), 503



if __name__ == '__main__':
    # app.run(debug=True)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)