from flask import Flask, render_template, request, jsonify
import requests
import os
from dotenv import load_dotenv
import ipaddress

from db_ops import create_table, get_ip_data, save_ip_data, save_request_log
from time import time
from db_ops import cleanup_old_data
cleanup_old_data()

last_request = {}
# 🔥 Load env first
load_dotenv()

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
    ip = data.get('ip')

    # ✅ Validation
    try:
        valid_ip = str(ipaddress.ip_address(ip))
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

        result = {
            "ip": abuse_data.get("ipAddress", valid_ip),
            "risk_score": abuse_data.get("abuseConfidenceScore", 0),
            "country": abuse_data.get("countryCode", "N/A"),
            "isp": abuse_data.get("isp", "N/A"),
            "usage": abuse_data.get("usageType", "N/A"),
            "total_reports": abuse_data.get("totalReports", 0),
            "is_tor": abuse_data.get("isTor", False),
            "is_whitelisted": abuse_data.get("isWhitelisted", False),
            "hostnames": abuse_data.get("hostnames", []),
            "vt": vt_summary
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
    app.run(debug=False)