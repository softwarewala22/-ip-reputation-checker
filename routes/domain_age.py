from flask import Blueprint, request, render_template
import whois
import requests
import os
from datetime import datetime

domain_age_bp = Blueprint('domain_age', __name__)

VT_API_KEY = os.getenv("VT_API_KEY")  # 🔥 put in .env


# 🔥 FORMAT FUNCTION (FIXED)
def format_domain_age(created_date):
    if isinstance(created_date, list):
        created_date = created_date[0]

    if not created_date:
        return None, None, None

    # ✅ timezone fix
    if created_date.tzinfo:
        today = datetime.now(created_date.tzinfo)
    else:
        today = datetime.now()

    total_days = (today - created_date).days

    years = total_days // 365
    months = (total_days % 365) // 30
    days = (total_days % 365) % 30

    is_risky = total_days < 180

    pretty_date = created_date.strftime("%A %d %B %Y")
    age_text = f"{years} years, {months} months and {days} days"

    return pretty_date, age_text, is_risky


# 🔥 VIRUSTOTAL FALLBACK
def get_vt_creation_date(domain):
    try:
        print("[VT] Trying fallback...")

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "x-apikey": VT_API_KEY
        }

        res = requests.get(url, headers=headers, timeout=5)
        data = res.json()

        print("[VT RESPONSE]", data)

        vt_ts = data.get("data", {}).get("attributes", {}).get("creation_date")

        if vt_ts:
            return datetime.fromtimestamp(vt_ts)

    except Exception as e:
        print("[VT ERROR]", e)

    return None


# 🔥 ROUTE
@domain_age_bp.route('/domain-age', methods=['GET', 'POST'])
def domain_age():
    domain_input = ""
    pretty_date = None
    age_text = None
    is_risky = None
    error = None

    if request.method == "POST":
        domain_input = request.form.get("domain")

        created = None

        # 🔥 1️⃣ TRY WHOIS
        try:
            w = whois.whois(domain_input)
            created = w.creation_date

            if isinstance(created, list):
                created = created[0]

            print("[WHOIS CREATED]", created)

        except Exception as e:
            print("[WHOIS FAILED]", e)

        # 🔥 2️⃣ FALLBACK → VIRUSTOTAL
        if not created:
            print("VT domain checking")
            created = get_vt_creation_date(domain_input)

        # 🔥 FINAL PROCESS
        if created:
            pretty_date, age_text, is_risky = format_domain_age(created)
            error = None
        else:
            error = "Unable to fetch domain age (WHOIS & VT failed)"

    return render_template(
        "domain_age.html",
        domain_input=domain_input,
        pretty_date=pretty_date,
        age_text=age_text,
        is_risky=is_risky,
        error=error
    )