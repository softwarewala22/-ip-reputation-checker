from flask import Blueprint, request, render_template
import urllib.parse

safelink_bp = Blueprint('safelink', __name__)

def remove_safelink(url):
    try:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        # 🔥 Defender SafeLinks
        if "url" in query:
            return urllib.parse.unquote(query["url"][0])

        # 🔥 Google Safe redirect
        if "q" in query:
            return urllib.parse.unquote(query["q"][0])

        # 🔥 Facebook redirect
        if "u" in query:
            return urllib.parse.unquote(query["u"][0])

        return url

    except:
        return url


@safelink_bp.route('/safelink-remover', methods=['GET', 'POST'])
def safelink_remover():
    cleaned_url = None
    input_url = ""

    if request.method == 'POST':
        input_url = request.form.get("input_url")

        if input_url:
            cleaned_url = remove_safelink(input_url)

    return render_template(
        "safelink.html",
        cleaned_url=cleaned_url,
        input_url=input_url
    )