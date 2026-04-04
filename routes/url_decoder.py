from flask import Blueprint, request, render_template
import urllib.parse

url_decoder_bp = Blueprint('url_decoder', __name__)

@url_decoder_bp.route('/url-decoder', methods=['GET', 'POST'])
def url_decoder():
    decoded_url = None
    error = None
    encoded_url = ""   # ✅ always initialize

    def multi_decode(url, times=3):
        for _ in range(times):
            url = urllib.parse.unquote(url)
        return url

    if request.method == 'POST':
        encoded_url = request.form.get('encoded_url', "").strip()

        if not encoded_url:
            error = "Please enter a URL"
        else:
            try:
                decoded_url = multi_decode(encoded_url)
            except Exception:
                error = "Invalid URL"

    return render_template(
        'url_decoder.html',
        decoded_url=decoded_url,
        error=error,
        encoded_url=encoded_url
    )