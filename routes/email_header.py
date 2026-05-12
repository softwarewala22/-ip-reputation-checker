"""
routes/email_header.py — IPIntel.tech
Flask Blueprint for Email Header Analyzer.
Place this file inside your  routes/  folder.
"""

from flask import Blueprint, render_template, request, jsonify
import sys
import os

# allow import from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from mail_analyzer import analyze_headers

email_header_bp = Blueprint('email_header', __name__)


@email_header_bp.route('/email-header', methods=['GET', 'POST'])
def email_header_page():
    """
    GET  → render empty form
    POST (form submit) → kept for compatibility but we handle via AJAX below
    """
    return render_template('email_header.html')


@email_header_bp.route('/analyze-headers', methods=['POST'])
def analyze():
    """
    AJAX endpoint.
    Accepts JSON: { "headers": "<raw header string>" }
    Returns full analysis JSON.
    """
    try:
        body = request.get_json(force=True, silent=True) or {}
        raw  = body.get('headers', '').strip()

        if not raw:
            return jsonify({'error': 'No headers provided'}), 400

        if len(raw) > 150_000:
            return jsonify({'error': 'Headers too large (max 150 KB)'}), 400

        result = analyze_headers(raw)

        if 'error' in result:
            return jsonify(result), 422

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500
