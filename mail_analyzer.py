"""
mail_analyzer.py — IPIntel.tech
Full email header analysis & spoof detection engine.
Place in project root alongside app.py
"""

import re
import socket
import ipaddress
from email import message_from_string
from email.utils import parsedate_to_datetime
from email.header import decode_header


# ── HELPERS ──────────────────────────────────────────────────────

def safe_ip(s):
    try:
        m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', s or '')
        if m:
            return str(ipaddress.ip_address(m.group(1)))
    except Exception:
        pass
    return None


def extract_domain(addr):
    m = re.search(r'@([\w.\-]+)', addr or '')
    return m.group(1).lower() if m else None


def rdns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None




def decode_mime_header(value):
    """
    Decode MIME encoded-word headers like:
    =?UTF-8?Q?Tech3_|_India=E2=80=99s_3-hour_takedown...?=
    
    Returns plain text string.
    """
    if not value:
        return value
    try:
        decoded_parts = decode_header(value)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(encoding or 'utf-8', errors='replace'))
            else:
                result.append(part)
        return ''.join(result)
    except Exception:
        return value  # return as-is if decode fails


def base_domain(d):
    if not d:
        return ''
    parts = d.lower().strip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else d.lower()


def domains_match(d1, d2):
    return bool(d1 and d2 and base_domain(d1) == base_domain(d2))


# ── HEADER PARSERS ────────────────────────────────────────────────

def parse_received_chain(msg):
    received = msg.get_all('Received') or []
    hops = []
    for raw in received:
        hop = {'raw': raw.strip()}

        m = re.search(r'from\s+([\S]+)', raw, re.I)
        if m:
            hop['from_host'] = m.group(1)

        m = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', raw)
        if not m:
            m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', raw)
        if m:
            hop['ip'] = m.group(1)

        m = re.search(r'by\s+([\S]+)', raw, re.I)
        if m:
            hop['by_host'] = m.group(1).rstrip(';')

        m = re.search(r';\s*(.+)$', raw.strip())
        if m:
            hop['timestamp_raw'] = m.group(1).strip()
            try:
                hop['timestamp'] = parsedate_to_datetime(hop['timestamp_raw']).isoformat()
            except Exception:
                hop['timestamp'] = None

        if hop.get('ip'):
            hop['rdns'] = rdns_lookup(hop['ip'])
            try:
                ip_obj = ipaddress.ip_address(hop['ip'])
                hop['ip_type'] = (
                    'loopback'  if ip_obj.is_loopback else
                    'private'   if ip_obj.is_private  else
                    'public'
                )
            except Exception:
                hop['ip_type'] = 'unknown'

        hops.append(hop)
    return hops


def parse_auth_results(msg):
    headers = msg.get_all('Authentication-Results') or []
    results = {'spf': None, 'dkim': None, 'dmarc': None, 'raw': []}
    for h in headers:
        results['raw'].append(h.strip())
        for proto in ['spf', 'dkim', 'dmarc']:
            m = re.search(rf'{proto}=(\S+)', h, re.I)
            if m and results[proto] is None:
                results[proto] = m.group(1).lower().rstrip(';,')
    return results


def parse_dkim_signatures(msg):
    sigs = msg.get_all('DKIM-Signature') or []
    out = []
    for s in sigs:
        d   = re.search(r'\bd=([^;]+)', s)
        sel = re.search(r'\bs=([^;]+)', s)
        a   = re.search(r'\ba=([^;]+)', s)
        out.append({
            'domain':    d.group(1).strip()   if d   else None,
            'selector':  sel.group(1).strip() if sel else None,
            'algorithm': a.group(1).strip()   if a   else None,
        })
    return out


def extract_all_ips(msg):
    """Collect all public IPs from Received headers + X-Originating-IP."""
    ips = []
    seen = set()
    for raw in (msg.get_all('Received') or []):
        for m in re.finditer(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', raw):
            ip = m.group(1)
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and not ip_obj.is_loopback and ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
            except Exception:
                pass
    xi = msg.get('X-Originating-IP', '')
    ip = safe_ip(xi)
    if ip and ip not in seen:
        ips.append(ip)
    return ips


# ── SPOOF SCORE ENGINE ────────────────────────────────────────────

def compute_spoof_score(data):
    score   = 0
    signals = []
    auth    = data['auth_results']

    from_domain   = data['from_domain']
    reply_domain  = data['reply_to_domain']
    return_domain = data['return_path_domain']
    sender_domain = data['sender_domain']
    hops          = data['received_hops']

    # ── SPF ──
    spf = auth.get('spf')
    if not spf:
        score += 15
        signals.append({'type': 'warn',   'label': 'SPF missing',        'detail': 'No SPF result in Authentication-Results'})
    elif spf in ('fail', 'hardfail', 'softfail'):
        score += 30 if spf != 'softfail' else 15
        signals.append({'type': 'danger', 'label': f'SPF {spf.upper()}', 'detail': 'Sending server is not authorised to send for this domain'})
    elif spf == 'neutral':
        score += 10
        signals.append({'type': 'warn',   'label': 'SPF neutral',        'detail': 'Domain has no SPF enforcement policy'})
    else:
        signals.append({'type': 'ok',     'label': 'SPF pass',           'detail': 'Sending server is authorised to send for this domain'})

    # ── DKIM ──
    dkim = auth.get('dkim')
    if not dkim:
        score += 15
        signals.append({'type': 'warn',   'label': 'DKIM missing',       'detail': 'No DKIM result found — message may be unsigned'})
    elif dkim in ('fail', 'invalid', 'permerror', 'temperror'):
        score += 30
        signals.append({'type': 'danger', 'label': f'DKIM {dkim.upper()}','detail': 'DKIM signature is invalid or the message was tampered with'})
    else:
        signals.append({'type': 'ok',     'label': 'DKIM pass',          'detail': 'Message signature is cryptographically verified'})

    # ── DMARC ──
    dmarc = auth.get('dmarc')
    if not dmarc:
        score += 10
        signals.append({'type': 'warn',   'label': 'DMARC missing',      'detail': 'No DMARC result found'})
    elif dmarc in ('fail', 'reject', 'quarantine'):
        score += 20
        signals.append({'type': 'danger', 'label': f'DMARC {dmarc.upper()}', 'detail': 'Email failed DMARC alignment policy'})
    else:
        signals.append({'type': 'ok',     'label': 'DMARC pass',         'detail': 'Email is aligned with domain DMARC policy'})

    # ── Reply-To mismatch (classic phishing) ──
    if reply_domain and from_domain and not domains_match(reply_domain, from_domain):
        score += 25
        signals.append({'type': 'danger', 'label': 'Reply-To mismatch',
            'detail': f'From: {from_domain}  →  Reply-To: {reply_domain} — responses go to a different domain (classic phishing)'})

    # ── Return-Path mismatch ──
    if return_domain and from_domain and not domains_match(return_domain, from_domain):
        score += 15
        signals.append({'type': 'warn',   'label': 'Return-Path mismatch',
            'detail': f'Envelope sender ({return_domain}) differs from From domain ({from_domain})'})

    # ── Sender header mismatch ──
    if sender_domain and from_domain and not domains_match(sender_domain, from_domain):
        score += 10
        signals.append({'type': 'warn',   'label': 'Sender header mismatch',
            'detail': f'Sender: {sender_domain}  ≠  From: {from_domain}'})

    # ── No Received chain ──
    if not hops:
        score += 20
        signals.append({'type': 'warn',   'label': 'No Received chain',
            'detail': 'No Received headers found — headers may have been manually crafted or stripped'})
    else:
        # ── Originating rDNS vs From domain ──
        first_pub = next((h for h in reversed(hops) if h.get('ip_type') == 'public'), None)
        if first_pub and from_domain:
            rdns = first_pub.get('rdns') or ''
            if rdns and not domains_match(rdns, from_domain):
                score += 10
                signals.append({'type': 'info',  'label': 'Origin rDNS mismatch',
                    'detail': f'Originating IP reverse DNS ({rdns}) does not match From domain ({from_domain})'})

    # ── No DKIM-Signature header ──
    if not data.get('dkim_signatures'):
        if score < 40:
            score += 5
        signals.append({'type': 'info',   'label': 'No DKIM-Signature header',
            'detail': 'The message was not signed with DKIM'})

    score = min(score, 100)

    if score >= 70:
        verdict, verdict_class = 'HIGH RISK',   'danger'
    elif score >= 40:
        verdict, verdict_class = 'SUSPICIOUS',  'warn'
    elif score >= 15:
        verdict, verdict_class = 'LOW RISK',    'info'
    else:
        verdict, verdict_class = 'CLEAN',       'ok'

    return score, verdict, verdict_class, signals


# ── MAIN ENTRY ────────────────────────────────────────────────────

def analyze_headers(raw: str) -> dict:
    if not raw or not raw.strip():
        return {'error': 'No headers provided'}

    if '\n\n' not in raw:
        raw += '\n\n'

    try:
        msg = message_from_string(raw)
    except Exception as e:
        return {'error': f'Parse failed: {e}'}

    from_raw          = msg.get('From', '')
    to_raw            = msg.get('To', '')
    reply_to_raw      = msg.get('Reply-To', '')
    return_path_raw   = msg.get('Return-Path', '')
    sender_raw        = msg.get('Sender', '')
    subject           = decode_mime_header(msg.get('Subject', ''))
    date_raw          = msg.get('Date', '')
    message_id        = msg.get('Message-ID', '')
    x_mailer          = msg.get('X-Mailer', '') or msg.get('User-Agent', '')
    x_originating_ip  = msg.get('X-Originating-IP', '')
    x_spam_status     = msg.get('X-Spam-Status', '')
    x_spam_score      = msg.get('X-Spam-Score', '')
    mime_version      = msg.get('MIME-Version', '')
    content_type      = msg.get('Content-Type', '')
    x_priority        = msg.get('X-Priority', '') or msg.get('Importance', '')

    from_domain    = extract_domain(from_raw)
    reply_domain   = extract_domain(reply_to_raw)
    return_domain  = extract_domain(return_path_raw)
    sender_domain  = extract_domain(sender_raw)

    date_parsed = None
    try:
        date_parsed = parsedate_to_datetime(date_raw).isoformat() if date_raw else None
    except Exception:
        pass

    hops            = parse_received_chain(msg)
    auth_results    = parse_auth_results(msg)
    dkim_signatures = parse_dkim_signatures(msg)
    all_ips         = extract_all_ips(msg)

    originating_ip = safe_ip(x_originating_ip)
    if not originating_ip and hops:
        for h in reversed(hops):
            if h.get('ip') and h.get('ip_type') == 'public':
                originating_ip = h['ip']
                break

    data = {
        'from_raw':            from_raw,
        'from_domain':         from_domain,
        'to_raw':              to_raw,
        'reply_to_raw':        reply_to_raw,
        'reply_to_domain':     reply_domain,
        'return_path_raw':     return_path_raw,
        'return_path_domain':  return_domain,
        'sender_raw':          sender_raw,
        'sender_domain':       sender_domain,
        'subject':             subject,
        'date_raw':            date_raw,
        'date_parsed':         date_parsed,
        'message_id':          message_id,
        'x_mailer':            x_mailer,
        'x_originating_ip':    originating_ip,
        'x_spam_status':       x_spam_status,
        'x_spam_score':        x_spam_score,
        'mime_version':        mime_version,
        'content_type':        content_type,
        'x_priority':          x_priority,
        'received_hops':       hops,
        'auth_results':        auth_results,
        'dkim_signatures':     dkim_signatures,
        'all_ips':             all_ips,
        'hop_count':           len(hops),
    }

    score, verdict, verdict_class, signals = compute_spoof_score(data)
    data['spoof_score']   = score
    data['verdict']       = verdict
    data['verdict_class'] = verdict_class
    data['signals']       = signals

    return data
