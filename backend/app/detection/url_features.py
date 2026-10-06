"""
CYBERNEXUS SOC - Python URL Feature Extractor
Safe deterministic string parsing without network calls.
"""
import re
import math
from urllib.parse import urlparse, parse_qs

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'update',
    'account', 'password', 'confirm', 'wallet', 'invoice', 'bank', 'support'
]

SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly']

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    frequencies = {}
    for c in s:
        frequencies[c] = frequencies.get(c, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def is_ip_address(host: str) -> bool:
    ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if re.match(ipv4_pattern, host):
        parts = host.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False

def extract_url_features(raw_url: str) -> dict:
    normalized = raw_url.strip()
    if not re.match(r'^https?://', normalized, re.IGNORECASE):
        normalized = 'http://' + normalized

    try:
        parsed = urlparse(normalized)
        host = (parsed.hostname or '').lower()
    except Exception:
        return {
            'url': raw_url,
            'host_is_ip': False,
            'subdomain_count': 0,
            'url_length': len(raw_url),
            'contains_at': '@' in raw_url,
            'suspicious_keywords': [],
            'is_punycode': 'xn--' in raw_url,
            'entropy': calculate_entropy(raw_url)
        }

    host_is_ip = is_ip_address(host)
    parts = host.split('.')
    subdomain_count = max(0, len(parts) - 2) if not host_is_ip else 0
    url_lower = raw_url.lower()
    keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

    return {
        'url': raw_url,
        'domain': host,
        'is_https': parsed.scheme.lower() == 'https',
        'host_is_ip': host_is_ip,
        'subdomain_count': subdomain_count,
        'url_length': len(raw_url),
        'contains_at': '@' in raw_url,
        'hyphen_count': raw_url.count('-'),
        'is_punycode': 'xn--' in host,
        'is_shortener': any(host == s or host.endswith('.' + s) for s in SHORTENER_DOMAINS),
        'suspicious_keywords': keywords,
        'entropy': calculate_entropy(host + parsed.path)
    }
