"""
Automated Unit Tests for CYBERNEXUS SOC Detection & Scoring Engines
"""
import sys
import os

# Ensure backend/ is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.detection.url_features import extract_url_features
from app.detection.scoring import calculate_risk_score

def test_url_feature_extraction_phishing():
    url = "http://login.secure-sso.verify-portal.account-update.test/auth/login?user=jdoe"
    features = extract_url_features(url)

    assert features['is_https'] is False
    assert features['subdomain_count'] >= 3
    assert 'login' in features['suspicious_keywords']
    assert 'secure' in features['suspicious_keywords']
    assert 'update' in features['suspicious_keywords']
    assert features['contains_at'] is False

def test_url_feature_extraction_punycode():
    url = "http://xn--gogle-pra.test/login"
    features = extract_url_features(url)

    assert features['is_punycode'] is True
    assert 'login' in features['suspicious_keywords']

def test_url_feature_extraction_ip_host():
    url = "http://198.51.100.45:8080/bank/verify"
    features = extract_url_features(url)

    assert features['host_is_ip'] is True
    assert 'verify' in features['suspicious_keywords']

def test_risk_scoring_critical_phish():
    features = {
        'host_is_ip': False,
        'contains_at': False,
        'is_punycode': False,
        'suspicious_keywords': ['login', 'secure', 'update'],
        'is_https': False,
        'subdomain_count': 4,
        'url_length': 120,
    }
    result = calculate_risk_score(features, ti_reputation="MALICIOUS")

    assert result['score'] >= 75
    assert result['severity'] == "CRITICAL"
    assert len(result['reasons']) >= 4

def test_risk_scoring_benign_corporate():
    features = {
        'host_is_ip': False,
        'contains_at': False,
        'is_punycode': False,
        'suspicious_keywords': [],
        'is_https': True,
        'subdomain_count': 1,
        'url_length': 45,
    }
    result = calculate_risk_score(features, ti_reputation="BENIGN")

    assert result['score'] < 25
    assert result['severity'] == "LOW"

if __name__ == '__main__':
    test_url_feature_extraction_phishing()
    test_url_feature_extraction_punycode()
    test_url_feature_extraction_ip_host()
    test_risk_scoring_critical_phish()
    test_risk_scoring_benign_corporate()
    print("ALL TESTS PASSED SUCCESSFULLY!")
