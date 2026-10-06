"""
CYBERNEXUS SOC - Python Risk Scoring Engine
Explainable deterministic 0-100 scoring.
"""
from typing import Dict, Any, List

def calculate_risk_score(features: Dict[str, Any], ti_reputation: str = "UNKNOWN") -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    signals: List[Dict[str, Any]] = []

    if features.get('host_is_ip'):
        score += 30
        reasons.append("Raw IP hostname detected")
        signals.append({"name": "RAW_IP_HOSTNAME", "weight": 30, "category": "STRUCTURAL"})

    if features.get('contains_at'):
        score += 25
        reasons.append('Contains "@" credential-delimiter symbol')
        signals.append({"name": "CONTAINS_AT", "weight": 25, "category": "STRUCTURAL"})

    if features.get('is_punycode'):
        score += 25
        reasons.append("Punycode / homograph spoofing detected")
        signals.append({"name": "PUNYCODE", "weight": 25, "category": "HEURISTIC"})

    kw = features.get('suspicious_keywords', [])
    if kw:
        weight = min(30, len(kw) * 10)
        score += weight
        reasons.append(f"Suspicious auth keywords found ({', '.join(kw)})")
        signals.append({"name": "AUTH_KEYWORDS", "weight": weight, "category": "HEURISTIC"})

    if not features.get('is_https') and kw:
        score += 20
        reasons.append("Plain HTTP protocol used on authentication target")
        signals.append({"name": "INSECURE_AUTH", "weight": 20, "category": "STRUCTURAL"})

    if features.get('subdomain_count', 0) >= 3:
        score += 15
        reasons.append(f"Excessive subdomain hierarchy ({features.get('subdomain_count')} subdomains)")
        signals.append({"name": "EXCESSIVE_SUBDOMAINS", "weight": 15, "category": "STRUCTURAL"})

    if features.get('url_length', 0) > 100:
        score += 10
        reasons.append("Anomalous URL length")
        signals.append({"name": "LONG_URL", "weight": 10, "category": "STRUCTURAL"})

    if ti_reputation == "MALICIOUS":
        score += 35
        reasons.append("Threat intelligence confirms malicious reputation")
        signals.append({"name": "TI_MALICIOUS", "weight": 35, "category": "INTEL"})

    final_score = min(100, max(0, score))
    if final_score >= 75:
        severity = "CRITICAL"
    elif final_score >= 50:
        severity = "HIGH"
    elif final_score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score": final_score,
        "severity": severity,
        "reasons": reasons,
        "signals": signals,
        "explanation": f"Score of {final_score}/100 ({severity}) calculated from {len(signals)} signals."
    }
