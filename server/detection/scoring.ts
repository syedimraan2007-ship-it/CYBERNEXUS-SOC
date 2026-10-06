/**
 * CYBERNEXUS SOC - Deterministic Explainable Risk Scoring Engine
 * Calculates 0-100 score with exact contributing signals, weights, and transparent explanations.
 */

import { RiskScoreResult, RiskSignal, Severity, UrlFeatures, ThreatIntelEnrichment } from '../../src/types/soc';

export function calculateRiskScore(
  features?: UrlFeatures,
  tiEnrichment?: ThreatIntelEnrichment,
  additionalRuleWeights?: { rule: string; weight: number; description: string }[]
): RiskScoreResult {
  const signals: RiskSignal[] = [];
  const reasons: string[] = [];
  let totalScore = 0;

  if (features) {
    if (features.hostIsIp) {
      signals.push({
        name: 'RAW_IP_HOSTNAME',
        scoreContribution: 30,
        category: 'STRUCTURAL',
        description: 'URL uses a raw IP address instead of a domain name, common in malicious direct routing.',
      });
      reasons.push('Raw IP hostname detected');
      totalScore += 30;
    }

    if (features.containsAtSymbol) {
      signals.push({
        name: 'CONTAINS_AT_SYMBOL',
        scoreContribution: 25,
        category: 'STRUCTURAL',
        description: 'URL contains "@" symbol, which can mislead users regarding actual target destination.',
      });
      reasons.push('Contains "@" credential-delimiter symbol');
      totalScore += 25;
    }

    if (features.isPunycode) {
      signals.push({
        name: 'PUNYCODE_DETECTED',
        scoreContribution: 25,
        category: 'HEURISTIC',
        description: 'Punycode (xn--) internationalized domain detected, frequently used in homograph spoofing.',
      });
      reasons.push('Punycode / homograph spoofing signal detected');
      totalScore += 25;
    }

    if (features.suspiciousKeywordsFound.length > 0) {
      const kwWeight = Math.min(30, features.suspiciousKeywordsFound.length * 10);
      signals.push({
        name: 'SUSPICIOUS_AUTH_KEYWORDS',
        scoreContribution: kwWeight,
        category: 'HEURISTIC',
        description: `URL contains targeted authentication/financial terms: ${features.suspiciousKeywordsFound.join(', ')}.`,
      });
      reasons.push(`Suspicious authentication keywords found (${features.suspiciousKeywordsFound.join(', ')})`);
      totalScore += kwWeight;
    }

    if (!features.isHttps && features.suspiciousKeywordsFound.length > 0) {
      signals.push({
        name: 'INSECURE_AUTH_CHANNEL',
        scoreContribution: 20,
        category: 'STRUCTURAL',
        description: 'Plain HTTP protocol used on authentication-related link.',
      });
      reasons.push('Plain HTTP protocol used on authentication target');
      totalScore += 20;
    }

    if (features.subdomainCount >= 3) {
      const subWeight = features.subdomainCount >= 5 ? 20 : 12;
      signals.push({
        name: 'EXCESSIVE_SUBDOMAINS',
        scoreContribution: subWeight,
        category: 'STRUCTURAL',
        description: `High number of subdomain layers (${features.subdomainCount}) often used to mimic trusted hostnames.`,
      });
      reasons.push(`Excessive subdomain hierarchy (${features.subdomainCount} subdomains)`);
      totalScore += subWeight;
    }

    if (features.urlLength > 100) {
      const lenWeight = features.urlLength > 150 ? 15 : 10;
      signals.push({
        name: 'ANOMALOUS_URL_LENGTH',
        scoreContribution: lenWeight,
        category: 'STRUCTURAL',
        description: `Unusually long URL length (${features.urlLength} characters).`,
      });
      reasons.push(`Anomalous URL length (${features.urlLength} characters)`);
      totalScore += lenWeight;
    }

    if (features.hyphenCount >= 3) {
      signals.push({
        name: 'EXCESSIVE_HYPHENS',
        scoreContribution: 10,
        category: 'HEURISTIC',
        description: `Multiple hyphens (${features.hyphenCount}) used in hostname/path to deceive visual inspection.`,
      });
      reasons.push(`Excessive hyphens in URL string (${features.hyphenCount} hyphens)`);
      totalScore += 10;
    }

    if (features.isShortener) {
      signals.push({
        name: 'URL_SHORTENER_OBFUSCATION',
        scoreContribution: 15,
        category: 'HEURISTIC',
        description: 'URL shortening service conceals true landing destination.',
      });
      reasons.push('URL shortening service conceals true destination');
      totalScore += 15;
    }

    if (features.entropy > 4.2) {
      signals.push({
        name: 'HIGH_LEXICAL_ENTROPY',
        scoreContribution: 12,
        category: 'HEURISTIC',
        description: `High character randomness/entropy (${features.entropy.toFixed(2)}) indicates randomized domain or path.`,
      });
      reasons.push(`High lexical entropy (${features.entropy.toFixed(2)})`);
      totalScore += 12;
    }
  }

  if (tiEnrichment) {
    if (tiEnrichment.overallReputation === 'MALICIOUS') {
      signals.push({
        name: 'THREAT_INTEL_MALICIOUS_REPUTATION',
        scoreContribution: 35,
        category: 'INTEL',
        description: 'Threat intelligence providers marked this indicator with verified malicious reputation.',
      });
      reasons.push('Threat intelligence confirms malicious reputation');
      totalScore += 35;
    } else if (tiEnrichment.overallReputation === 'SUSPICIOUS') {
      signals.push({
        name: 'THREAT_INTEL_SUSPICIOUS_REPUTATION',
        scoreContribution: 18,
        category: 'INTEL',
        description: 'Threat intelligence providers flagged anomalous or suspicious behavior.',
      });
      reasons.push('Threat intelligence flags suspicious reputation');
      totalScore += 18;
    }
  }

  if (additionalRuleWeights) {
    for (const rule of additionalRuleWeights) {
      signals.push({
        name: rule.rule,
        scoreContribution: rule.weight,
        category: 'BEHAVIORAL',
        description: rule.description,
      });
      reasons.push(rule.description);
      totalScore += rule.weight;
    }
  }

  // Cap normalized score to [0, 100]
  const finalScore = Math.min(100, Math.max(0, totalScore));

  let severity: Severity = 'LOW';
  if (finalScore >= 75) {
    severity = 'CRITICAL';
  } else if (finalScore >= 50) {
    severity = 'HIGH';
  } else if (finalScore >= 25) {
    severity = 'MEDIUM';
  } else {
    severity = 'LOW';
  }

  const explanation = reasons.length > 0
    ? `Calculated score of ${finalScore}/100 (${severity}) driven by ${signals.length} verified signals: ${reasons.slice(0, 3).join('; ')}${reasons.length > 3 ? ` and ${reasons.length - 3} more.` : '.'}`
    : `Calculated baseline risk score of ${finalScore}/100 (${severity}). No anomalous structural signals detected.`;

  return {
    score: finalScore,
    severity,
    reasons,
    signals,
    explanation,
    calculationTimestamp: new Date().toISOString(),
  };
}
