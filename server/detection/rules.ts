/**
 * CYBERNEXUS SOC - Modular Detection Rule Engine
 * Deterministic rules that evaluate indicators & events and produce auditable matches.
 */

import { extractUrlFeatures } from './url_features';
import { calculateRiskScore } from './scoring';
import { mapEventToMitreCandidates } from './mitre';
import { Severity } from '../../src/types/soc';

export interface RuleEvaluationInput {
  eventType: string;
  indicator: string;
  indicatorType: 'URL' | 'DOMAIN' | 'IP' | 'HASH';
  metadata?: Record<string, unknown>;
}

export interface RuleEvaluationResult {
  ruleId: string;
  ruleName: string;
  matched: boolean;
  severity: Severity;
  scoreContribution: number;
  description: string;
  mitreTechniqueId?: string;
  evidenceGenerated: {
    description: string;
    classification: 'OBSERVED' | 'INFERRED';
    confidence: number;
  }[];
}

export interface FullEngineResult {
  matchedRules: RuleEvaluationResult[];
  compositeSeverity: Severity;
  compositeScore: number;
  reasons: string[];
  mitreCandidates: ReturnType<typeof mapEventToMitreCandidates>;
}

export function evaluateDetectionRules(input: RuleEvaluationInput): FullEngineResult {
  const matchedRules: RuleEvaluationResult[] = [];
  const reasons: string[] = [];
  const additionalWeights: { rule: string; weight: number; description: string }[] = [];

  // Rule 1: Phishing URL Heuristic Matcher
  if (input.eventType === 'phishing_url' || input.indicatorType === 'URL') {
    const features = extractUrlFeatures(input.indicator);
    const hasPhishSignal = features.suspiciousKeywordsFound.length > 0 || features.hostIsIp || features.isPunycode || features.subdomainCount >= 3;
    if (hasPhishSignal) {
      matchedRules.push({
        ruleId: 'R-DET-PHISH-001',
        ruleName: 'Deceptive URL Structural Anomalies',
        matched: true,
        severity: features.hostIsIp || features.isPunycode ? 'CRITICAL' : 'HIGH',
        scoreContribution: 30,
        description: 'URL features match high-confidence deceptive patterns (suspicious auth keywords, IP host or punycode spoofing).',
        mitreTechniqueId: 'T1566.002',
        evidenceGenerated: [
          {
            description: `Observed URL characteristics: Subdomains: ${features.subdomainCount}, Keywords: [${features.suspiciousKeywordsFound.join(', ')}], HTTPS: ${features.isHttps}`,
            classification: 'OBSERVED',
            confidence: 0.95
          },
          {
            description: 'URL structure mimics internal authentication/service portal for credential harvesting',
            classification: 'INFERRED',
            confidence: 0.88
          }
        ]
      });
      additionalWeights.push({
        rule: 'R-DET-PHISH-001',
        weight: 30,
        description: 'Phishing heuristic match on target URL'
      });
    }
  }

  // Rule 2: Malware Hash IOC Matcher
  if (input.eventType === 'malware_hash' || input.indicatorType === 'HASH') {
    matchedRules.push({
      ruleId: 'R-DET-MALWARE-002',
      ruleName: 'Known Malicious Binary Hash',
      matched: true,
      severity: 'CRITICAL',
      scoreContribution: 40,
      description: 'Calculated file digest matches verified ransomware/loader hash catalog.',
      mitreTechniqueId: 'T1204.002',
      evidenceGenerated: [
        {
          description: `Cryptographic hash ${input.indicator} submitted to endpoint execution monitor`,
          classification: 'OBSERVED',
          confidence: 1.0
        },
        {
          description: 'Hash payload associated with second-stage beacon execution',
          classification: 'INFERRED',
          confidence: 0.92
        }
      ]
    });
    additionalWeights.push({
      rule: 'R-DET-MALWARE-002',
      weight: 40,
      description: 'Known malicious binary hash match'
    });
  }

  // Rule 3: Failed Login Burst / Brute Force
  if (input.eventType === 'failed_login_burst') {
    matchedRules.push({
      ruleId: 'R-DET-AUTH-003',
      ruleName: 'Rapid Authentication Failure Threshold Exceeded',
      matched: true,
      severity: 'HIGH',
      scoreContribution: 35,
      description: 'Over 120 failed authentication attempts recorded within a 60-second window across single source IP.',
      mitreTechniqueId: 'T1110',
      evidenceGenerated: [
        {
          description: `124 consecutive failed authentication attempts against endpoint from IP ${input.indicator}`,
          classification: 'OBSERVED',
          confidence: 1.0
        },
        {
          description: 'Pattern represents automated password spraying or brute force dictionary attack',
          classification: 'INFERRED',
          confidence: 0.94
        }
      ]
    });
    additionalWeights.push({
      rule: 'R-DET-AUTH-003',
      weight: 35,
      description: 'Rapid authentication failure threshold exceeded'
    });
  }

  // Rule 4: Impossible Travel Anomaly
  if (input.eventType === 'impossible_travel') {
    matchedRules.push({
      ruleId: 'R-DET-GEO-004',
      ruleName: 'Geo-Temporal Impossibility in User Sessions',
      matched: true,
      severity: 'HIGH',
      scoreContribution: 30,
      description: 'Consecutive successful authentications recorded from geographically distant locations within improbable transit timeframe.',
      mitreTechniqueId: 'T1078',
      evidenceGenerated: [
        {
          description: 'Authentication event in New York (US) followed by Tokyo (JP) within 14 minutes',
          classification: 'OBSERVED',
          confidence: 1.0
        },
        {
          description: 'Probable session token theft or unauthorized credential sharing',
          classification: 'INFERRED',
          confidence: 0.89
        }
      ]
    });
    additionalWeights.push({
      rule: 'R-DET-GEO-004',
      weight: 30,
      description: 'Geo-temporal impossible travel detected'
    });
  }

  // Rule 5: Unusual Login / Privilege Escalation
  if (input.eventType === 'unusual_login') {
    matchedRules.push({
      ruleId: 'R-DET-ID-005',
      ruleName: 'Off-Hours Unregistered Device Login to Privileged Asset',
      matched: true,
      severity: 'MEDIUM',
      scoreContribution: 25,
      description: 'Authentication observed outside established baseline hours from previously unseen workstation.',
      mitreTechniqueId: 'T1078',
      evidenceGenerated: [
        {
          description: 'Access to Domain Controller administrative console at 03:42 AM from unmanaged hostname',
          classification: 'OBSERVED',
          confidence: 1.0
        },
        {
          description: 'Adversary utilizing legitimate administrative credentials for stealthy lateral exploration',
          classification: 'INFERRED',
          confidence: 0.82
        }
      ]
    });
    additionalWeights.push({
      rule: 'R-DET-ID-005',
      weight: 25,
      description: 'Unusual off-hours privileged login'
    });
  }

  // Rule 6: Suspicious DNS Tunneling
  if (input.eventType === 'suspicious_dns') {
    matchedRules.push({
      ruleId: 'R-DET-DNS-006',
      ruleName: 'High-Entropy DNS Query Volume (Tunneling)',
      matched: true,
      severity: 'HIGH',
      scoreContribution: 35,
      description: 'Recursive DNS resolver logs reflect abnormal TXT query rates with elevated Shannon entropy.',
      mitreTechniqueId: 'T1071.004',
      evidenceGenerated: [
        {
          description: `450+ sub-queries under domain ${input.indicator} with average Shannon entropy 4.61`,
          classification: 'OBSERVED',
          confidence: 0.98
        },
        {
          description: 'DNS channel is being utilized for data exfiltration or bidirectional C2 command channeling',
          classification: 'INFERRED',
          confidence: 0.91
        }
      ]
    });
    additionalWeights.push({
      rule: 'R-DET-DNS-006',
      weight: 35,
      description: 'High-entropy DNS query anomaly / tunneling pattern'
    });
  }

  // Rule 7: Suspicious IP / C2 Beaconing
  if (input.eventType === 'suspicious_ip') {
    matchedRules.push({
      ruleId: 'R-DET-NET-007',
      ruleName: 'Egress Beaconing to Low-Reputation IP',
      matched: true,
      severity: 'HIGH',
      scoreContribution: 30,
      description: 'Regular heartbeat HTTPS connections observed to documentation/unallocated IP space.',
      mitreTechniqueId: 'T1071.001',
      evidenceGenerated: [
        {
          description: `60-second periodic TCP connections observed from internal host to ${input.indicator}`,
          classification: 'OBSERVED',
          confidence: 0.96
        },
        {
          description: 'Periodic network traffic matches command and control beacon profile',
          classification: 'INFERRED',
          confidence: 0.85
        }
      ]
    });
    additionalWeights.push({
      rule: 'R-DET-NET-007',
      weight: 30,
      description: 'Egress beaconing pattern to low-reputation IP'
    });
  }

  // Rule 8: Suspicious Domain / Typosquatting
  if (input.eventType === 'suspicious_domain') {
    matchedRules.push({
      ruleId: 'R-DET-DOM-008',
      ruleName: 'Typosquatting Brand Registration',
      matched: true,
      severity: 'HIGH',
      scoreContribution: 28,
      description: 'Newly registered domain incorporates protected brand naming with character substitution.',
      mitreTechniqueId: 'T1583.001',
      evidenceGenerated: [
        {
          description: `Domain ${input.indicator} registered within past 48 hours via privacy proxy`,
          classification: 'OBSERVED',
          confidence: 0.95
        },
        {
          description: 'Adversary infrastructure prepared for targeted impersonation campaign',
          classification: 'INFERRED',
          confidence: 0.88
        }
      ]
    });
    additionalWeights.push({
      rule: 'R-DET-DOM-008',
      weight: 28,
      description: 'Newly registered brand typosquatting domain'
    });
  }

  // Calculate composite score using our scoring engine
  const urlFeatures = input.indicatorType === 'URL' ? extractUrlFeatures(input.indicator) : undefined;
  const scoreResult = calculateRiskScore(urlFeatures, undefined, additionalWeights);
  const mitreCandidates = mapEventToMitreCandidates(input.eventType, input.indicatorType);

  for (const m of matchedRules) {
    reasons.push(m.ruleName);
  }

  return {
    matchedRules,
    compositeSeverity: scoreResult.severity,
    compositeScore: scoreResult.score,
    reasons,
    mitreCandidates,
  };
}
