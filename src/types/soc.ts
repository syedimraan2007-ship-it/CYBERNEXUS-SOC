/**
 * CYBERNEXUS SOC - Type Definitions
 * Detect. Investigate. Explain. Respond.
 */

export type UserRole = 'ANALYST' | 'LEAD' | 'ADMIN';

export interface User {
  id: string;
  username: string;
  name: string;
  role: UserRole;
  email: string;
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AlertStatus =
  | 'NEW'
  | 'TRIAGED'
  | 'INVESTIGATING'
  | 'CONTAINMENT_RECOMMENDED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE';

export type IndicatorType = 'URL' | 'DOMAIN' | 'IP' | 'HASH';

export type EvidenceClassification = 'OBSERVED' | 'INFERRED';

export interface EvidenceItem {
  id: string;
  source: string;
  timestamp: string;
  description: string;
  type: string;
  confidence: number; // 0.0 - 1.0
  classification: EvidenceClassification;
  details?: Record<string, unknown>;
}

export interface MitreTechnique {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  description: string;
  mappingType: 'OBSERVED' | 'INFERRED';
  confidence: number;
  source: string;
  evidenceRef?: string;
}

export interface UrlFeatures {
  url: string;
  domain: string;
  registeredDomain: string;
  tld: string;
  protocol: string;
  isHttps: boolean;
  hostIsIp: boolean;
  port: number | null;
  subdomainCount: number;
  urlLength: number;
  domainLength: number;
  containsAtSymbol: boolean;
  hyphenCount: number;
  encodedCharCount: number;
  isPunycode: boolean;
  isShortener: boolean;
  suspiciousKeywordsFound: string[];
  pathDepth: number;
  queryParamCount: number;
  entropy: number;
}

export interface RiskSignal {
  name: string;
  scoreContribution: number;
  category: 'STRUCTURAL' | 'HEURISTIC' | 'INTEL' | 'BEHAVIORAL';
  description: string;
}

export interface RiskScoreResult {
  score: number; // 0 - 100
  severity: Severity;
  reasons: string[];
  signals: RiskSignal[];
  explanation: string;
  calculationTimestamp: string;
}

export type ThreatIntelStatus =
  | 'SUCCESS'
  | 'NO_DATA'
  | 'UNAVAILABLE'
  | 'TIMEOUT'
  | 'RATE_LIMITED'
  | 'ERROR';

export interface ThreatIntelProviderResult {
  provider: string;
  status: ThreatIntelStatus;
  indicator: string;
  indicatorType: IndicatorType;
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';
  score?: number;
  confidence: number;
  details: Record<string, unknown>;
  synthetic: boolean;
  queriedAt: string;
  errorMessage?: string;
}

export interface ThreatIntelEnrichment {
  indicator: string;
  indicatorType: IndicatorType;
  providers: ThreatIntelProviderResult[];
  overallReputation: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';
  synthetic: boolean;
  summary: string;
}

export interface AiAnalystAssessment {
  assessment: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';
  confidence: number;
  summary: string;
  keyFindings: string[];
  evidenceDistinction: {
    observed: string[];
    inferred: string[];
  };
  riskExplanation: string[];
  mitreTechniques: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
    reasoning: string;
  }[];
  recommendedActions: {
    action: string;
    priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
    rationale: string;
  }[];
  missingInformation: string[];
  analystReviewRequired: boolean;
  provider: string;
  model: string;
  generatedAt: string;
  disclaimer: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  category: 'EVENT' | 'RULE' | 'TI' | 'AI' | 'ANALYST' | 'STATUS';
  actor?: string;
}

export interface AnalystNote {
  id: string;
  author: string;
  authorRole: UserRole;
  timestamp: string;
  content: string;
}

export interface RecommendedResponseAction {
  id: string;
  action: string;
  description: string;
  target: string;
  priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: 'CONTAINMENT' | 'ERADICATION' | 'INVESTIGATION' | 'MONITORING';
  status: 'PENDING_REVIEW' | 'APPROVED' | 'DISMISSED';
  evidenceRef?: string;
}

export interface RelatedAlert {
  alertId: string;
  title: string;
  severity: Severity;
  relationshipReason: string;
  indicator: string;
  timestamp: string;
}

export interface Alert {
  id: string; // e.g., CNX-001
  title: string;
  eventType: string;
  source: string;
  timestamp: string;
  indicator: string;
  indicatorType: IndicatorType;
  severity: Severity;
  riskScore: number;
  status: AlertStatus;
  synthetic: boolean;
  description: string;
  assignedTo?: string;
  urlFeatures?: UrlFeatures;
  riskBreakdown?: RiskScoreResult;
  ruleMatches?: string[];
  threatIntel?: ThreatIntelEnrichment;
  aiAssessment?: AiAnalystAssessment;
  mitreTechniques?: MitreTechnique[];
  evidenceList: EvidenceItem[];
  timeline: TimelineEvent[];
  analystNotes: AnalystNote[];
  recommendedActions: RecommendedResponseAction[];
  relatedAlerts: RelatedAlert[];
  resolutionNote?: string;
  resolvedAt?: string;
  resolvedBy?: string;
}

export interface SystemHealthState {
  backend: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  database: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  aiProvider: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  threatIntel: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  mitre: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  activeProviderName: string;
  syntheticDataMode: boolean;
  timestamp: string;
}

export interface SocDashboardStats {
  totalAlerts: number;
  criticalAlerts: number;
  highAlerts: number;
  mediumAlerts: number;
  lowAlerts: number;
  openIncidents: number;
  investigatingIncidents: number;
  resolvedIncidents: number;
  falsePositives: number;
  avgRiskScore: number;
  riskDistribution: {
    range: string;
    count: number;
  }[];
  alertTrend: {
    time: string;
    count: number;
  }[];
  mitreTopTechniques: {
    id: string;
    name: string;
    count: number;
  }[];
  topIndicators: {
    indicator: string;
    type: IndicatorType;
    severity: Severity;
    count: number;
  }[];
}
