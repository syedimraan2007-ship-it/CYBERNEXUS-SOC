/**
 * CYBERNEXUS SOC - Relational Database & Synthetic Dataset
 * Fully populated with 12 synthetic alerts (CNX-001 through CNX-012)
 * All indicators strictly use RFC-reserved domains and documentation IP ranges.
 */

import {
  Alert,
  AlertStatus,
  AnalystNote,
  EvidenceItem,
  MitreTechnique,
  RecommendedResponseAction,
  SocDashboardStats,
  TimelineEvent,
  User,
} from '../src/types/soc';
import { extractUrlFeatures } from './detection/url_features';
import { calculateRiskScore } from './detection/scoring';

export const USERS: User[] = [
  {
    id: 'USR-01',
    username: 'analyst1',
    name: 'Elena Rostova',
    role: 'ANALYST',
    email: 'elena.rostova@cyber-nexus.internal',
  },
  {
    id: 'USR-02',
    username: 'lead_soc',
    name: 'Marcus Vance',
    role: 'LEAD',
    email: 'marcus.vance@cyber-nexus.internal',
  },
  {
    id: 'USR-03',
    username: 'admin',
    name: 'Chief Security Officer',
    role: 'ADMIN',
    email: 'cso@cyber-nexus.internal',
  },
];

let alertsStore: Alert[] = [];

export function initializeDatabase(): void {
  const now = new Date();
  const subMinutes = (mins: number) => new Date(now.getTime() - mins * 60000).toISOString();

  alertsStore = [
    // 1. Phishing URL
    {
      id: 'CNX-001',
      title: 'Credential Harvesting Link Targeting Corporate SSO',
      eventType: 'phishing_url',
      source: 'Email Gateway Sensor (SEG-01)',
      timestamp: subMinutes(12),
      indicator: 'http://login.secure-sso.verify-portal.account-update.test/auth/login?user=jdoe',
      indicatorType: 'URL',
      severity: 'CRITICAL',
      riskScore: 88,
      status: 'NEW',
      synthetic: true,
      description: 'Incoming email lured corporate employee to synthetic login page with 4 subdomains and credential verification terms.',
      assignedTo: 'Elena Rostova',
      urlFeatures: extractUrlFeatures('http://login.secure-sso.verify-portal.account-update.test/auth/login?user=jdoe'),
      riskBreakdown: calculateRiskScore(
        extractUrlFeatures('http://login.secure-sso.verify-portal.account-update.test/auth/login?user=jdoe'),
        undefined,
        [{ rule: 'R-DET-PHISH-001', weight: 30, description: 'Phishing heuristic match on target URL' }]
      ),
      ruleMatches: ['R-DET-PHISH-001: Deceptive URL Structural Anomalies', 'R-HEUR-AUTH: Sensitive keywords on non-HTTPS'],
      evidenceList: [
        {
          id: 'EVD-001-A',
          source: 'Secure Email Gateway',
          timestamp: subMinutes(12),
          description: 'Observed URL in message body: http://login.secure-sso.verify-portal.account-update.test',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-001-B',
          source: 'Deterministic Feature Parser',
          timestamp: subMinutes(11),
          description: 'URL contains 4 subdomains, no TLS encryption (plain HTTP), and auth keywords: [login, secure, update, auth]',
          type: 'STRUCTURAL',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-001-C',
          source: 'Detection Engine',
          timestamp: subMinutes(10),
          description: 'Domain crafted to impersonate internal single sign-on authentication service',
          type: 'ANALYTICAL',
          confidence: 0.92,
          classification: 'INFERRED',
        },
      ],
      timeline: [
        { id: 'TL-01', timestamp: subMinutes(12), title: 'Email Event Ingested', description: 'Inbound message containing hyperlink intercepted', category: 'EVENT' },
        { id: 'TL-02', timestamp: subMinutes(11), title: 'Detection Rule R-DET-PHISH-001 Triggered', description: 'Structural scoring exceeded critical threshold', category: 'RULE' },
        { id: 'TL-03', timestamp: subMinutes(10), title: 'Alert Generated', description: 'Incident CNX-001 registered in SOC queue', category: 'STATUS' },
      ],
      analystNotes: [
        { id: 'NOTE-01', author: 'Elena Rostova', authorRole: 'ANALYST', timestamp: subMinutes(8), content: 'Initial triage confirms recipient employee did not click or enter credentials.' }
      ],
      mitreTechniques: [
        {
          techniqueId: 'T1566.002',
          techniqueName: 'Phishing: Spearphishing Link',
          tactic: 'Initial Access',
          description: 'Adversary sent spearphishing hyperlink targeting corporate employee credentials.',
          mappingType: 'OBSERVED',
          confidence: 0.95,
          source: 'Rule Engine: URL Structure & Phishing Heuristics',
        },
      ],
      recommendedActions: [
        {
          id: 'ACT-001-A',
          action: 'Block Domain on Web Proxy & DNS RPZ',
          description: 'Prevent internal network connections to account-update.test',
          target: 'account-update.test',
          priority: 'IMMEDIATE',
          category: 'CONTAINMENT',
          status: 'PENDING_REVIEW',
        },
        {
          id: 'ACT-001-B',
          action: 'Purge Email from Recipient Inboxes',
          description: 'Delete identical lure messages across enterprise Microsoft 365 tenant',
          target: 'Subject: Urgent: Verify Corporate SSO',
          priority: 'HIGH',
          category: 'ERADICATION',
          status: 'PENDING_REVIEW',
        },
      ],
      relatedAlerts: [
        {
          alertId: 'CNX-009',
          title: 'Typosquatting Brand Registration',
          severity: 'HIGH',
          relationshipReason: 'Shared infrastructure pattern and synthetic test domain hierarchy',
          indicator: 'account-update.test',
          timestamp: subMinutes(60),
        },
      ],
    },

    // 2. Benign URL
    {
      id: 'CNX-002',
      title: 'Legitimate Corporate Documentation Portal Access',
      eventType: 'url_inspection',
      source: 'Web Proxy (PROXY-02)',
      timestamp: subMinutes(25),
      indicator: 'https://internal-portal.corp.example.test/docs/handbook',
      indicatorType: 'URL',
      severity: 'LOW',
      riskScore: 8,
      status: 'TRIAGED',
      synthetic: true,
      description: 'Employee navigated to standard internal handbook URL. Low risk baseline confirmed.',
      assignedTo: 'Elena Rostova',
      urlFeatures: extractUrlFeatures('https://internal-portal.corp.example.test/docs/handbook'),
      riskBreakdown: calculateRiskScore(extractUrlFeatures('https://internal-portal.corp.example.test/docs/handbook')),
      ruleMatches: [],
      evidenceList: [
        {
          id: 'EVD-002-A',
          source: 'Corporate Proxy',
          timestamp: subMinutes(25),
          description: 'Valid TLS session established with trusted corporate certificate authority',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
      ],
      timeline: [
        { id: 'TL-04', timestamp: subMinutes(25), title: 'Inspection Request Logged', description: 'URL scanned during automated proxy baseline audit', category: 'EVENT' },
        { id: 'TL-05', timestamp: subMinutes(24), title: 'Triaged as Benign', description: 'Verified corporate domain match', category: 'STATUS' },
      ],
      analystNotes: [],
      mitreTechniques: [],
      recommendedActions: [
        {
          id: 'ACT-002-A',
          action: 'No Containment Required',
          description: 'Indicator verified as authorized enterprise resource',
          target: 'internal-portal.corp.example.test',
          priority: 'LOW',
          category: 'MONITORING',
          status: 'APPROVED',
        },
      ],
      relatedAlerts: [],
    },

    // 3. Suspicious DNS
    {
      id: 'CNX-003',
      title: 'High-Entropy DNS Query Volume (Tunneling Anomaly)',
      eventType: 'suspicious_dns',
      source: 'Core DNS Resolver (DNS-01)',
      timestamp: subMinutes(42),
      indicator: 'tunnel-exfil-test.reserved.test',
      indicatorType: 'DOMAIN',
      severity: 'HIGH',
      riskScore: 78,
      status: 'INVESTIGATING',
      synthetic: true,
      description: 'Over 450 anomalous sub-queries with high Shannon entropy detected targeting synthetic reserved test domain.',
      assignedTo: 'Marcus Vance',
      ruleMatches: ['R-DET-DNS-006: High-Entropy DNS Query Volume'],
      evidenceList: [
        {
          id: 'EVD-003-A',
          source: 'DNS Resolver Logs',
          timestamp: subMinutes(42),
          description: 'Observed 480 TXT records queried within 90 seconds from host 192.0.2.14',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-003-B',
          source: 'Statistical Baseline Analyzer',
          timestamp: subMinutes(40),
          description: 'Query entropy calculated at 4.68, heavily diverging from normal host baseline (2.1)',
          type: 'STATISTICAL',
          confidence: 0.94,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-003-C',
          source: 'Threat Correlator',
          timestamp: subMinutes(39),
          description: 'Payload signature aligns with DNS tunneling utility protocol encapsulation',
          type: 'ANALYTICAL',
          confidence: 0.88,
          classification: 'INFERRED',
        },
      ],
      timeline: [
        { id: 'TL-06', timestamp: subMinutes(42), title: 'DNS Anomaly Detected', description: 'Volume spike flagged on internal recursive resolver', category: 'EVENT' },
        { id: 'TL-07', timestamp: subMinutes(41), title: 'Rule R-DET-DNS-006 Triggered', description: 'Entropy threshold exceeded', category: 'RULE' },
        { id: 'TL-08', timestamp: subMinutes(35), title: 'Investigation Opened', description: 'Analyst Marcus Vance escalated case to active investigation', category: 'STATUS' },
      ],
      analystNotes: [
        { id: 'NOTE-02', author: 'Marcus Vance', authorRole: 'LEAD', timestamp: subMinutes(30), content: 'Isolated host 192.0.2.14 from local network segment. Analyzing running processes.' }
      ],
      mitreTechniques: [
        {
          techniqueId: 'T1071.004',
          techniqueName: 'Application Layer Protocol: DNS',
          tactic: 'Command and Control',
          description: 'Adversary communicates or tunnels data through DNS protocol.',
          mappingType: 'OBSERVED',
          confidence: 0.88,
          source: 'Rule Engine: High-Entropy DNS Resolver Monitor',
        },
      ],
      recommendedActions: [
        {
          id: 'ACT-003-A',
          action: 'Apply DNS Sinkhole to Root Domain',
          description: 'Redirect queries for tunnel-exfil-test.reserved.test to loopback',
          target: 'tunnel-exfil-test.reserved.test',
          priority: 'IMMEDIATE',
          category: 'CONTAINMENT',
          status: 'PENDING_REVIEW',
        },
        {
          id: 'ACT-003-B',
          action: 'Isolate Host 192.0.2.14 at Switch Port',
          description: 'Enforce quarantine VLAN on originating endpoint',
          target: '192.0.2.14',
          priority: 'HIGH',
          category: 'CONTAINMENT',
          status: 'APPROVED',
        },
      ],
      relatedAlerts: [],
    },

    // 4. Malware Hash
    {
      id: 'CNX-004',
      title: 'Known Malicious Binary Hash (LockNexus Loader)',
      eventType: 'malware_hash',
      source: 'Endpoint Detection and Response (EDR-03)',
      timestamp: subMinutes(65),
      indicator: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      indicatorType: 'HASH',
      severity: 'CRITICAL',
      riskScore: 96,
      status: 'CONTAINMENT_RECOMMENDED',
      synthetic: true,
      description: 'Execution of binary with verified ransomware loader hash intercepted in temp directory.',
      assignedTo: 'Elena Rostova',
      ruleMatches: ['R-DET-MALWARE-002: Known Malicious Binary Hash'],
      evidenceList: [
        {
          id: 'EVD-004-A',
          source: 'EDR Agent',
          timestamp: subMinutes(65),
          description: 'Process launch blocked: C:\\Users\\Public\\updater.exe with SHA256: e3b0c442...b855',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-004-B',
          source: 'Threat Intelligence Provider',
          timestamp: subMinutes(64),
          description: 'Synthetic threat intelligence matches LockNexus.Synthetic ransomware signature',
          type: 'INTEL',
          confidence: 0.98,
          classification: 'OBSERVED',
        },
      ],
      timeline: [
        { id: 'TL-09', timestamp: subMinutes(65), title: 'Process Execution Blocked', description: 'EDR blocked execution in user temp path', category: 'EVENT' },
        { id: 'TL-10', timestamp: subMinutes(64), title: 'Threat Intel Correlation Complete', description: 'Hash confirmed malicious', category: 'TI' },
        { id: 'TL-11', timestamp: subMinutes(60), title: 'Containment Recommended', description: 'Analyst issued endpoint isolation recommendation', category: 'STATUS' },
      ],
      analystNotes: [
        { id: 'NOTE-03', author: 'Elena Rostova', authorRole: 'ANALYST', timestamp: subMinutes(55), content: 'Binary blocked pre-execution. Full memory dump collected for forensic sandbox inspection.' }
      ],
      mitreTechniques: [
        {
          techniqueId: 'T1204.002',
          techniqueName: 'User Execution: Malicious File',
          tactic: 'Execution',
          description: 'Attempted execution of malicious loader binary.',
          mappingType: 'OBSERVED',
          confidence: 0.90,
          source: 'Rule Engine: Malicious File Hash Detection',
        },
      ],
      recommendedActions: [
        {
          id: 'ACT-004-A',
          action: 'Quarantine Host and Invalidate Active Tokens',
          description: 'Isolate compromised endpoint from network and revoke user session',
          target: 'WS-FINANCE-04',
          priority: 'IMMEDIATE',
          category: 'CONTAINMENT',
          status: 'PENDING_REVIEW',
        },
      ],
      relatedAlerts: [],
    },

    // 5. Failed Login Burst
    {
      id: 'CNX-005',
      title: 'Rapid Failed Authentication Burst (Brute Force Spray)',
      eventType: 'failed_login_burst',
      source: 'Identity Provider (IdP-AUTH)',
      timestamp: subMinutes(85),
      indicator: '198.51.100.77',
      indicatorType: 'IP',
      severity: 'HIGH',
      riskScore: 75,
      status: 'INVESTIGATING',
      synthetic: true,
      description: '124 consecutive failed authentication attempts in 60 seconds against VPN authentication portal.',
      assignedTo: 'Marcus Vance',
      ruleMatches: ['R-DET-AUTH-003: Rapid Authentication Failure Threshold Exceeded'],
      evidenceList: [
        {
          id: 'EVD-005-A',
          source: 'IdP Authentication Audit Log',
          timestamp: subMinutes(85),
          description: '124 failed login requests across 62 unique user accounts originating from 198.51.100.77',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-005-B',
          source: 'Identity Correlation',
          timestamp: subMinutes(84),
          description: 'Password spraying pattern attempting top 20 common corporate passwords',
          type: 'ANALYTICAL',
          confidence: 0.95,
          classification: 'INFERRED',
        },
      ],
      timeline: [
        { id: 'TL-12', timestamp: subMinutes(85), title: 'Spray Threshold Exceeded', description: 'Authentication failure rate exceeded 2 req/sec', category: 'EVENT' },
        { id: 'TL-13', timestamp: subMinutes(80), title: 'Investigation Assigned', description: 'Assigned to Marcus Vance', category: 'STATUS' },
      ],
      analystNotes: [],
      mitreTechniques: [
        {
          techniqueId: 'T1110',
          techniqueName: 'Brute Force',
          tactic: 'Credential Access',
          description: 'Automated password spraying against perimeter authentication endpoints.',
          mappingType: 'OBSERVED',
          confidence: 0.92,
          source: 'Rule Engine: Authentication Anomaly Correlator',
        },
      ],
      recommendedActions: [
        {
          id: 'ACT-005-A',
          action: 'Temporary IP Blacklist at Edge Firewall',
          description: 'Block inbound connections from 198.51.100.77 for 24 hours',
          target: '198.51.100.77',
          priority: 'IMMEDIATE',
          category: 'CONTAINMENT',
          status: 'PENDING_REVIEW',
        },
      ],
      relatedAlerts: [],
    },

    // 6. Impossible Travel
    {
      id: 'CNX-006',
      title: 'Geo-Temporal Impossibility in User Sessions',
      eventType: 'impossible_travel',
      source: 'Cloud Access Security Broker (CASB-01)',
      timestamp: subMinutes(110),
      indicator: '203.0.113.195',
      indicatorType: 'IP',
      severity: 'HIGH',
      riskScore: 72,
      status: 'TRIAGED',
      synthetic: true,
      description: 'Successful authentication for user s.chen in New York, followed 14 minutes later by session from Tokyo.',
      assignedTo: 'Elena Rostova',
      ruleMatches: ['R-DET-GEO-004: Geo-Temporal Impossibility in User Sessions'],
      evidenceList: [
        {
          id: 'EVD-006-A',
          source: 'CASB Session Log',
          timestamp: subMinutes(124),
          description: 'Session A created from US-East IP 192.0.2.80 (New York)',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-006-B',
          source: 'CASB Session Log',
          timestamp: subMinutes(110),
          description: 'Session B created from documentation IP 203.0.113.195 (Tokyo)',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-006-C',
          source: 'Identity Risk Engine',
          timestamp: subMinutes(109),
          description: 'Physical transit speed required: ~45,000 km/h. Likely session cookie replay or VPN relay.',
          type: 'ANALYTICAL',
          confidence: 0.91,
          classification: 'INFERRED',
        },
      ],
      timeline: [
        { id: 'TL-14', timestamp: subMinutes(110), title: 'Second Session Established', description: 'CASB flagged geo-distance discrepancy', category: 'EVENT' },
        { id: 'TL-15', timestamp: subMinutes(105), title: 'Alert Triaged', description: 'Analyst Elena Rostova verified travel conflict', category: 'STATUS' },
      ],
      analystNotes: [],
      mitreTechniques: [
        {
          techniqueId: 'T1078',
          techniqueName: 'Valid Accounts',
          tactic: 'Defense Evasion',
          description: 'Adversary utilizing valid credentials obtained via infostealer or session hijacking.',
          mappingType: 'INFERRED',
          confidence: 0.85,
          source: 'Rule Engine: Identity Geo-temporal Anomaly',
        },
      ],
      recommendedActions: [
        {
          id: 'ACT-006-A',
          action: 'Revoke User Refresh Tokens and Force MFA Challenge',
          description: 'Terminate all active browser sessions for s.chen',
          target: 'user: s.chen',
          priority: 'IMMEDIATE',
          category: 'CONTAINMENT',
          status: 'PENDING_REVIEW',
        },
      ],
      relatedAlerts: [],
    },

    // 7. Unusual Login
    {
      id: 'CNX-007',
      title: 'Off-Hours Unregistered Device Login to Privileged Asset',
      eventType: 'unusual_login',
      source: 'Active Directory Security Log (DC-01)',
      timestamp: subMinutes(140),
      indicator: '192.0.2.199',
      indicatorType: 'IP',
      severity: 'MEDIUM',
      riskScore: 48,
      status: 'NEW',
      synthetic: true,
      description: 'Domain administrator account authenticated at 03:42 AM local time from an unmanaged virtual machine.',
      assignedTo: undefined,
      ruleMatches: ['R-DET-ID-005: Off-Hours Unregistered Device Login'],
      evidenceList: [
        {
          id: 'EVD-007-A',
          source: 'Domain Controller Event 4624',
          timestamp: subMinutes(140),
          description: 'Logon type 10 (RemoteInteractive) for adm-turner from 192.0.2.199',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
      ],
      timeline: [
        { id: 'TL-16', timestamp: subMinutes(140), title: 'Logon Recorded', description: 'Off-baseline logon registered on DC-01', category: 'EVENT' },
      ],
      analystNotes: [],
      mitreTechniques: [
        {
          techniqueId: 'T1078',
          techniqueName: 'Valid Accounts',
          tactic: 'Initial Access',
          description: 'Privileged administrative credentials used during off-hours maintenance window.',
          mappingType: 'INFERRED',
          confidence: 0.75,
          source: 'Rule Engine: Off-Hours Privilege Monitor',
        },
      ],
      recommendedActions: [
        {
          id: 'ACT-007-A',
          action: 'Verify with On-Call SysAdmin',
          description: 'Confirm whether authorized maintenance activity was scheduled',
          target: 'adm-turner',
          priority: 'MEDIUM',
          category: 'INVESTIGATION',
          status: 'PENDING_REVIEW',
        },
      ],
      relatedAlerts: [],
    },

    // 8. Suspicious IP
    {
      id: 'CNX-008',
      title: 'Persistent Outbound Heartbeat to Low-Reputation IP (C2 Beacon)',
      eventType: 'suspicious_ip',
      source: 'Network Egress Firewall (FW-OUT)',
      timestamp: subMinutes(170),
      indicator: '198.51.100.45',
      indicatorType: 'IP',
      severity: 'HIGH',
      riskScore: 74,
      status: 'INVESTIGATING',
      synthetic: true,
      description: 'Host 192.0.2.33 maintains 60-second periodic TCP connections to synthetic documentation IP.',
      assignedTo: 'Marcus Vance',
      ruleMatches: ['R-DET-NET-007: Egress Beaconing to Low-Reputation IP'],
      evidenceList: [
        {
          id: 'EVD-008-A',
          source: 'NetFlow Collector',
          timestamp: subMinutes(170),
          description: '144 periodic outbound HTTPS sessions to 198.51.100.45:443 with jitter < 2%',
          type: 'TELEMETRY',
          confidence: 0.98,
          classification: 'OBSERVED',
        },
      ],
      timeline: [
        { id: 'TL-17', timestamp: subMinutes(170), title: 'Beaconing Signal Detected', description: 'Netflow statistical analyzer detected rhythmic beaconing', category: 'EVENT' },
      ],
      analystNotes: [],
      mitreTechniques: [
        {
          techniqueId: 'T1071.001',
          techniqueName: 'Application Layer Protocol: Web Protocols',
          tactic: 'Command and Control',
          description: 'Adversary utilizes standard web protocol for periodic C2 check-ins.',
          mappingType: 'INFERRED',
          confidence: 0.85,
          source: 'Rule Engine: Egress C2 Pattern Analyzer',
        },
      ],
      recommendedActions: [
        {
          id: 'ACT-008-A',
          action: 'Egress Block at Perimeter Router',
          description: 'Drop all outbound traffic destined for 198.51.100.45',
          target: '198.51.100.45',
          priority: 'HIGH',
          category: 'CONTAINMENT',
          status: 'PENDING_REVIEW',
        },
      ],
      relatedAlerts: [],
    },

    // 9. Suspicious Domain
    {
      id: 'CNX-009',
      title: 'Newly Registered Brand Impersonation Domain (Typosquatting)',
      eventType: 'suspicious_domain',
      source: 'Brand Protection Feed (INTEL-EXT)',
      timestamp: subMinutes(210),
      indicator: 'cybernexus-security-auth.test',
      indicatorType: 'DOMAIN',
      severity: 'HIGH',
      riskScore: 68,
      status: 'NEW',
      synthetic: true,
      description: 'Synthetic domain cybernexus-security-auth.test registered 36 hours ago with deceptive brand similarity.',
      assignedTo: undefined,
      ruleMatches: ['R-DET-DOM-008: Typosquatting Brand Registration'],
      evidenceList: [
        {
          id: 'EVD-009-A',
          source: 'Domain Registration Feeds',
          timestamp: subMinutes(210),
          description: 'Registration timestamp: 2026-10-04, MX records pointed to synthetic mail server',
          type: 'INTEL',
          confidence: 0.96,
          classification: 'OBSERVED',
        },
      ],
      timeline: [
        { id: 'TL-18', timestamp: subMinutes(210), title: 'Intel Ingestion', description: 'Newly registered domain flagged by brand monitoring pipeline', category: 'EVENT' },
      ],
      analystNotes: [],
      mitreTechniques: [
        {
          techniqueId: 'T1583.001',
          techniqueName: 'Acquire Infrastructure: Domains',
          tactic: 'Resource Development',
          description: 'Adversary registered impersonation domain prior to campaign execution.',
          mappingType: 'INFERRED',
          confidence: 0.78,
          source: 'Rule Engine: Domain Infrastructure Monitor',
        },
      ],
      recommendedActions: [
        {
          id: 'ACT-009-A',
          action: 'Add Domain to Preventive Blacklist',
          description: 'Preemptively block web and email gateway connections',
          target: 'cybernexus-security-auth.test',
          priority: 'MEDIUM',
          category: 'CONTAINMENT',
          status: 'PENDING_REVIEW',
        },
      ],
      relatedAlerts: [
        {
          alertId: 'CNX-001',
          title: 'Credential Harvesting Link Targeting Corporate SSO',
          severity: 'CRITICAL',
          relationshipReason: 'Shared keyword patterns and credential phishing targeting profile',
          indicator: 'account-update.test',
          timestamp: subMinutes(12),
        },
      ],
    },

    // 10. False Positive
    {
      id: 'CNX-010',
      title: 'Port Scan and Web Probing from Internal Security Scanner',
      eventType: 'vulnerability_scan',
      source: 'Network Intrusion Detection System (NIDS-01)',
      timestamp: subMinutes(260),
      indicator: '192.0.2.5',
      indicatorType: 'IP',
      severity: 'LOW',
      riskScore: 18,
      status: 'FALSE_POSITIVE',
      synthetic: true,
      description: 'Rapid port probing detected on internal subnet; verified as scheduled Nessus vulnerability assessment.',
      assignedTo: 'Marcus Vance',
      ruleMatches: [],
      evidenceList: [
        {
          id: 'EVD-010-A',
          source: 'NIDS Alert',
          timestamp: subMinutes(260),
          description: 'SYN scan targeting ports 80, 443, 8080, 8443 across 192.0.2.0/24',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-010-B',
          source: 'Change Management Registry',
          timestamp: subMinutes(255),
          description: 'Approved Change Window CHG-8821: Quarterly Internal Vulnerability Scan from scanner IP 192.0.2.5',
          type: 'ADMINISTRATIVE',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
      ],
      timeline: [
        { id: 'TL-19', timestamp: subMinutes(260), title: 'Probe Detected', description: 'NIDS generated port scan alert', category: 'EVENT' },
        { id: 'TL-20', timestamp: subMinutes(250), title: 'Correlated with Change Request', description: 'Matched approved vulnerability scanner window', category: 'RULE' },
        { id: 'TL-21', timestamp: subMinutes(245), title: 'Closed as False Positive', description: 'Incident closed by Marcus Vance', category: 'STATUS' },
      ],
      analystNotes: [
        { id: 'NOTE-04', author: 'Marcus Vance', authorRole: 'LEAD', timestamp: subMinutes(245), content: 'Verified with security engineering team. Scheduled authorized quarterly audit. Marked as false positive.' }
      ],
      mitreTechniques: [],
      recommendedActions: [
        {
          id: 'ACT-010-A',
          action: 'No Operational Action Required',
          description: 'Scanner IP is whitelisted for the duration of the change window',
          target: '192.0.2.5',
          priority: 'LOW',
          category: 'MONITORING',
          status: 'DISMISSED',
        },
      ],
      relatedAlerts: [],
      resolutionNote: 'Authorized vulnerability assessment window CHG-8821 verified by SOC Lead. Closing as benign false positive.',
      resolvedAt: subMinutes(245),
      resolvedBy: 'Marcus Vance',
    },

    // 11. High Severity Incident
    {
      id: 'CNX-011',
      title: 'Credential Stuffing Leading to Active Session Hijack',
      eventType: 'compromised_account',
      source: 'SIEM Correlation Engine (CORR-CORE)',
      timestamp: subMinutes(310),
      indicator: '203.0.113.88',
      indicatorType: 'IP',
      severity: 'HIGH',
      riskScore: 82,
      status: 'INVESTIGATING',
      synthetic: true,
      description: 'Multiple successful logins followed immediately by unauthorized API key generation on privileged developer account.',
      assignedTo: 'Elena Rostova',
      ruleMatches: ['R-DET-AUTH-003: Credential Stuffing', 'R-DET-GEO-004: Anomalous Session Fingerprint'],
      evidenceList: [
        {
          id: 'EVD-011-A',
          source: 'API Gateway Audit',
          timestamp: subMinutes(310),
          description: 'Production API read/write token generated for dev-service account from IP 203.0.113.88',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
      ],
      timeline: [
        { id: 'TL-22', timestamp: subMinutes(310), title: 'High-Privilege Token Minted', description: 'Abnormal API key creation triggered SOC alert', category: 'EVENT' },
      ],
      analystNotes: [],
      mitreTechniques: [
        {
          techniqueId: 'T1078',
          techniqueName: 'Valid Accounts',
          tactic: 'Defense Evasion',
          description: 'Compromised service account utilized to mint persistent API keys.',
          mappingType: 'OBSERVED',
          confidence: 0.89,
          source: 'SIEM Correlation Rule',
        },
      ],
      recommendedActions: [
        {
          id: 'ACT-011-A',
          action: 'Revoke Generated API Key Immediately',
          description: 'Invalidate token key_live_synthetic_991823',
          target: 'key_live_synthetic_991823',
          priority: 'IMMEDIATE',
          category: 'CONTAINMENT',
          status: 'PENDING_REVIEW',
        },
      ],
      relatedAlerts: [],
    },

    // 12. Critical Severity Incident
    {
      id: 'CNX-012',
      title: 'Enterprise Ransomware Staging & Volume Shadow Deletion Attempt',
      eventType: 'malicious_binary',
      source: 'Endpoint Behavioral Sensor (EDR-PRO)',
      timestamp: subMinutes(360),
      indicator: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
      indicatorType: 'HASH',
      severity: 'CRITICAL',
      riskScore: 98,
      status: 'CONTAINMENT_RECOMMENDED',
      synthetic: true,
      description: 'PowerShell execution spawned vssadmin.exe attempting "delete shadows /all /quiet" combined with mass encryption canary trigger.',
      assignedTo: 'Marcus Vance',
      ruleMatches: ['R-DET-MALWARE-002: Malicious Binary', 'R-DET-SYS-009: Volume Shadow Copy Tampering'],
      evidenceList: [
        {
          id: 'EVD-012-A',
          source: 'Sysmon Event ID 1',
          timestamp: subMinutes(360),
          description: 'Parent: powershell.exe -enc ... -> Child: vssadmin.exe delete shadows /all /quiet',
          type: 'TELEMETRY',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-012-B',
          source: 'File Integrity Canary',
          timestamp: subMinutes(359),
          description: 'Canary honey-files modified with extension .nexuslocked on file share FS-CORP-01',
          type: 'BEHAVIORAL',
          confidence: 1.0,
          classification: 'OBSERVED',
        },
        {
          id: 'EVD-012-C',
          source: 'Behavioral Analyzer',
          timestamp: subMinutes(358),
          description: 'High-confidence ransomware impact preparation. Imminent destruction of system recovery snapshots.',
          type: 'ANALYTICAL',
          confidence: 0.99,
          classification: 'INFERRED',
        },
      ],
      timeline: [
        { id: 'TL-23', timestamp: subMinutes(360), title: 'Shadow Copy Deletion Blocked', description: 'EDR heuristic intercepted vssadmin invocation', category: 'EVENT' },
        { id: 'TL-24', timestamp: subMinutes(359), title: 'Canary Alarm Fired', description: 'Canary file encryption detected on storage array', category: 'EVENT' },
        { id: 'TL-25', timestamp: subMinutes(355), title: 'Incident Escalated to Lead', description: 'Marcus Vance assigned critical priority containment', category: 'STATUS' },
      ],
      analystNotes: [
        { id: 'NOTE-05', author: 'Marcus Vance', authorRole: 'LEAD', timestamp: subMinutes(350), content: 'Immediate network isolation invoked for file server FS-CORP-01. Offline backup validation in progress.' }
      ],
      mitreTechniques: [
        {
          techniqueId: 'T1486',
          techniqueName: 'Data Encrypted for Impact',
          tactic: 'Impact',
          description: 'Attempted mass encryption of enterprise shared directories.',
          mappingType: 'OBSERVED',
          confidence: 0.98,
          source: 'EDR Canary Detection Sensor',
        },
        {
          techniqueId: 'T1059.001',
          techniqueName: 'Command and Scripting Interpreter: PowerShell',
          tactic: 'Execution',
          description: 'PowerShell utilized for execution of obfuscated helper scripts.',
          mappingType: 'OBSERVED',
          confidence: 0.95,
          source: 'Sysmon Process Tree Monitor',
        },
      ],
      recommendedActions: [
        {
          id: 'ACT-012-A',
          action: 'Immediately Isolate File Server FS-CORP-01 from SAN & LAN',
          description: 'Sever network and storage fabric to halt lateral spread',
          target: 'FS-CORP-01',
          priority: 'IMMEDIATE',
          category: 'CONTAINMENT',
          status: 'APPROVED',
        },
        {
          id: 'ACT-012-B',
          action: 'Lock Domain Admin Accounts Involved in Session',
          description: 'Prevent further domain-wide privilege abuse',
          target: 'Active Directory Domain',
          priority: 'IMMEDIATE',
          category: 'CONTAINMENT',
          status: 'PENDING_REVIEW',
        },
      ],
      relatedAlerts: [
        {
          alertId: 'CNX-004',
          title: 'Known Malicious Binary Hash (LockNexus Loader)',
          severity: 'CRITICAL',
          relationshipReason: 'Matching ransomware malware family and second-stage payload lineage',
          indicator: 'e3b0c442...b855',
          timestamp: subMinutes(65),
        },
      ],
    },
  ];
}

// Ensure database is initialized on load
initializeDatabase();

export const Database = {
  getAlerts(): Alert[] {
    return [...alertsStore];
  },

  getAlertById(id: string): Alert | null {
    const alert = alertsStore.find(a => a.id.toLowerCase() === id.toLowerCase());
    return alert ? { ...alert } : null;
  },

  updateAlertStatus(
    id: string,
    newStatus: AlertStatus,
    actorName: string = 'Analyst',
    resolutionNote?: string
  ): { success: boolean; alert?: Alert; error?: string } {
    const alert = alertsStore.find(a => a.id.toLowerCase() === id.toLowerCase());
    if (!alert) {
      return { success: false, error: 'Alert not found' };
    }

    // Validate state transitions
    const validTransitions: Record<AlertStatus, AlertStatus[]> = {
      NEW: ['TRIAGED', 'INVESTIGATING', 'FALSE_POSITIVE'],
      TRIAGED: ['INVESTIGATING', 'CONTAINMENT_RECOMMENDED', 'RESOLVED', 'FALSE_POSITIVE'],
      INVESTIGATING: ['CONTAINMENT_RECOMMENDED', 'RESOLVED', 'FALSE_POSITIVE'],
      CONTAINMENT_RECOMMENDED: ['RESOLVED', 'INVESTIGATING', 'FALSE_POSITIVE'],
      RESOLVED: ['INVESTIGATING'], // Re-open
      FALSE_POSITIVE: ['INVESTIGATING'], // Re-open
    };

    if (alert.status !== newStatus && !validTransitions[alert.status]?.includes(newStatus)) {
      return {
        success: false,
        error: `Invalid status transition from ${alert.status} to ${newStatus}. Valid transitions are: ${validTransitions[alert.status]?.join(', ') || 'none'}`,
      };
    }

    // If resolving or marking false positive, require analyst note
    if ((newStatus === 'RESOLVED' || newStatus === 'FALSE_POSITIVE') && (!resolutionNote || resolutionNote.trim().length < 5)) {
      return {
        success: false,
        error: 'A detailed resolution note (at least 5 characters) is mandatory to resolve or mark an incident as false positive.',
      };
    }

    const previousStatus = alert.status;
    alert.status = newStatus;
    const timestamp = new Date().toISOString();

    if (newStatus === 'RESOLVED' || newStatus === 'FALSE_POSITIVE') {
      alert.resolutionNote = resolutionNote;
      alert.resolvedAt = timestamp;
      alert.resolvedBy = actorName;
    }

    // Add timeline entry
    alert.timeline.push({
      id: `TL-STATUS-${Date.now()}`,
      timestamp,
      title: `Status Changed: ${previousStatus} → ${newStatus}`,
      description: resolutionNote ? `Resolution Note: ${resolutionNote}` : `Updated by ${actorName}`,
      category: 'STATUS',
      actor: actorName,
    });

    if (resolutionNote) {
      alert.analystNotes.push({
        id: `NOTE-RES-${Date.now()}`,
        author: actorName,
        authorRole: 'ANALYST',
        timestamp,
        content: `[Resolution Note] ${resolutionNote}`,
      });
    }

    return { success: true, alert: { ...alert } };
  },

  addAnalystNote(
    id: string,
    content: string,
    author: string = 'Elena Rostova',
    authorRole: 'ANALYST' | 'LEAD' | 'ADMIN' = 'ANALYST'
  ): { success: boolean; alert?: Alert; note?: AnalystNote; error?: string } {
    const alert = alertsStore.find(a => a.id.toLowerCase() === id.toLowerCase());
    if (!alert) {
      return { success: false, error: 'Alert not found' };
    }
    if (!content || content.trim() === '') {
      return { success: false, error: 'Note content cannot be empty' };
    }

    const newNote: AnalystNote = {
      id: `NOTE-${Date.now()}`,
      author,
      authorRole,
      timestamp: new Date().toISOString(),
      content: content.trim(),
    };

    alert.analystNotes.push(newNote);

    alert.timeline.push({
      id: `TL-NOTE-${Date.now()}`,
      timestamp: newNote.timestamp,
      title: `Analyst Note Added by ${author}`,
      description: content.length > 80 ? content.slice(0, 80) + '...' : content,
      category: 'ANALYST',
      actor: author,
    });

    return { success: true, alert: { ...alert }, note: newNote };
  },

  updateRecommendedAction(
    alertId: string,
    actionId: string,
    newStatus: 'PENDING_REVIEW' | 'APPROVED' | 'DISMISSED',
    actor: string = 'Elena Rostova'
  ): { success: boolean; alert?: Alert; error?: string } {
    const alert = alertsStore.find(a => a.id.toLowerCase() === alertId.toLowerCase());
    if (!alert) return { success: false, error: 'Alert not found' };

    const action = alert.recommendedActions.find(act => act.id === actionId);
    if (!action) return { success: false, error: 'Action not found' };

    action.status = newStatus;
    const timestamp = new Date().toISOString();

    alert.timeline.push({
      id: `TL-ACT-${Date.now()}`,
      timestamp,
      title: `Response Action ${newStatus}: ${action.action}`,
      description: `Target: ${action.target} - Updated by ${actor}`,
      category: 'ANALYST',
      actor,
    });

    return { success: true, alert: { ...alert } };
  },

  addEvidence(alertId: string, evidence: Omit<EvidenceItem, 'id' | 'timestamp'>): EvidenceItem | null {
    const alert = alertsStore.find(a => a.id.toLowerCase() === alertId.toLowerCase());
    if (!alert) return null;

    const newEvidence: EvidenceItem = {
      id: `EVD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      ...evidence,
    };
    alert.evidenceList.push(newEvidence);
    return newEvidence;
  },

  setAlertAiAssessment(alertId: string, assessment: Alert['aiAssessment']): boolean {
    const alert = alertsStore.find(a => a.id.toLowerCase() === alertId.toLowerCase());
    if (!alert) return false;
    alert.aiAssessment = assessment;
    alert.timeline.push({
      id: `TL-AI-${Date.now()}`,
      timestamp: new Date().toISOString(),
      title: 'AI Security Analyst Assessment Completed',
      description: `Confidence: ${Math.round((assessment?.confidence || 0) * 100)}% - Classified as ${assessment?.assessment}`,
      category: 'AI',
      actor: assessment?.provider || 'AI Engine',
    });
    return true;
  },

  setAlertThreatIntel(alertId: string, intel: Alert['threatIntel']): boolean {
    const alert = alertsStore.find(a => a.id.toLowerCase() === alertId.toLowerCase());
    if (!alert) return false;
    alert.threatIntel = intel;
    alert.timeline.push({
      id: `TL-TI-${Date.now()}`,
      timestamp: new Date().toISOString(),
      title: 'Threat Intelligence Enrichment Completed',
      description: intel?.summary || 'TI providers queried',
      category: 'TI',
      actor: 'Threat Intelligence Router',
    });
    return true;
  },

  getDashboardStats(): SocDashboardStats {
    const alerts = alertsStore;
    const totalAlerts = alerts.length;
    const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL').length;
    const highAlerts = alerts.filter(a => a.severity === 'HIGH').length;
    const mediumAlerts = alerts.filter(a => a.severity === 'MEDIUM').length;
    const lowAlerts = alerts.filter(a => a.severity === 'LOW' || a.severity === 'INFO').length;

    const openIncidents = alerts.filter(a => a.status === 'NEW' || a.status === 'TRIAGED').length;
    const investigatingIncidents = alerts.filter(a => a.status === 'INVESTIGATING' || a.status === 'CONTAINMENT_RECOMMENDED').length;
    const resolvedIncidents = alerts.filter(a => a.status === 'RESOLVED').length;
    const falsePositives = alerts.filter(a => a.status === 'FALSE_POSITIVE').length;

    const avgRiskScore = Math.round(alerts.reduce((acc, a) => acc + a.riskScore, 0) / (totalAlerts || 1));

    const riskDistribution = [
      { range: '0-24 (Low)', count: alerts.filter(a => a.riskScore < 25).length },
      { range: '25-49 (Medium)', count: alerts.filter(a => a.riskScore >= 25 && a.riskScore < 50).length },
      { range: '50-74 (High)', count: alerts.filter(a => a.riskScore >= 50 && a.riskScore < 75).length },
      { range: '75-100 (Critical)', count: alerts.filter(a => a.riskScore >= 75).length },
    ];

    const alertTrend = [
      { time: '06:00', count: 1 },
      { time: '08:00', count: 2 },
      { time: '10:00', count: 4 },
      { time: '12:00', count: 2 },
      { time: '14:00', count: 5 },
      { time: '16:00', count: 3 },
      { time: 'Now', count: alerts.length },
    ];

    const mitreCounts: Record<string, { id: string; name: string; count: number }> = {};
    for (const a of alerts) {
      if (a.mitreTechniques) {
        for (const t of a.mitreTechniques) {
          if (!mitreCounts[t.techniqueId]) {
            mitreCounts[t.techniqueId] = { id: t.techniqueId, name: t.techniqueName, count: 0 };
          }
          mitreCounts[t.techniqueId].count++;
        }
      }
    }

    const mitreTopTechniques = Object.values(mitreCounts)
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const topIndicators = alerts
      .map(a => ({
        indicator: a.indicator,
        type: a.indicatorType,
        severity: a.severity,
        count: 1,
      }))
      .slice(0, 5);

    return {
      totalAlerts,
      criticalAlerts,
      highAlerts,
      mediumAlerts,
      lowAlerts,
      openIncidents,
      investigatingIncidents,
      resolvedIncidents,
      falsePositives,
      avgRiskScore,
      riskDistribution,
      alertTrend,
      mitreTopTechniques,
      topIndicators,
    };
  },

  resetDemoState(): void {
    initializeDatabase();
  },
};
