/**
 * CYBERNEXUS SOC - MITRE ATT&CK Enterprise Integration
 * Enterprise Tactics & Techniques dataset with candidate mapping logic.
 */

import { MitreTechnique } from '../../src/types/soc';

export interface MitreTacticDefinition {
  id: string;
  name: string;
  shortName: string;
  description: string;
}

export interface MitreTechniqueDefinition {
  id: string;
  name: string;
  tacticId: string;
  tacticName: string;
  description: string;
  detectionGuidance: string;
  mitigation: string;
}

export const MITRE_TACTICS: MitreTacticDefinition[] = [
  { id: 'TA0043', name: 'Reconnaissance', shortName: 'Recon', description: 'Gather information to plan future adversary operations' },
  { id: 'TA0042', name: 'Resource Development', shortName: 'Resource Dev', description: 'Establish resources adversaries need to support operations' },
  { id: 'TA0001', name: 'Initial Access', shortName: 'Initial Access', description: 'Adversary is trying to get into your network' },
  { id: 'TA0002', name: 'Execution', shortName: 'Execution', description: 'Adversary is trying to run malicious code' },
  { id: 'TA0003', name: 'Persistence', shortName: 'Persistence', description: 'Adversary is trying to maintain their foothold' },
  { id: 'TA0004', name: 'Privilege Escalation', shortName: 'Priv Escalation', description: 'Adversary is trying to gain higher-level permissions' },
  { id: 'TA0005', name: 'Defense Evasion', shortName: 'Defense Evasion', description: 'Adversary is trying to avoid being detected' },
  { id: 'TA0006', name: 'Credential Access', shortName: 'Credential Access', description: 'Adversary is trying to steal account names and passwords' },
  { id: 'TA0007', name: 'Discovery', shortName: 'Discovery', description: 'Adversary is trying to figure out your environment' },
  { id: 'TA0008', name: 'Lateral Movement', shortName: 'Lateral Movement', description: 'Adversary is trying to move through your environment' },
  { id: 'TA0009', name: 'Collection', shortName: 'Collection', description: 'Adversary is trying to gather data of interest' },
  { id: 'TA0011', name: 'Command and Control', shortName: 'C2', description: 'Adversary is trying to communicate with compromised systems' },
  { id: 'TA0010', name: 'Exfiltration', shortName: 'Exfiltration', description: 'Adversary is trying to steal data' },
  { id: 'TA0040', name: 'Impact', shortName: 'Impact', description: 'Adversary is trying to manipulate, interrupt, or destroy systems' },
];

export const MITRE_TECHNIQUES_DATABASE: Record<string, MitreTechniqueDefinition> = {
  'T1566.002': {
    id: 'T1566.002',
    name: 'Phishing: Spearphishing Link',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    description: 'Adversaries send spearphishing messages with malicious links to lure victims into opening malicious URLs, often directing to credential harvesting pages or payload delivery.',
    detectionGuidance: 'Analyze incoming email logs, proxy/DNS logs for newly observed domains, URL entropy, homograph characters, and credential entry on unauthorized sites.',
    mitigation: 'Implement email authentication (SPF, DKIM, DMARC), anti-spoofing gateway filters, web reputation controls, and multi-factor authentication (MFA).'
  },
  'T1204.002': {
    id: 'T1204.002',
    name: 'User Execution: Malicious File',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    description: 'An adversary relies upon a user opening a malicious file in order to execute unauthorized code on the victim system.',
    detectionGuidance: 'Monitor process creation events (Sysmon Event ID 1), file download events from web browsers, and file hashes against threat intelligence databases.',
    mitigation: 'Block execution of untrusted scripts/macros, enforce application control policies, and isolate untrusted file downloads in secure sandboxes.'
  },
  'T1110': {
    id: 'T1110',
    name: 'Brute Force',
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    description: 'Adversaries may use brute force techniques to attempt credential guessing or password spraying against target authentication endpoints.',
    detectionGuidance: 'Aggregate authentication logs to detect high-frequency failed logins from single IP addresses or distributed spray attempts across multiple user accounts.',
    mitigation: 'Implement account lockout policies, rate limiting on login APIs, CAPTCHA, and enforce phishing-resistant MFA.'
  },
  'T1078': {
    id: 'T1078',
    name: 'Valid Accounts',
    tacticId: 'TA0005',
    tacticName: 'Defense Evasion',
    description: 'Adversaries obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
    detectionGuidance: 'Correlate anomalous login locations (impossible travel), unusual time of day, novel device fingerprints, and abnormal access to sensitive resources.',
    mitigation: 'Enforce strict conditional access policies, continuous access evaluation, and rapid credential revocation upon anomaly detection.'
  },
  'T1071.004': {
    id: 'T1071.004',
    name: 'Application Layer Protocol: DNS',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries communicate using the Domain Name System (DNS) application layer protocol to conceal C2 activity or tunnel exfiltrated data through TXT/A queries.',
    detectionGuidance: 'Analyze recursive DNS logs for high volume of subdomains under single root domains, high query entropy, unusual query types, and long request payloads.',
    mitigation: 'Deploy DNS firewall / RPZ (Response Policy Zone), inspect recursive resolver telemetry, and block requests to newly registered or unclassified domains.'
  },
  'T1071.001': {
    id: 'T1071.001',
    name: 'Application Layer Protocol: Web Protocols',
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    description: 'Adversaries communicate using application layer web protocols (HTTP/HTTPS) to blend C2 traffic with normal inbound and outbound web browsing.',
    detectionGuidance: 'Inspect network traffic for periodic beaconing patterns, unusual User-Agent strings, direct IP connections, or abnormal TLS certificate characteristics.',
    mitigation: 'Implement SSL/TLS decryption and inspection proxies, network egress filtering, and web content filtering.'
  },
  'T1583.001': {
    id: 'T1583.001',
    name: 'Acquire Infrastructure: Domains',
    tacticId: 'TA0042',
    tacticName: 'Resource Development',
    description: 'Adversaries acquire domains that can be used during targeting. Domains may be registered with deceptive names (typosquatting or brand spoofing).',
    detectionGuidance: 'Monitor certificate transparency logs and newly registered domain feeds for brand keywords and typosquat variations.',
    mitigation: 'Proactively register defensive brand domain variants and leverage threat intelligence feeds that track adversary infrastructure.'
  },
  'T1059.001': {
    id: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    description: 'Adversaries abuse PowerShell commands and scripts to execute actions, download payloads, and interact with the Windows operating system.',
    detectionGuidance: 'Enable Script Block Logging (Event ID 4104) and Transcription. Look for encoded commands (-enc), bypass flags (-ExecutionPolicy Bypass), and web download invocations.',
    mitigation: 'Enforce PowerShell Constrained Language Mode, AppLocker / Windows Defender Application Control (WDAC), and disable PowerShell v2.'
  },
  'T1486': {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tacticId: 'TA0040',
    tacticName: 'Impact',
    description: 'Adversaries encrypt data on target systems to interrupt availability to system and network resources, often extorting the victim (Ransomware).',
    detectionGuidance: 'Detect high-volume file modification bursts, mass file extension changes, volume shadow copy deletion commands (vssadmin delete shadows), and canary file modifications.',
    mitigation: 'Maintain immutable offline backups, restrict administrative service access, and implement endpoint behavior-based ransomware protection.'
  }
};

export function lookupMitreTechnique(id: string): MitreTechniqueDefinition | null {
  return MITRE_TECHNIQUES_DATABASE[id] || null;
}

export function getAllMitreTechniques(): MitreTechniqueDefinition[] {
  return Object.values(MITRE_TECHNIQUES_DATABASE);
}

export function mapEventToMitreCandidates(eventType: string, indicatorType?: string): MitreTechnique[] {
  const candidates: MitreTechnique[] = [];

  switch (eventType.toLowerCase()) {
    case 'phishing_url':
    case 'spearphishing_link':
    case 'phishing': {
      const t = MITRE_TECHNIQUES_DATABASE['T1566.002'];
      if (t) {
        candidates.push({
          techniqueId: t.id,
          techniqueName: t.name,
          tactic: t.tacticName,
          description: t.description,
          mappingType: 'OBSERVED',
          confidence: 0.95,
          source: 'Rule Engine: URL Structure & Phishing Heuristics',
        });
      }
      break;
    }
    case 'malware_hash':
    case 'file_hash':
    case 'malicious_binary': {
      const t = MITRE_TECHNIQUES_DATABASE['T1204.002'];
      if (t) {
        candidates.push({
          techniqueId: t.id,
          techniqueName: t.name,
          tactic: t.tacticName,
          description: t.description,
          mappingType: 'OBSERVED',
          confidence: 0.90,
          source: 'Rule Engine: Malicious File Hash Detection',
        });
      }
      break;
    }
    case 'failed_login_burst':
    case 'brute_force': {
      const t = MITRE_TECHNIQUES_DATABASE['T1110'];
      if (t) {
        candidates.push({
          techniqueId: t.id,
          techniqueName: t.name,
          tactic: t.tacticName,
          description: t.description,
          mappingType: 'OBSERVED',
          confidence: 0.92,
          source: 'Rule Engine: Authentication Anomaly Correlator',
        });
      }
      break;
    }
    case 'impossible_travel':
    case 'unusual_login':
    case 'compromised_account': {
      const t = MITRE_TECHNIQUES_DATABASE['T1078'];
      if (t) {
        candidates.push({
          techniqueId: t.id,
          techniqueName: t.name,
          tactic: t.tacticName,
          description: t.description,
          mappingType: 'INFERRED',
          confidence: 0.85,
          source: 'Rule Engine: Identity Geo-temporal Anomaly',
        });
      }
      break;
    }
    case 'suspicious_dns':
    case 'dns_tunneling': {
      const t = MITRE_TECHNIQUES_DATABASE['T1071.004'];
      if (t) {
        candidates.push({
          techniqueId: t.id,
          techniqueName: t.name,
          tactic: t.tacticName,
          description: t.description,
          mappingType: 'OBSERVED',
          confidence: 0.88,
          source: 'Rule Engine: High-Entropy DNS Resolver Monitor',
        });
      }
      break;
    }
    case 'suspicious_ip':
    case 'c2_beacon': {
      const t = MITRE_TECHNIQUES_DATABASE['T1071.001'];
      if (t) {
        candidates.push({
          techniqueId: t.id,
          techniqueName: t.name,
          tactic: t.tacticName,
          description: t.description,
          mappingType: 'INFERRED',
          confidence: 0.80,
          source: 'Rule Engine: Egress C2 Pattern Analyzer',
        });
      }
      break;
    }
    case 'suspicious_domain':
    case 'typosquat_domain': {
      const t = MITRE_TECHNIQUES_DATABASE['T1583.001'];
      if (t) {
        candidates.push({
          techniqueId: t.id,
          techniqueName: t.name,
          tactic: t.tacticName,
          description: t.description,
          mappingType: 'INFERRED',
          confidence: 0.78,
          source: 'Rule Engine: Domain Infrastructure Monitor',
        });
      }
      break;
    }
    default:
      break;
  }

  return candidates;
}
