/**
 * CYBERNEXUS SOC - Synthetic Threat Intelligence Provider
 * Deterministic local intelligence for reserved test domains and documentation IP ranges.
 * All indicators returned by this provider are strictly flagged: synthetic = true.
 */

import { IndicatorType, ThreatIntelProviderResult } from '../../src/types/soc';
import { ThreatIntelProvider } from './base';

export class SyntheticProvider implements ThreatIntelProvider {
  name = 'SyntheticThreatIntel';

  isConfigured(): boolean {
    return true;
  }

  async lookup(indicator: string, type: IndicatorType): Promise<ThreatIntelProviderResult> {
    const ind = indicator.trim().toLowerCase();
    const timestamp = new Date().toISOString();

    // Check for malicious synthetic URLs
    if (type === 'URL' || ind.startsWith('http')) {
      if (ind.includes('secure-login-verify.account-update.test') || ind.includes('198.51.100.45') || ind.includes('phish') || ind.includes('credential')) {
        return {
          provider: this.name,
          status: 'SUCCESS',
          indicator,
          indicatorType: 'URL',
          reputation: 'MALICIOUS',
          score: 94,
          confidence: 0.95,
          details: {
            threatCategory: 'Credential Phishing / Impersonation',
            firstSeen: '2026-10-01T08:12:00Z',
            lastSeen: timestamp,
            tags: ['SYNTHETIC', 'PHISHING', 'CREDENTIAL_HARVESTER'],
            asn: 'AS64496 (Reserved Documentation AS)',
            threatActor: 'APT-SYNTHETIC-DEMO',
            campaign: 'Operation Echo Lure',
            passiveDnsHits: 18,
          },
          synthetic: true,
          queriedAt: timestamp,
        };
      }

      if (ind.includes('internal-portal.corp.example.test') || ind.includes('example.com') || ind.includes('portal.example.test')) {
        return {
          provider: this.name,
          status: 'SUCCESS',
          indicator,
          indicatorType: 'URL',
          reputation: 'BENIGN',
          score: 5,
          confidence: 0.98,
          details: {
            threatCategory: 'Legitimate Corporate Infrastructure',
            firstSeen: '2024-01-15T00:00:00Z',
            lastSeen: timestamp,
            tags: ['SYNTHETIC', 'VERIFIED_CORP', 'BENIGN'],
            asn: 'AS64496 (Reserved Corporate Transit)',
          },
          synthetic: true,
          queriedAt: timestamp,
        };
      }
    }

    // Check for IP indicators (documentation ranges 192.0.2.x, 198.51.100.x, 203.0.113.x)
    if (type === 'IP' || /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ind)) {
      if (ind.includes('198.51.100.77') || ind.includes('203.0.113.195') || ind.includes('198.51.100.45')) {
        return {
          provider: this.name,
          status: 'SUCCESS',
          indicator,
          indicatorType: 'IP',
          reputation: 'MALICIOUS',
          score: 89,
          confidence: 0.92,
          details: {
            threatCategory: 'Command and Control (C2) / Scanning Node',
            country: 'Reserved (ZZ)',
            subnet: '198.51.100.0/24 (RFC 5737 TEST-NET-2)',
            asn: 'AS64496 (Documentation ASN)',
            abuseReportsCount: 42,
            associatedMalware: ['SYNTH-BEACON', 'DEMO-LOADER'],
            openPorts: [443, 8443, 9001],
          },
          synthetic: true,
          queriedAt: timestamp,
        };
      }

      if (ind.includes('192.0.2.1') || ind.includes('10.0.0.1')) {
        return {
          provider: this.name,
          status: 'SUCCESS',
          indicator,
          indicatorType: 'IP',
          reputation: 'BENIGN',
          score: 2,
          confidence: 0.99,
          details: {
            threatCategory: 'Authorized Gateway',
            country: 'Internal',
            subnet: '192.0.2.0/24 (RFC 5737 TEST-NET-1)',
            asn: 'AS64496',
          },
          synthetic: true,
          queriedAt: timestamp,
        };
      }
    }

    // Check for Malware Hash
    if (type === 'HASH' || ind.length === 64 || ind.length === 32) {
      if (ind.includes('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') || ind.includes('a1b2c3d4e5f67890') || ind.includes('d41d8cd98f00b204e9800998ecf8427e') || ind.startsWith('deadbeef') || ind.startsWith('ca7b')) {
        return {
          provider: this.name,
          status: 'SUCCESS',
          indicator,
          indicatorType: 'HASH',
          reputation: 'MALICIOUS',
          score: 96,
          confidence: 0.98,
          details: {
            threatCategory: 'Ransomware Dropper / Infostealer',
            malwareFamily: 'LockNexus.Synthetic',
            fileType: 'PE32+ Executable (GUI) x86-64',
            fileSize: '418,290 bytes',
            imphash: '8a9c8f0e5b12da673410bc394a',
            detectionRatio: '68/72 AV engines',
            signatures: ['Ransomware.Win64.LockNexus', 'Trojan.Downloader.Heuristic'],
          },
          synthetic: true,
          queriedAt: timestamp,
        };
      }
    }

    // Default synthetic fallback when indicator doesn't match specific synthetic test case
    return {
      provider: this.name,
      status: 'NO_DATA',
      indicator,
      indicatorType: type,
      reputation: 'UNKNOWN',
      score: 0,
      confidence: 0.5,
      details: {
        note: 'DATA NOT AVAILABLE in local synthetic threat database for this indicator.',
        verifiedEvidence: 'NO VERIFIED EVIDENCE'
      },
      synthetic: true,
      queriedAt: timestamp,
    };
  }
}
