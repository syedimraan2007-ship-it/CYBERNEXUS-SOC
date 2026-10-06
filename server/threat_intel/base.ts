/**
 * CYBERNEXUS SOC - Threat Intelligence Provider Interface & Base Types
 */

import { IndicatorType, ThreatIntelProviderResult, ThreatIntelStatus } from '../../src/types/soc';

export interface ThreatIntelProvider {
  name: string;
  isConfigured(): boolean;
  lookup(indicator: string, type: IndicatorType): Promise<ThreatIntelProviderResult>;
}

export function createUnavailableResult(
  providerName: string,
  indicator: string,
  type: IndicatorType,
  status: ThreatIntelStatus = 'UNAVAILABLE',
  errorMessage: string = 'Provider API key not configured or service unreachable. DATA NOT AVAILABLE.'
): ThreatIntelProviderResult {
  return {
    provider: providerName,
    status,
    indicator,
    indicatorType: type,
    reputation: 'UNKNOWN',
    score: 0,
    confidence: 0,
    details: {
      statusReason: errorMessage,
      verifiedEvidence: 'NO VERIFIED EVIDENCE'
    },
    synthetic: false,
    queriedAt: new Date().toISOString(),
    errorMessage
  };
}
