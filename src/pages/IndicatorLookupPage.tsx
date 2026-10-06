import React, { useState } from 'react';
import { analyzeIndicator } from '../services/api';
import { IndicatorType, RiskScoreResult, ThreatIntelEnrichment, AiAnalystAssessment, MitreTechnique } from '../types/soc';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskScoreMeter } from '../components/RiskScoreMeter';
import {
  Globe,
  Search,
  Activity,
  Layers,
  Sparkles,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Info,
} from 'lucide-react';

export const IndicatorLookupPage: React.FC = () => {
  const [indicatorInput, setIndicatorInput] = useState('198.51.100.45');
  const [indicatorType, setIndicatorType] = useState<IndicatorType>('IP');
  const [isSearching, setIsSearching] = useState(false);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelEnrichment | null>(null);
  const [riskScore, setRiskScore] = useState<RiskScoreResult | null>(null);
  const [aiAssessment, setAiAssessment] = useState<AiAnalystAssessment | null>(null);
  const [mitreCandidates, setMitreCandidates] = useState<MitreTechnique[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const presets = [
    { label: 'C2 Beacon IP (Documentation RFC)', indicator: '198.51.100.45', type: 'IP' as IndicatorType },
    { label: 'LockNexus Ransomware Hash', indicator: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', type: 'HASH' as IndicatorType },
    { label: 'Typosquatted Brand Domain', indicator: 'cybernexus-security-auth.test', type: 'DOMAIN' as IndicatorType },
    { label: 'Clean Internal Gateway IP', indicator: '192.0.2.1', type: 'IP' as IndicatorType },
  ];

  const handleLookup = async (targetInd?: string, targetType?: IndicatorType) => {
    const ind = targetInd || indicatorInput;
    const type = targetType || indicatorType;
    if (!ind.trim()) return;

    setIsSearching(true);
    setErrorMessage(null);

    try {
      const result = await analyzeIndicator(ind.trim(), type);
      setThreatIntel(result.threatIntel);
      setRiskScore(result.riskScore);
      setAiAssessment(result.aiAssessment);
      setMitreCandidates(result.mitreCandidates || []);
    } catch (err: unknown) {
      setErrorMessage((err as Error).message || 'Lookup failed');
    } finally {
      setIsSearching(false);
    }
  };

  return (
    <div className="space-y-6 pb-24 md:pb-12 max-w-5xl mx-auto">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 p-4 sm:p-5 rounded-xl shadow-lg">
        <div className="flex items-center gap-2">
          <div className="p-2 bg-blue-600/20 text-blue-400 rounded-lg border border-blue-500/40">
            <Globe size={20} />
          </div>
          <div>
            <h1 className="text-lg sm:text-xl font-bold text-white tracking-tight flex items-center gap-2">
              Threat Intelligence & Indicator Analyzer
              <span className="text-[10px] bg-amber-950 text-amber-300 border border-amber-800/50 px-2 py-0.5 rounded font-mono font-medium">
                SYNTHETIC CATALOG
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Query IP addresses, domains, and cryptographic file hashes across multi-provider threat intelligence.
            </p>
          </div>
        </div>
      </div>

      {/* Input Form */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-3">
        <div className="flex flex-col sm:flex-row gap-2">
          <select
            value={indicatorType}
            onChange={e => setIndicatorType(e.target.value as IndicatorType)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500 shrink-0"
          >
            <option value="IP">IP Address</option>
            <option value="DOMAIN">Domain</option>
            <option value="HASH">File Hash</option>
            <option value="URL">URL String</option>
          </select>

          <input
            type="text"
            value={indicatorInput}
            onChange={e => setIndicatorInput(e.target.value)}
            placeholder="Enter indicator (e.g. 198.51.100.45 or SHA256 hash)..."
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-red-500 font-mono"
          />

          <button
            onClick={() => handleLookup()}
            disabled={isSearching}
            className="px-5 py-2.5 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition-colors shrink-0 shadow-lg min-h-[44px]"
          >
            <Search size={15} />
            <span>{isSearching ? 'Querying Intel...' : 'Lookup Indicator'}</span>
          </button>
        </div>

        {/* Presets */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-[11px] text-slate-500 font-mono">Presets:</span>
          {presets.map(item => (
            <button
              key={item.label}
              onClick={() => {
                setIndicatorInput(item.indicator);
                setIndicatorType(item.type);
                handleLookup(item.indicator, item.type);
              }}
              className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-300 text-[11px] font-mono rounded transition-colors"
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {errorMessage && (
        <div className="bg-red-950 border border-red-500/50 p-3 rounded-lg text-xs text-red-300 flex items-center gap-2">
          <AlertTriangle size={15} className="shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Results */}
      {threatIntel && riskScore && (
        <div className="space-y-4">
          {/* Risk Score Summary */}
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={riskScore.severity} size="md" />
                <span className="font-mono text-xs text-slate-400">
                  Reputation: {threatIntel.overallReputation}
                </span>
              </div>
              <h2 className="text-sm font-bold text-white">
                Calculated Risk Score: {riskScore.score} / 100
              </h2>
              <p className="text-xs text-slate-300">{riskScore.explanation}</p>
            </div>
            <div className="shrink-0">
              <RiskScoreMeter score={riskScore.score} severity={riskScore.severity} size="lg" />
            </div>
          </div>

          {/* Provider Results Breakdown */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
              Threat Intelligence Providers
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
              {threatIntel.providers.map(p => (
                <div key={p.provider} className="bg-slate-950 border border-slate-800 p-3 rounded-lg space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">{p.provider}</span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      p.status === 'SUCCESS' ? 'text-emerald-400 bg-emerald-950 border border-emerald-800/40' : 'text-slate-400 bg-slate-900'
                    }`}>
                      {p.status}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400">
                    Reputation: <span className={p.reputation === 'MALICIOUS' ? 'text-red-400 font-bold' : 'text-slate-300'}>{p.reputation}</span>
                  </div>
                  {p.details && (
                    <div className="text-[10px] text-slate-500 truncate" title={JSON.stringify(p.details)}>
                      {Object.entries(p.details).slice(0, 2).map(([k, v]) => `${k}: ${v}`).join(' | ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* AI Security Assessment */}
          {aiAssessment && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2">
                <Sparkles size={16} className="text-red-400" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                  AI Security Analyst Explanation ({aiAssessment.model})
                </h3>
              </div>
              <p className="text-xs text-slate-300 bg-slate-950 p-3 rounded-lg border border-slate-800 leading-relaxed">
                {aiAssessment.summary}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
