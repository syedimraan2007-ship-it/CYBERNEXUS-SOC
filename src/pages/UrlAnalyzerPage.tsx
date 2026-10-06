import React, { useState } from 'react';
import { analyzeUrl } from '../services/api';
import { UrlFeatures, RiskScoreResult, ThreatIntelEnrichment, AiAnalystAssessment, MitreTechnique } from '../types/soc';
import { RiskScoreMeter } from '../components/RiskScoreMeter';
import { SeverityBadge } from '../components/SeverityBadge';
import {
  Search,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Unlock,
  Cpu,
  Layers,
  Sparkles,
  Info,
  ArrowRight,
  Shield,
} from 'lucide-react';

interface UrlAnalyzerPageProps {
  initialUrl?: string;
  onOpenInvestigation?: (alertId: string) => void;
}

export const UrlAnalyzerPage: React.FC<UrlAnalyzerPageProps> = ({ initialUrl = '' }) => {
  const [urlInput, setUrlInput] = useState(
    initialUrl || 'http://login.secure-sso.verify-portal.account-update.test/auth/login?user=jdoe'
  );
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [features, setFeatures] = useState<UrlFeatures | null>(null);
  const [riskScore, setRiskScore] = useState<RiskScoreResult | null>(null);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelEnrichment | null>(null);
  const [aiAssessment, setAiAssessment] = useState<AiAnalystAssessment | null>(null);
  const [mitreCandidates, setMitreCandidates] = useState<MitreTechnique[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const sampleUrls = [
    {
      label: 'Synthetic Credential Phish',
      url: 'http://login.secure-sso.verify-portal.account-update.test/auth/login?user=jdoe',
    },
    {
      label: 'Homograph Punycode Spoof',
      url: 'http://xn--gogle-pra.test/security-checkpoint/login',
    },
    {
      label: 'Raw IP Host Direct Routing',
      url: 'http://198.51.100.45:8080/bank/verify-account',
    },
    {
      label: 'Obfuscated Credential Delimiter (@)',
      url: 'http://trusted-corp.test@attacker-controlled.test/auth/update',
    },
    {
      label: 'Benign Corporate Portal',
      url: 'https://internal-portal.corp.example.test/docs/handbook',
    },
  ];

  const handleAnalyze = async (targetUrl?: string) => {
    const url = targetUrl || urlInput;
    if (!url.trim()) return;

    setIsAnalyzing(true);
    setErrorMessage(null);

    try {
      const result = await analyzeUrl(url.trim());
      setFeatures(result.features);
      setRiskScore(result.riskScore);
      setThreatIntel(result.threatIntel);
      setAiAssessment(result.aiAssessment);
      setMitreCandidates(result.mitreCandidates);
    } catch (err: unknown) {
      setErrorMessage((err as Error).message || 'Analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6 pb-24 md:pb-12 max-w-5xl mx-auto">
      {/* 1. Header Banner */}
      <div className="bg-slate-900 border border-slate-800 p-4 sm:p-5 rounded-xl shadow-lg">
        <div className="flex items-center gap-2">
          <div className="p-2 bg-red-600/20 text-red-400 rounded-lg border border-red-500/40">
            <Search size={20} />
          </div>
          <div>
            <h1 className="text-lg sm:text-xl font-bold text-white tracking-tight flex items-center gap-2">
              Deterministic Phishing URL Feature Analyzer
              <span className="text-[10px] bg-red-950 text-red-300 border border-red-700/50 px-2 py-0.5 rounded font-mono font-medium">
                ANTI-SSRF ENFORCED
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Structural lexical parsing and threat intelligence enrichment without executing outbound web requests.
            </p>
          </div>
        </div>

        {/* Strict Safety Notice */}
        <div className="mt-3 p-2.5 bg-slate-950 rounded border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2">
          <Info size={14} className="text-amber-400 shrink-0 mt-0.5" />
          <span>
            <strong>Safety Enforcement:</strong> The backend NEVER fetches user-submitted URLs directly. Only mathematical string attributes (entropy, subdomain count, punycode, TLD) and verified threat intelligence catalogs are analyzed.
          </span>
        </div>
      </div>

      {/* 2. Input Form & Presets */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-3">
        <div className="flex flex-col sm:flex-row gap-2">
          <input
            type="text"
            value={urlInput}
            onChange={e => setUrlInput(e.target.value)}
            placeholder="Enter URL to inspect (e.g. http://login.verify-portal.account-update.test)..."
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-red-500 font-mono"
          />
          <button
            onClick={() => handleAnalyze()}
            disabled={isAnalyzing}
            className="px-5 py-2.5 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition-colors shrink-0 shadow-lg shadow-red-950/40 min-h-[44px]"
          >
            <Search size={15} />
            <span>{isAnalyzing ? 'Extracting Signals...' : 'Extract & Score'}</span>
          </button>
        </div>

        {/* Quick Sample Selector */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-[11px] text-slate-500 font-mono">Sample Presets:</span>
          {sampleUrls.map(item => (
            <button
              key={item.label}
              onClick={() => {
                setUrlInput(item.url);
                handleAnalyze(item.url);
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

      {/* 3. Results Section */}
      {features && riskScore && (
        <div className="space-y-4">
          {/* Risk Score Summary Banner */}
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={riskScore.severity} size="md" />
                <span className="font-mono text-xs text-slate-400">
                  Calculated: {new Date(riskScore.calculationTimestamp).toLocaleTimeString()}
                </span>
              </div>
              <h2 className="text-sm font-bold text-white">
                Deterministic Risk Score: {riskScore.score} / 100
              </h2>
              <p className="text-xs text-slate-300">{riskScore.explanation}</p>
            </div>
            <div className="shrink-0">
              <RiskScoreMeter score={riskScore.score} severity={riskScore.severity} size="lg" />
            </div>
          </div>

          {/* Lexical Structural Feature Breakdown */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                Extracted Structural Features
              </h3>
              <span className="text-[10px] font-mono text-slate-400">
                Signals for Heuristic Rule Engine
              </span>
            </div>

            <div className="p-4 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5 text-xs">
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-0.5">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">Registered Domain</span>
                <span className="font-mono font-bold text-slate-200 text-xs truncate block" title={features.registeredDomain}>
                  {features.registeredDomain}
                </span>
              </div>

              <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-0.5">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">Encryption Protocol</span>
                <span className={`font-mono font-bold text-xs flex items-center gap-1 ${features.isHttps ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {features.isHttps ? <Lock size={12} /> : <Unlock size={12} />}
                  {features.protocol.toUpperCase()}
                </span>
              </div>

              <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-0.5">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">Host is Raw IP</span>
                <span className={`font-mono font-bold text-xs ${features.hostIsIp ? 'text-red-400' : 'text-slate-300'}`}>
                  {features.hostIsIp ? 'TRUE (Direct Routing)' : 'FALSE (Domain Name)'}
                </span>
              </div>

              <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-0.5">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">Subdomain Depth</span>
                <span className={`font-mono font-bold text-xs ${features.subdomainCount >= 3 ? 'text-orange-400' : 'text-slate-300'}`}>
                  {features.subdomainCount} subdomains
                </span>
              </div>

              <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-0.5">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">URL String Length</span>
                <span className={`font-mono font-bold text-xs ${features.urlLength > 100 ? 'text-amber-400' : 'text-slate-300'}`}>
                  {features.urlLength} characters
                </span>
              </div>

              <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-0.5">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">Punycode / Homograph</span>
                <span className={`font-mono font-bold text-xs ${features.isPunycode ? 'text-red-400' : 'text-slate-300'}`}>
                  {features.isPunycode ? 'DETECTED (xn--)' : 'NONE'}
                </span>
              </div>

              <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-0.5">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">Contains '@' Symbol</span>
                <span className={`font-mono font-bold text-xs ${features.containsAtSymbol ? 'text-red-400' : 'text-slate-300'}`}>
                  {features.containsAtSymbol ? 'YES (Obfuscation)' : 'NO'}
                </span>
              </div>

              <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-0.5">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">Lexical Entropy</span>
                <span className={`font-mono font-bold text-xs ${features.entropy > 4.2 ? 'text-amber-400' : 'text-slate-300'}`}>
                  {features.entropy} bits
                </span>
              </div>
            </div>

            {/* Sensitive Keywords Found */}
            {features.suspiciousKeywordsFound.length > 0 && (
              <div className="px-4 pb-3">
                <div className="p-2.5 bg-red-950/40 border border-red-800/40 rounded-lg flex items-center gap-2">
                  <span className="font-mono text-[11px] text-red-300 font-semibold">
                    Targeted Auth Keywords Identified:
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {features.suspiciousKeywordsFound.map(kw => (
                      <span key={kw} className="bg-red-900/60 text-red-200 border border-red-700/50 px-2 py-0.5 rounded font-mono text-[10px]">
                        {kw}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* AI Security Analyst Explanation Card */}
          {aiAssessment && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 space-y-3">
              <div className="flex items-center gap-2">
                <Sparkles size={16} className="text-red-400" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                  AI Security Analyst Explanation ({aiAssessment.model})
                </h3>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                {aiAssessment.summary}
              </p>
              <div className="text-[11px] text-slate-400 italic">
                {aiAssessment.disclaimer}
              </div>
            </div>
          )}

          {/* MITRE Candidate Technique */}
          {mitreCandidates.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-white block">
                Candidate MITRE ATT&CK Enterprise Techniques
              </span>
              {mitreCandidates.map(m => (
                <div key={m.techniqueId} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between text-xs">
                  <div>
                    <span className="font-mono font-bold text-red-400">{m.techniqueId}: {m.techniqueName}</span>
                    <span className="text-slate-400 block text-[11px] mt-0.5">Tactic: {m.tactic} · Status: {m.mappingType}</span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-2 py-1 rounded">
                    Confidence: {Math.round(m.confidence * 100)}%
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
