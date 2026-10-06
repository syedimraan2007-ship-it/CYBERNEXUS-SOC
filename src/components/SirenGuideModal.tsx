import React from 'react';
import {
  Flame,
  CheckCircle,
  ArrowRight,
  ShieldAlert,
  Search,
  Cpu,
  FileText,
  X,
  PlayCircle,
  ExternalLink,
} from 'lucide-react';

interface SirenGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
  onStartChallenge: (alertId: string) => void;
}

export const SirenGuideModal: React.FC<SirenGuideModalProps> = ({
  isOpen,
  onClose,
  onStartChallenge,
}) => {
  if (!isOpen) return null;

  const steps = [
    { num: '01', title: 'New Alert Ingestion', desc: 'Identify critical alert CNX-001 in queue (Credential Harvester).' },
    { num: '02', title: 'Initial Triage', desc: 'Inspect affected indicator, severity badge, and risk score.' },
    { num: '03', title: 'Open Investigation', desc: 'Launch full investigation workspace (/investigations/CNX-001).' },
    { num: '04', title: 'Deterministic Analysis', desc: 'Inspect structural URL feature signals (subdomains, auth keywords).' },
    { num: '05', title: 'Threat Intelligence', desc: 'Enrich indicator against multi-provider TI & local synthetic catalog.' },
    { num: '06', title: 'AI Analyst Assistance', desc: 'Generate explainable reasoning with strict Observed vs Inferred distinction.' },
    { num: '07', title: 'MITRE ATT&CK Mapping', desc: 'Map observed evidence to Enterprise technique T1566.002.' },
    { num: '08', title: 'Review Response Action', desc: 'Review containment proposal (Block domain on web proxy & DNS RPZ).' },
    { num: '09', title: 'Analyst Decision', desc: 'Record human analyst notes and update incident state.' },
    { num: '10', title: 'Resolution & Audit', desc: 'Resolve incident with mandatory audit note.' },
    { num: '11', title: 'Generate PDF Report', desc: 'Export full professional SOC Incident Dossier as downloadable PDF.' },
  ];

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full shadow-2xl overflow-hidden my-auto">
        {/* Header */}
        <div className="bg-gradient-to-r from-red-950/80 via-slate-900 to-slate-900 px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-red-500/20 rounded-lg border border-red-500/40 text-red-400">
              <Flame size={20} />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                5-Minute SOC Siren Challenge
                <span className="text-[10px] bg-red-950 text-red-300 border border-red-700/50 px-2 py-0.5 rounded font-mono">
                  DEMO RUNBOOK
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                End-to-end incident lifecycle from raw alert to generated PDF dossier.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 max-h-[65vh] overflow-y-auto space-y-4 text-xs text-slate-300">
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
            <span className="text-amber-400 font-semibold block mb-1">Fundamental SOC Architecture Principle:</span>
            <p className="text-slate-400 leading-relaxed">
              AI is <strong className="text-slate-200">decision support and explanation</strong>, not autonomous authority. Deterministic rules, evidence classification (<strong className="text-emerald-400">OBSERVED</strong> vs <strong className="text-amber-400">INFERRED</strong>), and human analyst approval are mandatory.
            </p>
          </div>

          <div className="space-y-2">
            <span className="font-mono text-[11px] text-slate-400 font-semibold uppercase tracking-wider block">
              11-Step Rapid Demonstration Runbook:
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {steps.map(step => (
                <div
                  key={step.num}
                  className="bg-slate-950/40 border border-slate-800/80 p-2.5 rounded-lg flex items-start gap-2.5"
                >
                  <span className="font-mono text-[10px] font-bold text-red-400 bg-red-950/40 border border-red-800/30 px-1.5 py-0.5 rounded shrink-0">
                    {step.num}
                  </span>
                  <div>
                    <span className="font-medium text-slate-200 block text-[11px]">{step.title}</span>
                    <span className="text-slate-400 text-[10px] leading-tight block mt-0.5">{step.desc}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="bg-slate-950 px-5 py-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <button
            onClick={onClose}
            className="px-3 py-1.5 text-xs text-slate-400 hover:text-white transition-colors"
          >
            Close Guide
          </button>

          <button
            onClick={() => {
              onClose();
              onStartChallenge('CNX-001');
            }}
            className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white font-medium rounded-lg text-xs flex items-center gap-2 transition-colors shadow-lg shadow-red-950/50"
          >
            <PlayCircle size={15} />
            <span>Launch Siren Challenge on CNX-001</span>
            <ArrowRight size={13} />
          </button>
        </div>
      </div>
    </div>
  );
};
