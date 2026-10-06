import React, { useState } from 'react';
import {
  MITRE_TACTICS,
  MITRE_TECHNIQUES_DATABASE,
  MitreTechniqueDefinition,
} from '../../server/detection/mitre';
import { Grid, Shield, Search, ExternalLink, Info, CheckCircle2 } from 'lucide-react';

export const MitreMatrixPage: React.FC = () => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechniqueDefinition | null>(
    MITRE_TECHNIQUES_DATABASE['T1566.002']
  );
  const [searchFilter, setSearchFilter] = useState('');

  const techniquesList = Object.values(MITRE_TECHNIQUES_DATABASE).filter(t => {
    if (!searchFilter.trim()) return true;
    const q = searchFilter.toLowerCase();
    return (
      t.id.toLowerCase().includes(q) ||
      t.name.toLowerCase().includes(q) ||
      t.tacticName.toLowerCase().includes(q) ||
      t.description.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6 pb-24 md:pb-12 max-w-6xl mx-auto">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 p-4 sm:p-5 rounded-xl shadow-lg">
        <div className="flex items-center gap-2">
          <div className="p-2 bg-purple-600/20 text-purple-400 rounded-lg border border-purple-500/40">
            <Grid size={20} />
          </div>
          <div>
            <h1 className="text-lg sm:text-xl font-bold text-white tracking-tight flex items-center gap-2">
              MITRE ATT&CK Enterprise Framework
              <span className="text-[10px] bg-purple-950 text-purple-300 border border-purple-700/50 px-2 py-0.5 rounded font-mono font-medium">
                V14 ENTERPRISE
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Curated adversarial tactics, techniques, and procedures (TTPs) aligned with SOC detection heuristics.
            </p>
          </div>
        </div>
      </div>

      {/* Search & Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Technique Selector */}
        <div className="space-y-3 lg:col-span-1">
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchFilter}
              onChange={e => setSearchFilter(e.target.value)}
              placeholder="Filter technique by ID or name..."
              className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-3 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-red-500 font-mono"
            />
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden max-h-[600px] overflow-y-auto divide-y divide-slate-800/80">
            {techniquesList.map(t => {
              const isSelected = selectedTechnique?.id === t.id;
              return (
                <div
                  key={t.id}
                  onClick={() => setSelectedTechnique(t)}
                  className={`p-3 cursor-pointer transition-colors text-xs space-y-1 ${
                    isSelected ? 'bg-purple-950/40 border-l-2 border-purple-400' : 'hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-red-400">{t.id}</span>
                    <span className="text-[10px] font-mono text-purple-300 bg-purple-950 px-1.5 py-0.5 rounded border border-purple-800/40">
                      {t.tacticName}
                    </span>
                  </div>
                  <h4 className="font-semibold text-slate-200">{t.name}</h4>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Technique Deep Dive Dossier */}
        <div className="lg:col-span-2">
          {selectedTechnique ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5 shadow-xl">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-lg font-bold text-red-400">{selectedTechnique.id}</span>
                  <span className="text-xs font-mono text-purple-300 bg-purple-950 border border-purple-800/50 px-2 py-0.5 rounded uppercase">
                    Tactic: {selectedTechnique.tacticName} ({selectedTechnique.tacticId})
                  </span>
                </div>
                <h2 className="text-base sm:text-lg font-bold text-white mt-1">
                  {selectedTechnique.name}
                </h2>
              </div>

              {/* Description */}
              <div className="space-y-1.5">
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 block">
                  Technique Description:
                </span>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                  {selectedTechnique.description}
                </p>
              </div>

              {/* Detection Guidance */}
              <div className="space-y-1.5">
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 block flex items-center gap-1.5">
                  <Shield size={14} />
                  SOC Detection Guidance:
                </span>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                  {selectedTechnique.detectionGuidance}
                </p>
              </div>

              {/* Mitigation Strategy */}
              <div className="space-y-1.5">
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-emerald-400 block flex items-center gap-1.5">
                  <CheckCircle2 size={14} />
                  Mitigation Controls:
                </span>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                  {selectedTechnique.mitigation}
                </p>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
              Select a MITRE technique on the left to inspect architectural detection guidance.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
