import React from 'react';
import { SystemHealthState } from '../types/soc';
import { Shield, Cpu, Database, Globe, Network, AlertCircle } from 'lucide-react';

interface SystemHealthBannerProps {
  health: SystemHealthState | null;
  onRefresh?: () => void;
}

export const SystemHealthBanner: React.FC<SystemHealthBannerProps> = ({ health }) => {
  if (!health) return null;

  const getStatusColor = (status: 'ONLINE' | 'DEGRADED' | 'OFFLINE') => {
    switch (status) {
      case 'ONLINE':
        return 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30';
      case 'DEGRADED':
        return 'text-amber-400 bg-amber-950/60 border-amber-500/30';
      case 'OFFLINE':
      default:
        return 'text-red-400 bg-red-950/60 border-red-500/30';
    }
  };

  return (
    <div className="bg-slate-900 border-b border-slate-800 px-3 py-2 text-xs text-slate-300">
      <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="font-mono text-slate-200 font-semibold tracking-wide text-[11px]">SOC TELEMETRY:</span>
          <span className="text-amber-400 font-mono font-medium text-[11px] bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-500/30">
            SYNTHETIC DATA MODE
          </span>
        </div>

        {/* Health status pills */}
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
          <div className={`flex items-center gap-1 px-2 py-0.5 rounded border ${getStatusColor(health.backend)}`}>
            <Cpu size={12} />
            <span>Backend: {health.backend}</span>
          </div>

          <div className={`flex items-center gap-1 px-2 py-0.5 rounded border ${getStatusColor(health.database)}`}>
            <Database size={12} />
            <span>DB: {health.database}</span>
          </div>

          <div className={`flex items-center gap-1 px-2 py-0.5 rounded border ${getStatusColor(health.aiProvider)}`}>
            <Shield size={12} />
            <span>AI: {health.aiProvider}</span>
          </div>

          <div className={`flex items-center gap-1 px-2 py-0.5 rounded border ${getStatusColor(health.threatIntel)}`}>
            <Globe size={12} />
            <span>TI: {health.threatIntel}</span>
          </div>

          <div className={`flex items-center gap-1 px-2 py-0.5 rounded border ${getStatusColor(health.mitre)}`}>
            <Network size={12} />
            <span>MITRE: {health.mitre}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
