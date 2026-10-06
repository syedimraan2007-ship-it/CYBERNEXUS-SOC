import React from 'react';
import { Severity } from '../types/soc';

interface RiskScoreMeterProps {
  score: number;
  severity?: Severity;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export const RiskScoreMeter: React.FC<RiskScoreMeterProps> = ({
  score,
  severity,
  size = 'md',
  showLabel = true,
}) => {
  // Determine color based on 0-100 score ranges
  const getColor = () => {
    if (score >= 75) return { text: 'text-red-400', bar: 'bg-red-500', border: 'border-red-500/40', bg: 'bg-red-950/30' };
    if (score >= 50) return { text: 'text-orange-400', bar: 'bg-orange-500', border: 'border-orange-500/40', bg: 'bg-orange-950/30' };
    if (score >= 25) return { text: 'text-amber-400', bar: 'bg-amber-500', border: 'border-amber-500/40', bg: 'bg-amber-950/30' };
    return { text: 'text-emerald-400', bar: 'bg-emerald-500', border: 'border-emerald-500/40', bg: 'bg-emerald-950/30' };
  };

  const c = getColor();

  if (size === 'sm') {
    return (
      <div className="flex items-center gap-2">
        <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
          <div className={`h-full ${c.bar}`} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
        </div>
        <span className={`font-mono text-xs font-bold ${c.text}`}>{score}</span>
      </div>
    );
  }

  if (size === 'lg') {
    return (
      <div className={`flex flex-col items-center justify-center p-3 rounded-lg border ${c.border} ${c.bg}`}>
        <div className="flex items-baseline gap-1">
          <span className={`text-3xl font-mono font-bold tracking-tight ${c.text}`}>{score}</span>
          <span className="text-xs text-slate-400 font-mono">/100</span>
        </div>
        {showLabel && (
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-300 font-semibold mt-0.5">
            {severity || (score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW')} RISK
          </span>
        )}
        <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden border border-slate-700/80 mt-2">
          <div className={`h-full transition-all duration-500 ${c.bar}`} style={{ width: `${score}%` }} />
        </div>
      </div>
    );
  }

  // Medium (standard)
  return (
    <div className="flex items-center gap-2.5">
      <div className="w-16 h-2 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
        <div className={`h-full ${c.bar}`} style={{ width: `${score}%` }} />
      </div>
      <div className="flex items-baseline gap-0.5">
        <span className={`font-mono font-bold text-sm ${c.text}`}>{score}</span>
        <span className="font-mono text-[10px] text-slate-500">/100</span>
      </div>
    </div>
  );
};
