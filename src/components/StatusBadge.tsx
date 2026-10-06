import React from 'react';
import { AlertStatus } from '../types/soc';
import { Bell, Search, Activity, ShieldCheck, CheckCircle2, XCircle } from 'lucide-react';

interface StatusBadgeProps {
  status: AlertStatus;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const getMeta = () => {
    switch (status) {
      case 'NEW':
        return {
          label: 'NEW',
          bg: 'bg-indigo-950/60 border-indigo-500/40 text-indigo-300',
          icon: Bell,
        };
      case 'TRIAGED':
        return {
          label: 'TRIAGED',
          bg: 'bg-purple-950/60 border-purple-500/40 text-purple-300',
          icon: Search,
        };
      case 'INVESTIGATING':
        return {
          label: 'INVESTIGATING',
          bg: 'bg-cyan-950/60 border-cyan-500/40 text-cyan-300',
          icon: Activity,
        };
      case 'CONTAINMENT_RECOMMENDED':
        return {
          label: 'CONTAINMENT REC.',
          bg: 'bg-rose-950/60 border-rose-500/40 text-rose-300',
          icon: ShieldCheck,
        };
      case 'RESOLVED':
        return {
          label: 'RESOLVED',
          bg: 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300',
          icon: CheckCircle2,
        };
      case 'FALSE_POSITIVE':
        return {
          label: 'FALSE POSITIVE',
          bg: 'bg-slate-800 border-slate-600 text-slate-300',
          icon: XCircle,
        };
    }
  };

  const meta = getMeta();
  const Icon = meta.icon;
  const padding = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 border rounded font-mono font-medium tracking-wide ${meta.bg} ${padding}`}
      title={`Incident Status: ${status}`}
    >
      <Icon size={size === 'sm' ? 11 : 13} className="shrink-0" />
      <span>{meta.label}</span>
    </span>
  );
};
