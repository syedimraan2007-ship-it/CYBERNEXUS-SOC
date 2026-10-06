import React from 'react';
import { Severity } from '../types/soc';
import { ShieldAlert, AlertTriangle, AlertCircle, Info } from 'lucide-react';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true,
}) => {
  const getStyles = () => {
    switch (severity) {
      case 'CRITICAL':
        return {
          bg: 'bg-red-950/80 border-red-500/50 text-red-300',
          dot: 'bg-red-400',
          icon: ShieldAlert,
        };
      case 'HIGH':
        return {
          bg: 'bg-orange-950/80 border-orange-500/50 text-orange-300',
          dot: 'bg-orange-400',
          icon: AlertTriangle,
        };
      case 'MEDIUM':
        return {
          bg: 'bg-amber-950/80 border-amber-500/50 text-amber-300',
          dot: 'bg-amber-400',
          icon: AlertCircle,
        };
      case 'LOW':
        return {
          bg: 'bg-blue-950/80 border-blue-500/50 text-blue-300',
          dot: 'bg-blue-400',
          icon: Info,
        };
      case 'INFO':
      default:
        return {
          bg: 'bg-slate-800 border-slate-700 text-slate-300',
          dot: 'bg-slate-400',
          icon: Info,
        };
    }
  };

  const style = getStyles();
  const Icon = style.icon;

  const sizeClasses = {
    sm: 'text-[11px] px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-sm px-3 py-1.5 gap-2 font-semibold',
  }[size];

  const iconSizes = {
    sm: 12,
    md: 14,
    lg: 16,
  }[size];

  return (
    <span
      className={`inline-flex items-center border rounded-md font-mono tracking-wider font-medium uppercase ${style.bg} ${sizeClasses}`}
      aria-label={`Severity: ${severity}`}
    >
      {showIcon && <Icon size={iconSizes} aria-hidden="true" className="shrink-0" />}
      <span>{severity}</span>
    </span>
  );
};
