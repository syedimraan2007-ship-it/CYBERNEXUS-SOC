import React, { useState } from 'react';
import { Alert, Severity, AlertStatus } from '../types/soc';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { RiskScoreMeter } from '../components/RiskScoreMeter';
import {
  Bell,
  Search,
  Filter,
  ArrowRight,
  Shield,
  Layers,
  Clock,
  ArrowUpDown,
} from 'lucide-react';

interface AlertsPageProps {
  alerts: Alert[];
  onSelectAlert: (alertId: string) => void;
  onInvestigateAlert: (alertId: string) => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({
  alerts,
  onSelectAlert,
  onInvestigateAlert,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'risk' | 'time'>('risk');

  const filteredAlerts = alerts
    .filter(a => {
      if (selectedSeverity !== 'ALL' && a.severity !== selectedSeverity) return false;
      if (selectedStatus !== 'ALL' && a.status !== selectedStatus) return false;
      if (searchQuery.trim() !== '') {
        const q = searchQuery.toLowerCase();
        return (
          a.id.toLowerCase().includes(q) ||
          a.title.toLowerCase().includes(q) ||
          a.indicator.toLowerCase().includes(q) ||
          a.eventType.toLowerCase().includes(q)
        );
      }
      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'risk') return b.riskScore - a.riskScore;
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });

  return (
    <div className="space-y-6 pb-24 md:pb-12 max-w-6xl mx-auto">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 p-4 sm:p-5 rounded-xl shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 bg-red-600/20 text-red-400 rounded-lg border border-red-500/40">
              <Bell size={20} />
            </div>
            <div>
              <h1 className="text-lg sm:text-xl font-bold text-white tracking-tight">
                Alert Management Queue
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Triage, investigate, and manage lifecycle state for all inbound synthetic security events.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={() => setSortBy(sortBy === 'risk' ? 'time' : 'risk')}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg flex items-center gap-1.5 transition-colors"
          >
            <ArrowUpDown size={13} />
            <span>Sort by: {sortBy === 'risk' ? 'Risk Score' : 'Timestamp'}</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-3">
        <div className="flex flex-col sm:flex-row gap-2.5">
          <div className="relative flex-1">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search alert by ID, indicator, title, or event type..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-red-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
            <span className="text-[11px] text-slate-500 uppercase mr-1">Status:</span>
            {['ALL', 'NEW', 'TRIAGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map(st => (
              <button
                key={st}
                onClick={() => setSelectedStatus(st)}
                className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                  selectedStatus === st
                    ? 'bg-slate-800 text-white border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-950'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Alerts Grid / Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-semibold text-white">
            Displaying {filteredAlerts.length} Security Alerts
          </span>
          <span className="text-[10px] font-mono text-slate-500 uppercase">
            Click row or card to view investigation
          </span>
        </div>

        {/* Mobile View: Cards */}
        <div className="divide-y divide-slate-800/80 md:hidden">
          {filteredAlerts.map(alert => (
            <div
              key={alert.id}
              onClick={() => onSelectAlert(alert.id)}
              className="p-3.5 hover:bg-slate-800/40 transition-colors space-y-2.5 cursor-pointer"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="font-mono text-xs font-bold text-red-400">{alert.id}</span>
                    <SeverityBadge severity={alert.severity} size="sm" />
                    <StatusBadge status={alert.status} size="sm" />
                  </div>
                  <h3 className="text-xs font-semibold text-slate-200 mt-1 leading-snug">
                    {alert.title}
                  </h3>
                </div>
                <div className="shrink-0 text-right">
                  <RiskScoreMeter score={alert.riskScore} severity={alert.severity} size="sm" />
                </div>
              </div>

              <div className="bg-slate-950 p-2 rounded border border-slate-800/60 font-mono text-[11px] text-slate-400 break-all">
                {alert.indicator}
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                <span>{alert.source}</span>
                <button
                  onClick={e => {
                    e.stopPropagation();
                    onInvestigateAlert(alert.id);
                  }}
                  className="px-3 py-1 bg-red-600/20 hover:bg-red-600 border border-red-500/40 hover:border-red-500 text-red-300 hover:text-white rounded text-xs font-medium inline-flex items-center gap-1 transition-colors min-h-[36px]"
                >
                  <span>Investigate</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Desktop View: Table */}
        <div className="hidden md:block overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/70 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Title & Source</th>
                <th className="px-4 py-3">Indicator</th>
                <th className="px-4 py-3">Risk Score</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredAlerts.map(alert => (
                <tr
                  key={alert.id}
                  onClick={() => onSelectAlert(alert.id)}
                  className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                >
                  <td className="px-4 py-3 font-mono font-bold text-red-400 whitespace-nowrap">
                    {alert.id}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <SeverityBadge severity={alert.severity} size="sm" />
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-semibold text-slate-200 line-clamp-1">{alert.title}</div>
                    <div className="text-[11px] text-slate-500 font-mono mt-0.5">{alert.source}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-300 max-w-xs truncate" title={alert.indicator}>
                    {alert.indicator}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <RiskScoreMeter score={alert.riskScore} severity={alert.severity} size="sm" />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <StatusBadge status={alert.status} size="sm" />
                  </td>
                  <td className="px-4 py-3 text-right whitespace-nowrap">
                    <button
                      onClick={e => {
                        e.stopPropagation();
                        onInvestigateAlert(alert.id);
                      }}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-red-600 border border-slate-700 hover:border-red-500 text-slate-300 hover:text-white rounded text-xs font-medium inline-flex items-center gap-1 transition-colors"
                    >
                      <span>Investigate</span>
                      <ArrowRight size={13} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
