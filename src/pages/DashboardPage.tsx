import React, { useState } from 'react';
import {
  Alert,
  SocDashboardStats,
  Severity,
  AlertStatus,
} from '../types/soc';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { RiskScoreMeter } from '../components/RiskScoreMeter';
import {
  ShieldAlert,
  AlertTriangle,
  Activity,
  CheckCircle2,
  XCircle,
  Search,
  Filter,
  ArrowRight,
  Shield,
  Layers,
  Clock,
  Sparkles,
} from 'lucide-react';

interface DashboardPageProps {
  alerts: Alert[];
  stats: SocDashboardStats | null;
  onSelectAlert: (alertId: string) => void;
  onInvestigateAlert: (alertId: string) => void;
  onOpenUrlAnalyzer: (url?: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  alerts,
  stats,
  onSelectAlert,
  onInvestigateAlert,
  onOpenUrlAnalyzer,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');

  // Filter alerts
  const filteredAlerts = alerts.filter(a => {
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
  });

  return (
    <div className="space-y-6 pb-20 md:pb-8">
      {/* 1. Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900 border border-slate-800 p-4 sm:p-5 rounded-xl shadow-lg">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Security Operations Centre
            </h1>
            <span className="text-[10px] bg-red-950 text-red-300 border border-red-700/50 px-2 py-0.5 rounded font-mono font-medium">
              LIVE MONITOR
            </span>
          </div>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Real-time alert correlation, deterministic detection heuristics, and explainable AI decision support.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onOpenUrlAnalyzer()}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-200 text-xs font-medium rounded-lg flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Search size={14} className="text-red-400" />
            <span>Ad-Hoc URL Analyzer</span>
          </button>
        </div>
      </div>

      {/* 2. Primary KPI Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-2.5 sm:gap-3">
        {/* Total Alerts */}
        <div className="bg-slate-900 border border-slate-800 p-3 sm:p-4 rounded-xl">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">Total Alerts</span>
          <div className="flex items-baseline justify-between mt-1">
            <span className="text-2xl font-mono font-bold text-white">{stats?.totalAlerts ?? alerts.length}</span>
            <Layers size={16} className="text-slate-500" />
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="bg-slate-900 border border-red-900/40 p-3 sm:p-4 rounded-xl">
          <span className="text-[11px] font-mono text-red-400 uppercase tracking-wider block">Critical</span>
          <div className="flex items-baseline justify-between mt-1">
            <span className="text-2xl font-mono font-bold text-red-400">{stats?.criticalAlerts ?? 0}</span>
            <ShieldAlert size={16} className="text-red-400" />
          </div>
        </div>

        {/* High Alerts */}
        <div className="bg-slate-900 border border-orange-900/40 p-3 sm:p-4 rounded-xl">
          <span className="text-[11px] font-mono text-orange-400 uppercase tracking-wider block">High Severity</span>
          <div className="flex items-baseline justify-between mt-1">
            <span className="text-2xl font-mono font-bold text-orange-400">{stats?.highAlerts ?? 0}</span>
            <AlertTriangle size={16} className="text-orange-400" />
          </div>
        </div>

        {/* Investigating Incidents */}
        <div className="bg-slate-900 border border-cyan-900/40 p-3 sm:p-4 rounded-xl">
          <span className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider block">Investigating</span>
          <div className="flex items-baseline justify-between mt-1">
            <span className="text-2xl font-mono font-bold text-cyan-400">{stats?.investigatingIncidents ?? 0}</span>
            <Activity size={16} className="text-cyan-400" />
          </div>
        </div>

        {/* Resolved Incidents */}
        <div className="bg-slate-900 border border-emerald-900/40 p-3 sm:p-4 rounded-xl">
          <span className="text-[11px] font-mono text-emerald-400 uppercase tracking-wider block">Resolved</span>
          <div className="flex items-baseline justify-between mt-1">
            <span className="text-2xl font-mono font-bold text-emerald-400">{stats?.resolvedIncidents ?? 0}</span>
            <CheckCircle2 size={16} className="text-emerald-400" />
          </div>
        </div>

        {/* False Positives */}
        <div className="bg-slate-900 border border-slate-800 p-3 sm:p-4 rounded-xl">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">False Positives</span>
          <div className="flex items-baseline justify-between mt-1">
            <span className="text-2xl font-mono font-bold text-slate-300">{stats?.falsePositives ?? 0}</span>
            <XCircle size={16} className="text-slate-500" />
          </div>
        </div>
      </div>

      {/* 3. Risk Distribution & Top MITRE Framework Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Risk Distribution Breakdown */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between mb-3">
            <span>Deterministic Risk Distribution</span>
            <span className="text-[10px] text-slate-500 font-normal">0-100 Scoring Scale</span>
          </h2>

          <div className="space-y-2.5">
            {stats?.riskDistribution?.map(rd => {
              const total = stats.totalAlerts || 1;
              const pct = Math.round((rd.count / total) * 100);
              return (
                <div key={rd.range} className="space-y-1">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-300">{rd.range}</span>
                    <span className="text-slate-400 font-semibold">
                      {rd.count} <span className="text-slate-500 font-normal">({pct}%)</span>
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${
                        rd.range.includes('Critical')
                          ? 'bg-red-500'
                          : rd.range.includes('High')
                          ? 'bg-orange-500'
                          : rd.range.includes('Medium')
                          ? 'bg-amber-500'
                          : 'bg-emerald-500'
                      }`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* MITRE Top Active Techniques */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl lg:col-span-2">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between mb-3">
            <span>Observed MITRE ATT&CK Activity</span>
            <span className="text-[10px] text-slate-500">Enterprise Framework</span>
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {stats?.mitreTopTechniques?.map(t => (
              <div
                key={t.id}
                className="bg-slate-950 border border-slate-800/80 p-2.5 rounded-lg flex items-center justify-between"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-red-400">{t.id}</span>
                    <span className="text-[10px] text-slate-400 bg-slate-800/60 px-1.5 py-0.5 rounded font-mono">
                      {t.count} hit{t.count > 1 ? 's' : ''}
                    </span>
                  </div>
                  <span className="text-xs text-slate-300 font-medium block truncate max-w-[200px] mt-0.5">
                    {t.name}
                  </span>
                </div>
                <Shield size={16} className="text-slate-600 shrink-0" />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 4. Filter & Search Controls */}
      <div className="bg-slate-900 border border-slate-800 p-3.5 rounded-xl space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter by indicator, title, event type, or ID (e.g. CNX-001)..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-red-500/50"
            />
          </div>

          {/* Quick Filters */}
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
            <span className="text-[11px] text-slate-500 uppercase mr-1">Severity:</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                  selectedSeverity === sev
                    ? 'bg-slate-800 text-white border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-950'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* 5. Live SOC Alerts Table & Cards (Mobile-First) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-white">Active SOC Incident Queue</h2>
            <span className="text-xs font-mono text-slate-400">({filteredAlerts.length} events)</span>
          </div>
          <span className="text-[10px] font-mono text-slate-500 uppercase">
            Showing synthetic indicators
          </span>
        </div>

        {/* Mobile View: Cards */}
        <div className="divide-y divide-slate-800/80 md:hidden">
          {filteredAlerts.map(alert => (
            <div
              key={alert.id}
              className="p-3.5 hover:bg-slate-800/40 transition-colors space-y-2.5"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="font-mono text-xs font-bold text-red-400">{alert.id}</span>
                    <SeverityBadge severity={alert.severity} size="sm" />
                    <StatusBadge status={alert.status} size="sm" />
                  </div>
                  <h3 className="text-xs font-medium text-slate-200 mt-1 font-semibold leading-snug">
                    {alert.title}
                  </h3>
                </div>
                <div className="shrink-0 text-right">
                  <RiskScoreMeter score={alert.riskScore} severity={alert.severity} size="sm" />
                </div>
              </div>

              <div className="bg-slate-950 p-2 rounded border border-slate-800/60 font-mono text-[11px] text-slate-400 break-all">
                <span className="text-slate-500 uppercase text-[9px] block">INDICATOR ({alert.indicatorType}):</span>
                {alert.indicator}
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                <span>{alert.source}</span>
                <button
                  onClick={() => onInvestigateAlert(alert.id)}
                  className="px-3 py-1.5 bg-red-600/20 hover:bg-red-600 border border-red-500/40 hover:border-red-500 text-red-300 hover:text-white rounded text-xs font-sans font-medium flex items-center gap-1 transition-colors min-h-[36px]"
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
                <th className="px-4 py-3">Incident ID</th>
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
                  className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                  onClick={() => onSelectAlert(alert.id)}
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
