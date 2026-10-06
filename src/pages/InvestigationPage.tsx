import React, { useState } from 'react';
import {
  Alert,
  AlertStatus,
  EvidenceClassification,
  User,
} from '../types/soc';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { RiskScoreMeter } from '../components/RiskScoreMeter';
import {
  runInvestigation,
  updateIncidentStatus,
  addIncidentNote,
  updateResponseAction,
  generateReport,
} from '../services/api';
import {
  ShieldAlert,
  Shield,
  Activity,
  Cpu,
  FileText,
  Clock,
  Sparkles,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Send,
  Download,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Layers,
  ArrowLeft,
} from 'lucide-react';

interface InvestigationPageProps {
  alert: Alert;
  currentUser: User | null;
  onBack: () => void;
  onAlertUpdated: (updated: Alert) => void;
  onOpenUrlAnalyzer: (url: string) => void;
}

export const InvestigationPage: React.FC<InvestigationPageProps> = ({
  alert,
  currentUser,
  onBack,
  onAlertUpdated,
  onOpenUrlAnalyzer,
}) => {
  const [activeAlert, setActiveAlert] = useState<Alert>(alert);
  const [newNote, setNewNote] = useState('');
  const [resolutionNote, setResolutionNote] = useState('');
  const [resolutionStatus, setResolutionStatus] = useState<'RESOLVED' | 'FALSE_POSITIVE'>('RESOLVED');
  const [isResolving, setIsResolving] = useState(false);
  const [isLoadingAi, setIsLoadingAi] = useState(false);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [pdfDownloadUrl, setPdfDownloadUrl] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Section collapse state for mobile readability
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({
    ai: false, // open by default
    actions: false, // open by default
    timeline: false, // open by default
    evidence: false,
    threatIntel: false,
    mitre: false,
    related: true,
    notes: false,
  });

  const toggleSection = (section: string) => {
    setCollapsedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const handleRunAiInvestigation = async () => {
    setIsLoadingAi(true);
    setErrorMessage(null);
    try {
      const updated = await runInvestigation(activeAlert.id);
      setActiveAlert(updated);
      onAlertUpdated(updated);
    } catch (err: unknown) {
      setErrorMessage((err as Error).message || 'AI Investigation failed');
    } finally {
      setIsLoadingAi(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    try {
      const updated = await addIncidentNote(activeAlert.id, newNote);
      setActiveAlert(updated);
      onAlertUpdated(updated);
      setNewNote('');
    } catch (err: unknown) {
      setErrorMessage((err as Error).message || 'Failed to add note');
    }
  };

  const handleUpdateActionStatus = async (
    actionId: string,
    status: 'APPROVED' | 'DISMISSED' | 'PENDING_REVIEW'
  ) => {
    try {
      const updated = await updateResponseAction(activeAlert.id, actionId, status);
      setActiveAlert(updated);
      onAlertUpdated(updated);
    } catch (err: unknown) {
      setErrorMessage((err as Error).message || 'Failed to update action');
    }
  };

  const handleStatusTransition = async (newStatus: AlertStatus) => {
    if (newStatus === 'RESOLVED' || newStatus === 'FALSE_POSITIVE') {
      setIsResolving(true);
      setResolutionStatus(newStatus);
      return;
    }

    try {
      const updated = await updateIncidentStatus(activeAlert.id, newStatus);
      setActiveAlert(updated);
      onAlertUpdated(updated);
    } catch (err: unknown) {
      setErrorMessage((err as Error).message || 'Failed to update status');
    }
  };

  const handleSubmitResolution = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resolutionNote.trim() || resolutionNote.trim().length < 5) {
      setErrorMessage('Resolution note must be at least 5 characters long.');
      return;
    }

    try {
      const updated = await updateIncidentStatus(activeAlert.id, resolutionStatus, resolutionNote);
      setActiveAlert(updated);
      onAlertUpdated(updated);
      setIsResolving(false);
      setResolutionNote('');
      setErrorMessage(null);
    } catch (err: unknown) {
      setErrorMessage((err as Error).message || 'Resolution failed');
    }
  };

  const handleGeneratePdf = async () => {
    setIsGeneratingPdf(true);
    setErrorMessage(null);
    try {
      const report = await generateReport(activeAlert.id);
      setPdfDownloadUrl(report.base64);

      // Trigger automatic file download
      const link = document.createElement('a');
      link.href = report.base64;
      link.download = report.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (err: unknown) {
      setErrorMessage((err as Error).message || 'Failed to generate PDF report');
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  return (
    <div className="space-y-6 pb-24 md:pb-12 max-w-5xl mx-auto">
      {/* Back button and quick actions */}
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors py-1.5 px-2 rounded-lg hover:bg-slate-900"
        >
          <ArrowLeft size={14} />
          <span>Back to Alerts Queue</span>
        </button>

        <div className="flex items-center gap-2">
          {/* AI Run button */}
          <button
            onClick={handleRunAiInvestigation}
            disabled={isLoadingAi}
            className="px-3 py-1.5 bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 disabled:opacity-50 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 shadow-sm transition-all min-h-[36px]"
          >
            <Sparkles size={14} className={isLoadingAi ? 'animate-spin' : ''} />
            <span>{isLoadingAi ? 'Analyzing Evidence...' : 'Run AI Security Analyst'}</span>
          </button>

          {/* PDF Report Generation button */}
          <button
            onClick={handleGeneratePdf}
            disabled={isGeneratingPdf}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium rounded-lg flex items-center gap-1.5 transition-colors min-h-[36px]"
          >
            <Download size={14} className={isGeneratingPdf ? 'animate-bounce' : 'text-red-400'} />
            <span>{isGeneratingPdf ? 'Rendering PDF...' : 'Download PDF Dossier'}</span>
          </button>
        </div>
      </div>

      {/* Error banner if any */}
      {errorMessage && (
        <div className="bg-red-950/80 border border-red-500/50 p-3 rounded-lg flex items-start justify-between text-xs text-red-200">
          <div className="flex items-center gap-2">
            <AlertTriangle size={15} className="text-red-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button onClick={() => setErrorMessage(null)} className="text-red-400 hover:text-white">
            <XCircle size={15} />
          </button>
        </div>
      )}

      {/* 1. Incident ID, Status, Severity & Risk Score Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-base font-bold text-red-400">{activeAlert.id}</span>
              <SeverityBadge severity={activeAlert.severity} size="md" />
              <StatusBadge status={activeAlert.status} size="md" />
              <span className="text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800/50 px-2 py-0.5 rounded">
                SYNTHETIC
              </span>
            </div>
            <h1 className="text-base sm:text-lg font-bold text-white tracking-tight">
              {activeAlert.title}
            </h1>
            <p className="text-xs text-slate-400">
              Source: <span className="text-slate-300">{activeAlert.source}</span> · Event Type: <span className="text-slate-300 font-mono">{activeAlert.eventType}</span> · Detected: {new Date(activeAlert.timestamp).toLocaleString()}
            </p>
          </div>

          {/* Risk Score */}
          <div className="shrink-0">
            <RiskScoreMeter score={activeAlert.riskScore} severity={activeAlert.severity} size="lg" />
          </div>
        </div>

        {/* 5. Affected Indicator Banner */}
        <div className="mt-4 pt-3.5 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800">
          <div className="space-y-0.5">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">
              AFFECTED TARGET INDICATOR ({activeAlert.indicatorType}):
            </span>
            <span className="font-mono text-xs text-slate-200 font-semibold break-all select-all">
              {activeAlert.indicator}
            </span>
          </div>

          {activeAlert.indicatorType === 'URL' && (
            <button
              onClick={() => onOpenUrlAnalyzer(activeAlert.indicator)}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded border border-slate-700 shrink-0 self-start sm:self-center transition-colors"
            >
              Analyze URL Features →
            </button>
          )}
        </div>

        {/* Lifecycle Transitions Control Bar */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-slate-400 font-mono">Incident State Controls:</span>
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
            {activeAlert.status === 'NEW' && (
              <button
                onClick={() => handleStatusTransition('TRIAGED')}
                className="px-2.5 py-1 bg-purple-950/80 hover:bg-purple-900 border border-purple-500/40 text-purple-300 rounded transition-colors"
              >
                Acknowledge & Triage
              </button>
            )}

            {(activeAlert.status === 'NEW' || activeAlert.status === 'TRIAGED') && (
              <button
                onClick={() => handleStatusTransition('INVESTIGATING')}
                className="px-2.5 py-1 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 rounded transition-colors"
              >
                Open Investigation
              </button>
            )}

            {activeAlert.status === 'INVESTIGATING' && (
              <button
                onClick={() => handleStatusTransition('CONTAINMENT_RECOMMENDED')}
                className="px-2.5 py-1 bg-rose-950/80 hover:bg-rose-900 border border-rose-500/40 text-rose-300 rounded transition-colors"
              >
                Recommend Containment
              </button>
            )}

            {activeAlert.status !== 'RESOLVED' && activeAlert.status !== 'FALSE_POSITIVE' && (
              <>
                <button
                  onClick={() => handleStatusTransition('RESOLVED')}
                  className="px-2.5 py-1 bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-500/40 text-emerald-300 rounded transition-colors"
                >
                  Resolve Incident
                </button>
                <button
                  onClick={() => handleStatusTransition('FALSE_POSITIVE')}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-300 rounded transition-colors"
                >
                  Mark False Positive
                </button>
              </>
            )}

            {(activeAlert.status === 'RESOLVED' || activeAlert.status === 'FALSE_POSITIVE') && (
              <button
                onClick={() => handleStatusTransition('INVESTIGATING')}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-300 rounded transition-colors"
              >
                Re-Open Investigation
              </button>
            )}
          </div>
        </div>

        {/* Resolution Modal/Drawer when resolving */}
        {isResolving && (
          <form onSubmit={handleSubmitResolution} className="mt-4 p-3.5 bg-slate-950 rounded-lg border border-red-500/30 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-xs text-white">
                Confirm {resolutionStatus === 'RESOLVED' ? 'Incident Resolution' : 'False Positive Designation'}
              </span>
              <button type="button" onClick={() => setIsResolving(false)} className="text-slate-400 hover:text-white">
                <XCircle size={15} />
              </button>
            </div>
            <p className="text-[11px] text-slate-400">
              Security compliance policy strictly requires a detailed analyst resolution note before closing this incident.
            </p>
            <textarea
              value={resolutionNote}
              onChange={e => setResolutionNote(e.target.value)}
              placeholder="Detail the root cause, containment verification, and closing remarks..."
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-red-500 min-h-[60px]"
              required
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setIsResolving(false)}
                className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs rounded"
              >
                Confirm & Close
              </button>
            </div>
          </form>
        )}
      </div>

      {/* 6. AI Security Analyst Assessment Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div
          onClick={() => toggleSection('ai')}
          className="p-4 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-red-600/20 text-red-400 rounded-lg border border-red-500/40">
              <Sparkles size={16} />
            </div>
            <div>
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                6. AI Security Analyst Assessment
              </h2>
              <span className="text-[10px] text-slate-400 font-mono">
                Model: {activeAlert.aiAssessment?.model || 'Google Gemini 3.8 Flash'} · Decision Support & Explanation
              </span>
            </div>
          </div>
          <button className="text-slate-400">
            {collapsedSections.ai ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
          </button>
        </div>

        {!collapsedSections.ai && (
          <div className="p-4 sm:p-5 space-y-4 text-xs text-slate-300">
            {activeAlert.aiAssessment ? (
              <>
                {/* Summary & Classification */}
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/80 space-y-1.5">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-400 uppercase">Assessment:</span>
                    <span className={`font-bold ${activeAlert.aiAssessment.assessment === 'MALICIOUS' ? 'text-red-400' : 'text-amber-400'}`}>
                      {activeAlert.aiAssessment.assessment} (Confidence: {Math.round(activeAlert.aiAssessment.confidence * 100)}%)
                    </span>
                  </div>
                  <p className="text-slate-200 leading-relaxed">
                    {activeAlert.aiAssessment.summary}
                  </p>
                </div>

                {/* Strict Evidence Distinction: Observed vs Inferred */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="p-3 bg-slate-950/60 border border-emerald-950/60 rounded-lg space-y-1.5">
                    <span className="font-mono text-[11px] font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                      <CheckCircle2 size={13} />
                      OBSERVED FACTS (Directly Received)
                    </span>
                    <ul className="space-y-1 list-disc list-inside text-slate-300 text-[11px]">
                      {activeAlert.aiAssessment.evidenceDistinction.observed.map((obs, idx) => (
                        <li key={idx} className="leading-tight">{obs}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-3 bg-slate-950/60 border border-amber-950/60 rounded-lg space-y-1.5">
                    <span className="font-mono text-[11px] font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Cpu size={13} />
                      INFERRED CONCLUSIONS (Analytical Deduction)
                    </span>
                    <ul className="space-y-1 list-disc list-inside text-slate-300 text-[11px]">
                      {activeAlert.aiAssessment.evidenceDistinction.inferred.map((inf, idx) => (
                        <li key={idx} className="leading-tight">{inf}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Key Findings & Risk Explanation */}
                {activeAlert.aiAssessment.keyFindings.length > 0 && (
                  <div className="space-y-1.5">
                    <span className="font-mono text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                      Analyst Key Findings:
                    </span>
                    <div className="space-y-1">
                      {activeAlert.aiAssessment.keyFindings.map((kf, idx) => (
                        <div key={idx} className="p-2 bg-slate-950 rounded border border-slate-800 text-[11px] text-slate-300">
                          • {kf}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Human Review Disclaimer */}
                <div className="p-2.5 bg-slate-950 border border-slate-800/80 rounded text-[11px] text-slate-400 italic">
                  <strong>Analyst Review Required:</strong> {activeAlert.aiAssessment.disclaimer}
                </div>
              </>
            ) : (
              <div className="text-center py-6 space-y-2">
                <p className="text-slate-400">No AI security evaluation executed yet for this incident.</p>
                <button
                  onClick={handleRunAiInvestigation}
                  className="px-3.5 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-medium inline-flex items-center gap-1.5"
                >
                  <Sparkles size={14} />
                  <span>Execute AI Security Analyst Assessment</span>
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 7. Recommended Response Actions (Human-in-the-Loop) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div
          onClick={() => toggleSection('actions')}
          className="p-4 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-cyan-600/20 text-cyan-400 rounded-lg border border-cyan-500/40">
              <Shield size={16} />
            </div>
            <div>
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                7. Recommended Response Actions
              </h2>
              <span className="text-[10px] text-slate-400 font-mono">
                Containment & Eradication Proposals · Manual Human Approval Required
              </span>
            </div>
          </div>
          <button className="text-slate-400">
            {collapsedSections.actions ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
          </button>
        </div>

        {!collapsedSections.actions && (
          <div className="p-4 sm:p-5 space-y-3">
            {activeAlert.recommendedActions.map(action => (
              <div
                key={action.id}
                className="bg-slate-950 border border-slate-800 p-3.5 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-200 text-sm">{action.action}</span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-semibold ${
                      action.priority === 'IMMEDIATE'
                        ? 'bg-red-950 text-red-300 border border-red-700/50'
                        : 'bg-orange-950 text-orange-300 border border-orange-700/50'
                    }`}>
                      {action.priority}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                      STATUS: {action.status}
                    </span>
                  </div>
                  <p className="text-slate-400 text-xs">{action.description}</p>
                  <span className="font-mono text-[11px] text-slate-500 block">
                    Target: <span className="text-slate-400">{action.target}</span> · Category: {action.category}
                  </span>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  {action.status === 'PENDING_REVIEW' ? (
                    <>
                      <button
                        onClick={() => handleUpdateActionStatus(action.id, 'APPROVED')}
                        className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-medium text-xs transition-colors"
                      >
                        Approve Action
                      </button>
                      <button
                        onClick={() => handleUpdateActionStatus(action.id, 'DISMISSED')}
                        className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                      >
                        Dismiss
                      </button>
                    </>
                  ) : (
                    <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 size={13} />
                      {action.status}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 8. Incident Chronological Timeline */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div
          onClick={() => toggleSection('timeline')}
          className="p-4 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-amber-600/20 text-amber-400 rounded-lg border border-amber-500/40">
              <Clock size={16} />
            </div>
            <div>
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                8. Incident Chronological Timeline
              </h2>
              <span className="text-[10px] text-slate-400 font-mono">
                {activeAlert.timeline.length} verified events from source telemetry
              </span>
            </div>
          </div>
          <button className="text-slate-400">
            {collapsedSections.timeline ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
          </button>
        </div>

        {!collapsedSections.timeline && (
          <div className="p-4 sm:p-5">
            <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
              {activeAlert.timeline.map((evt, idx) => (
                <div key={evt.id || idx} className="relative group">
                  <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-red-500 ring-4 ring-slate-900" />
                  <div className="space-y-0.5">
                    <div className="flex items-baseline gap-2">
                      <span className="font-semibold text-xs text-slate-200">{evt.title}</span>
                      <span className="text-[10px] font-mono text-slate-500">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </span>
                      {evt.actor && (
                        <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1 rounded">
                          by {evt.actor}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400">{evt.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* 9. Verified Evidence Registry */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div
          onClick={() => toggleSection('evidence')}
          className="p-4 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-emerald-600/20 text-emerald-400 rounded-lg border border-emerald-500/40">
              <CheckCircle2 size={16} />
            </div>
            <div>
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                9. Verified Evidence Registry
              </h2>
              <span className="text-[10px] text-slate-400 font-mono">
                Audited evidence items tagged as OBSERVED or INFERRED
              </span>
            </div>
          </div>
          <button className="text-slate-400">
            {collapsedSections.evidence ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
          </button>
        </div>

        {!collapsedSections.evidence && (
          <div className="p-4 sm:p-5 space-y-2.5">
            {activeAlert.evidenceList.map(ev => {
              const isObserved = ev.classification === 'OBSERVED';
              return (
                <div
                  key={ev.id}
                  className="bg-slate-950 border border-slate-800 p-3 rounded-lg flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                        isObserved
                          ? 'bg-emerald-950/80 text-emerald-300 border-emerald-600/40'
                          : 'bg-amber-950/80 text-amber-300 border-amber-600/40'
                      }`}>
                        {ev.classification}
                      </span>
                      <span className="font-semibold text-slate-300">{ev.source}</span>
                      <span className="text-[10px] font-mono text-slate-500">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="text-slate-300 text-xs leading-relaxed">{ev.description}</p>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-1.5 py-0.5 rounded shrink-0">
                    Confidence: {Math.round(ev.confidence * 100)}%
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 10. Threat Intelligence Multi-Provider Results */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div
          onClick={() => toggleSection('threatIntel')}
          className="p-4 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-blue-600/20 text-blue-400 rounded-lg border border-blue-500/40">
              <Activity size={16} />
            </div>
            <div>
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                10. Threat Intelligence Provider Abstraction
              </h2>
              <span className="text-[10px] text-slate-400 font-mono">
                VirusTotal, URLScan, AbuseIPDB, SafeBrowsing, RDAP & Synthetic Catalog
              </span>
            </div>
          </div>
          <button className="text-slate-400">
            {collapsedSections.threatIntel ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
          </button>
        </div>

        {!collapsedSections.threatIntel && (
          <div className="p-4 sm:p-5 space-y-3">
            {activeAlert.threatIntel ? (
              <>
                <div className="p-3 bg-slate-950 rounded border border-slate-800 text-xs text-slate-300">
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                    TI Aggregator Summary:
                  </span>
                  {activeAlert.threatIntel.summary}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                  {activeAlert.threatIntel.providers.map(p => (
                    <div
                      key={p.provider}
                      className="bg-slate-950 border border-slate-800/80 p-3 rounded-lg space-y-1.5 text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-200">{p.provider}</span>
                        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                          p.status === 'SUCCESS'
                            ? 'text-emerald-400 bg-emerald-950 border border-emerald-800/40'
                            : 'text-slate-400 bg-slate-900 border border-slate-800'
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
              </>
            ) : (
              <div className="text-center py-4 text-slate-400 text-xs">
                Threat intelligence lookup pending. Run investigation to enrich indicators.
              </div>
            )}
          </div>
        )}
      </div>

      {/* 11. MITRE ATT&CK Enterprise Matrix */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div
          onClick={() => toggleSection('mitre')}
          className="p-4 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-purple-600/20 text-purple-400 rounded-lg border border-purple-500/40">
              <Layers size={16} />
            </div>
            <div>
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                11. MITRE ATT&CK Enterprise Framework
              </h2>
              <span className="text-[10px] text-slate-400 font-mono">
                Tactics & Techniques Mapped to Verified Evidence
              </span>
            </div>
          </div>
          <button className="text-slate-400">
            {collapsedSections.mitre ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
          </button>
        </div>

        {!collapsedSections.mitre && (
          <div className="p-4 sm:p-5 space-y-3">
            {activeAlert.mitreTechniques && activeAlert.mitreTechniques.length > 0 ? (
              activeAlert.mitreTechniques.map(mt => (
                <div
                  key={mt.techniqueId}
                  className="bg-slate-950 border border-slate-800 p-3 rounded-lg space-y-1.5 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-red-400">{mt.techniqueId}</span>
                      <span className="font-semibold text-slate-200">{mt.techniqueName}</span>
                    </div>
                    <span className="text-[10px] font-mono text-purple-300 bg-purple-950 border border-purple-800/40 px-2 py-0.5 rounded uppercase">
                      Tactic: {mt.tactic}
                    </span>
                  </div>
                  <p className="text-slate-400 text-xs leading-relaxed">{mt.description}</p>
                  <div className="text-[10px] font-mono text-slate-500 pt-1">
                    Mapping Source: {mt.source} · Confidence: {Math.round(mt.confidence * 100)}%
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-4 text-slate-400 text-xs">
                No active MITRE techniques mapped for this event baseline.
              </div>
            )}
          </div>
        )}
      </div>

      {/* 12. Related Alerts / Correlation */}
      {activeAlert.relatedAlerts.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div
            onClick={() => toggleSection('related')}
            className="p-4 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between cursor-pointer select-none"
          >
            <div className="flex items-center gap-2">
              <div className="p-1.5 bg-orange-600/20 text-orange-400 rounded-lg border border-orange-500/40">
                <AlertTriangle size={16} />
              </div>
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                12. Correlated Security Incidents
              </h2>
            </div>
            <button className="text-slate-400">
              {collapsedSections.related ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
            </button>
          </div>

          {!collapsedSections.related && (
            <div className="p-4 sm:p-5 space-y-2">
              {activeAlert.relatedAlerts.map(rel => (
                <div
                  key={rel.alertId}
                  className="bg-slate-950 border border-slate-800 p-3 rounded-lg flex items-center justify-between text-xs"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-red-400">{rel.alertId}</span>
                      <span className="font-semibold text-slate-200">{rel.title}</span>
                    </div>
                    <p className="text-[11px] text-slate-400">Reason: {rel.relationshipReason}</p>
                  </div>
                  <SeverityBadge severity={rel.severity} size="sm" />
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 13. Analyst Notes & Journal */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div
          onClick={() => toggleSection('notes')}
          className="p-4 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-slate-800 text-slate-300 rounded-lg border border-slate-700">
              <FileText size={16} />
            </div>
            <div>
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                13. SOC Analyst Journal & Notes
              </h2>
              <span className="text-[10px] text-slate-400 font-mono">
                {activeAlert.analystNotes.length} recorded investigator notes
              </span>
            </div>
          </div>
          <button className="text-slate-400">
            {collapsedSections.notes ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
          </button>
        </div>

        {!collapsedSections.notes && (
          <div className="p-4 sm:p-5 space-y-4">
            {/* Notes List */}
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {activeAlert.analystNotes.map(n => (
                <div key={n.id} className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs space-y-1">
                  <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
                    <span className="font-semibold text-slate-300">{n.author} ({n.authorRole})</span>
                    <span>{new Date(n.timestamp).toLocaleString()}</span>
                  </div>
                  <p className="text-slate-200 leading-relaxed">{n.content}</p>
                </div>
              ))}
            </div>

            {/* Add note input */}
            <form onSubmit={handleAddNote} className="flex gap-2">
              <input
                type="text"
                value={newNote}
                onChange={e => setNewNote(e.target.value)}
                placeholder="Log observation, forensic finding, or update..."
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-red-500"
              />
              <button
                type="submit"
                className="px-3.5 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
              >
                <Send size={13} />
                <span>Add Note</span>
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};
