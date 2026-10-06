import React, { useState } from 'react';
import { Alert } from '../types/soc';
import { generateReport } from '../services/api';
import { FileText, Download, CheckCircle2, ShieldAlert, Sparkles, ExternalLink, Eye, X } from 'lucide-react';

interface ReportsPageProps {
  alerts: Alert[];
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ alerts }) => {
  const [selectedAlertId, setSelectedAlertId] = useState<string>('CNX-001');
  const [isGenerating, setIsGenerating] = useState(false);
  const [reportResult, setReportResult] = useState<{ filename: string; base64: string } | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleGenerateReport = async (alertId: string) => {
    setIsGenerating(true);
    setErrorMessage(null);
    try {
      const res = await generateReport(alertId);
      setReportResult({ filename: res.filename, base64: res.base64 });

      // Trigger instant download
      const link = document.createElement('a');
      link.href = res.base64;
      link.download = res.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (err: unknown) {
      setErrorMessage((err as Error).message || 'Failed to generate report');
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-6 pb-24 md:pb-12 max-w-5xl mx-auto">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 p-4 sm:p-5 rounded-xl shadow-lg">
        <div className="flex items-center gap-2">
          <div className="p-2 bg-red-600/20 text-red-400 rounded-lg border border-red-500/40">
            <FileText size={20} />
          </div>
          <div>
            <h1 className="text-lg sm:text-xl font-bold text-white tracking-tight flex items-center gap-2">
              SOC Incident Report Generator (PDF)
              <span className="text-[10px] bg-red-950 text-red-300 border border-red-700/50 px-2 py-0.5 rounded font-mono font-medium">
                PRODUCTION DOSSIER
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Generate standardized, executive and technical PDF incident investigation dossiers.
            </p>
          </div>
        </div>
      </div>

      {/* Quick Sample Downloads Required by Section 23 */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Sample 1: High / Critical Incident */}
        <div className="bg-slate-900 border border-red-900/50 p-4 rounded-xl space-y-3">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <span className="text-[10px] font-mono font-bold bg-red-950 text-red-300 border border-red-700/50 px-2 py-0.5 rounded">
                SAMPLE HIGH / CRITICAL DOSSIER
              </span>
              <h3 className="text-sm font-bold text-white mt-1">
                CNX-001: Credential Harvesting Lure
              </h3>
              <p className="text-xs text-slate-400">
                Full forensic breakdown of phishing URL, observed subdomains, MITRE T1566.002, and containment action.
              </p>
            </div>
            <ShieldAlert size={20} className="text-red-400 shrink-0" />
          </div>

          <button
            onClick={() => handleGenerateReport('CNX-001')}
            disabled={isGenerating}
            className="w-full py-2 px-3 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-lg"
          >
            <Download size={14} />
            <span>Generate & Download Critical PDF</span>
          </button>
        </div>

        {/* Sample 2: Benign / False Positive Incident */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-3">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <span className="text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700 px-2 py-0.5 rounded">
                SAMPLE BENIGN / FALSE POSITIVE
              </span>
              <h3 className="text-sm font-bold text-white mt-1">
                CNX-010: Scheduled Security Scanner Audit
              </h3>
              <p className="text-xs text-slate-400">
                Internal port probe correlated with change request registry and resolved as benign false positive.
              </p>
            </div>
            <CheckCircle2 size={20} className="text-emerald-400 shrink-0" />
          </div>

          <button
            onClick={() => handleGenerateReport('CNX-010')}
            disabled={isGenerating}
            className="w-full py-2 px-3 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors"
          >
            <Download size={14} />
            <span>Generate & Download Benign PDF</span>
          </button>
        </div>
      </div>

      {/* Custom Incident Report Generator */}
      <div className="bg-slate-900 border border-slate-800 p-4 sm:p-5 rounded-xl space-y-4">
        <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
          Generate Report for Any Queued Incident
        </h3>

        <div className="flex flex-col sm:flex-row gap-2.5">
          <select
            value={selectedAlertId}
            onChange={e => setSelectedAlertId(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500"
          >
            {alerts.map(a => (
              <option key={a.id} value={a.id}>
                {a.id} [{a.severity}] - {a.title} ({a.status})
              </option>
            ))}
          </select>

          <button
            onClick={() => handleGenerateReport(selectedAlertId)}
            disabled={isGenerating}
            className="px-5 py-2.5 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-lg min-h-[44px]"
          >
            <Download size={14} />
            <span>{isGenerating ? 'Rendering PDF...' : 'Generate & Download PDF'}</span>
          </button>
        </div>

        {reportResult && (
          <div className="p-3 bg-emerald-950/40 border border-emerald-800/40 rounded-lg flex items-center justify-between text-xs text-emerald-300">
            <div className="flex items-center gap-2">
              <CheckCircle2 size={16} />
              <span>Report Generated: <strong>{reportResult.filename}</strong></span>
            </div>
            <button
              onClick={() => setPreviewOpen(true)}
              className="text-emerald-200 hover:text-white underline font-mono flex items-center gap-1"
            >
              <Eye size={13} />
              <span>Preview In-App</span>
            </button>
          </div>
        )}
      </div>

      {/* Embedded In-App PDF Preview Modal */}
      {previewOpen && reportResult && (
        <div className="fixed inset-0 z-50 bg-slate-950/90 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-4xl h-[85vh] flex flex-col overflow-hidden shadow-2xl">
            <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <span className="font-mono text-xs text-white font-semibold">
                Report Preview: {reportResult.filename}
              </span>
              <button onClick={() => setPreviewOpen(false)} className="text-slate-400 hover:text-white">
                <X size={18} />
              </button>
            </div>
            <iframe
              src={reportResult.base64}
              title="PDF Report Preview"
              className="w-full flex-1 border-none bg-white"
            />
          </div>
        </div>
      )}
    </div>
  );
};
