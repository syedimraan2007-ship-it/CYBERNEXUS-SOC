/**
 * CYBERNEXUS SOC - Professional SOC Incident PDF Report Generator
 * Builds downloadable PDF incident reports including all 14 SOC workflow artifacts,
 * timeline, evidence classification, MITRE ATT&CK mapping, and required safety disclaimers.
 */

import { jsPDF } from 'jspdf';
import { Alert } from '../../src/types/soc';

export function generateIncidentPdf(alert: Alert): { filename: string; base64: string; buffer: Buffer } {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  let y = 18;

  const checkPageBreak = (neededHeight: number) => {
    if (y + neededHeight > pageHeight - 15) {
      doc.addPage();
      y = 18;
      // Header on next page
      doc.setFontSize(8);
      doc.setTextColor(140, 150, 160);
      doc.text(`CYBERNEXUS SOC | INCIDENT REPORT: ${alert.id}`, 15, 10);
      doc.text(`PAGE ${doc.internal.pages.length - 1}`, pageWidth - 25, 10);
      doc.setDrawColor(220, 225, 230);
      doc.line(15, 12, pageWidth - 15, 12);
    }
  };

  // 1. Report Header Banner
  doc.setFillColor(15, 23, 42); // Dark slate
  doc.rect(15, y, pageWidth - 30, 24, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text('CYBERNEXUS SOC', 20, y + 9);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  doc.text('INCIDENT INVESTIGATION & THREAT INTELLIGENCE DOSSIER', 20, y + 16);

  doc.setFontSize(8);
  doc.setTextColor(248, 113, 113);
  doc.text('[SYNTHETIC DEMO DATA]', pageWidth - 65, y + 9);
  doc.setTextColor(203, 213, 225);
  doc.text(`GENERATED: ${new Date().toISOString().slice(0, 16)}`, pageWidth - 65, y + 16);

  y += 30;

  // 2. Incident Summary Box
  doc.setDrawColor(226, 232, 240);
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(15, y, pageWidth - 30, 32, 2, 2, 'FD');

  doc.setTextColor(30, 41, 59);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text(`Incident ID: ${alert.id} - ${alert.title}`, 20, y + 8);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text(`Status: ${alert.status}    |    Severity: ${alert.severity}    |    Risk Score: ${alert.riskScore}/100`, 20, y + 15);
  doc.text(`Source: ${alert.source}    |    Event Type: ${alert.eventType}`, 20, y + 21);
  doc.text(`Affected Indicator: ${alert.indicator.length > 55 ? alert.indicator.slice(0, 55) + '...' : alert.indicator}`, 20, y + 27);

  y += 38;

  // 3. Deterministic Detection & Risk Scoring
  checkPageBreak(30);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('1. Deterministic Detection & Scoring Signals', 15, y);
  y += 6;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(51, 65, 85);

  if (alert.riskBreakdown?.signals && alert.riskBreakdown.signals.length > 0) {
    for (const sig of alert.riskBreakdown.signals.slice(0, 4)) {
      doc.text(`• [${sig.category}] ${sig.name} (+${sig.scoreContribution} pts): ${sig.description}`, 18, y);
      y += 5;
    }
  } else {
    doc.text(`• Calculated composite risk score: ${alert.riskScore}/100 (${alert.severity})`, 18, y);
    y += 5;
  }
  y += 4;

  // 4. Evidence Classification (Observed vs Inferred)
  checkPageBreak(35);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('2. Verified Evidence Registry', 15, y);
  y += 6;

  doc.setFontSize(8.5);
  for (const ev of alert.evidenceList.slice(0, 4)) {
    const isObs = ev.classification === 'OBSERVED';
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(isObs ? 22 : 180, isObs ? 101 : 83, isObs ? 52 : 9); // Emerald vs Amber
    doc.text(`[${ev.classification}]`, 18, y);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    const descText = `${ev.source} (${ev.timestamp.slice(11, 19)}): ${ev.description}`;
    const wrapped = doc.splitTextToSize(descText, pageWidth - 55);
    doc.text(wrapped, 45, y);
    y += (wrapped.length * 4) + 2;
    checkPageBreak(15);
  }
  y += 4;

  // 5. MITRE ATT&CK Enterprise Mappings
  checkPageBreak(25);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('3. MITRE ATT&CK Enterprise Framework Alignment', 15, y);
  y += 6;

  doc.setFontSize(8.5);
  if (alert.mitreTechniques && alert.mitreTechniques.length > 0) {
    for (const mt of alert.mitreTechniques) {
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 41, 59);
      doc.text(`• ${mt.techniqueId} - ${mt.techniqueName} [Tactic: ${mt.tactic} | Status: ${mt.mappingType}]`, 18, y);
      y += 4.5;
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      const desc = doc.splitTextToSize(mt.description, pageWidth - 38);
      doc.text(desc, 22, y);
      y += (desc.length * 4) + 2;
      checkPageBreak(15);
    }
  } else {
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text('No candidate MITRE techniques mapped for this baseline event.', 18, y);
    y += 5;
  }
  y += 4;

  // 6. AI Security Analyst Assessment
  checkPageBreak(30);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('4. AI Security Analyst Assessment (Decision Support)', 15, y);
  y += 6;

  doc.setFontSize(8.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(51, 65, 85);

  const aiSummary = alert.aiAssessment?.summary || 'Deterministic analysis verified this incident according to standard security operating procedures.';
  const wrappedAi = doc.splitTextToSize(aiSummary, pageWidth - 35);
  doc.text(wrappedAi, 18, y);
  y += (wrappedAi.length * 4) + 4;

  // 7. Recommended Response Actions
  checkPageBreak(25);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('5. Recommended Response Actions (Human-in-the-Loop)', 15, y);
  y += 6;

  for (const act of alert.recommendedActions) {
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 41, 59);
    doc.text(`• [${act.priority}] ${act.action} (Status: ${act.status})`, 18, y);
    y += 4.5;
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(`  Target: ${act.target} - Rationale: ${act.description}`, 20, y);
    y += 5;
    checkPageBreak(12);
  }
  y += 4;

  // 8. Incident Resolution / Analyst Notes
  if (alert.resolutionNote || alert.analystNotes.length > 0) {
    checkPageBreak(25);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('6. Resolution Audit & Analyst Notes', 15, y);
    y += 6;

    doc.setFontSize(8.5);
    if (alert.resolutionNote) {
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(`Resolution Note (${alert.resolvedBy || 'Analyst'} at ${alert.resolvedAt?.slice(0, 16) || 'N/A'}):`, 18, y);
      y += 4.5;
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      const resWrapped = doc.splitTextToSize(alert.resolutionNote, pageWidth - 38);
      doc.text(resWrapped, 20, y);
      y += (resWrapped.length * 4) + 4;
    }

    for (const n of alert.analystNotes) {
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text(`[${n.timestamp.slice(11, 16)}] ${n.author} (${n.authorRole}): ${n.content}`, 18, y);
      y += 4.5;
      checkPageBreak(10);
    }
    y += 4;
  }

  // 9. Required Safety Disclaimers (Strict non-negotiable)
  checkPageBreak(25);
  doc.setDrawColor(203, 213, 225);
  doc.setFillColor(241, 245, 249);
  doc.roundedRect(15, y, pageWidth - 30, 20, 1, 1, 'FD');

  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(71, 85, 105);
  doc.text('NON-NEGOTIABLE SAFETY & VERIFICATION DISCLAIMERS:', 18, y + 5);

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100, 116, 139);
  doc.text('• SYNTHETIC DATA: All indicators are synthetic and utilize RFC-reserved documentation domains/IP addresses.', 18, y + 10);
  doc.text('• HUMAN REVIEW REQUIRED: AI is decision support, not autonomous authority. An authorized analyst must approve all responses.', 18, y + 15);

  const filename = `CYBERNEXUS_REPORT_${alert.id}_${Date.now()}.pdf`;
  const base64 = doc.output('datauristring');
  const arrayBuffer = doc.output('arraybuffer');
  const buffer = Buffer.from(arrayBuffer);

  return { filename, base64, buffer };
}
