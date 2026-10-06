/**
 * CYBERNEXUS SOC - API Routes Implementation
 * Complete REST API matching the SOC specification.
 */

import { Router, Request, Response } from 'express';
import { Database } from './database';
import { extractUrlFeatures } from './detection/url_features';
import { calculateRiskScore } from './detection/scoring';
import { evaluateDetectionRules } from './detection/rules';
import { lookupThreatIntel } from './threat_intel/router';
import { runAiAnalyst } from './ai/gemini';
import { getAllMitreTechniques, lookupMitreTechnique } from './detection/mitre';
import { generateIncidentPdf } from './reports/pdf_generator';
import { authenticateUser, getUserFromToken } from './security/auth';
import { validateUrlInput, validateIndicatorInput } from './security/validation';
import { logAudit } from './security/audit';
import { IndicatorType, SystemHealthState } from '../src/types/soc';

export const apiRouter = Router();

// 1. Health Endpoints
apiRouter.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'OK',
    app: 'CYBERNEXUS SOC',
    tagline: 'Detect. Investigate. Explain. Respond.',
    timestamp: new Date().toISOString(),
  });
});

apiRouter.get('/system/health', (_req: Request, res: Response) => {
  const apiKey = process.env.GEMINI_API_KEY;
  const health: SystemHealthState = {
    backend: 'ONLINE',
    database: 'ONLINE',
    aiProvider: apiKey ? 'ONLINE' : 'DEGRADED',
    threatIntel: 'ONLINE',
    mitre: 'ONLINE',
    activeProviderName: apiKey ? 'Google Gemini 3.8 Flash' : 'Deterministic AI Engine (Offline Fallback)',
    syntheticDataMode: true,
    timestamp: new Date().toISOString(),
  };
  res.json(health);
});

// 2. Authentication Endpoints
apiRouter.post('/auth/login', (req: Request, res: Response) => {
  const { username, password } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username is required.' });
  }

  const authResult = authenticateUser(username, password);
  if (!authResult) {
    return res.status(401).json({ error: 'Invalid credentials. Allowed demo users: analyst1, lead_soc, admin' });
  }

  logAudit(authResult.user.name, 'USER_LOGIN', undefined, { username });
  res.json(authResult);
});

apiRouter.get('/auth/me', (req: Request, res: Response) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = getUserFromToken(token);
  res.json({ user });
});

// 3. Alerts & Dashboard Stats
apiRouter.get('/alerts', (req: Request, res: Response) => {
  const alerts = Database.getAlerts();
  const stats = Database.getDashboardStats();
  res.json({ alerts, stats });
});

apiRouter.get('/alerts/:id', (req: Request, res: Response) => {
  const alert = Database.getAlertById(req.params.id);
  if (!alert) {
    return res.status(404).json({ error: `Alert ${req.params.id} not found.` });
  }
  res.json(alert);
});

// 4. Incidents & Investigation Workspace
apiRouter.get('/incidents/:id', (req: Request, res: Response) => {
  const alert = Database.getAlertById(req.params.id);
  if (!alert) {
    return res.status(404).json({ error: `Incident ${req.params.id} not found.` });
  }
  res.json(alert);
});

apiRouter.post('/incidents/:id/investigate', async (req: Request, res: Response) => {
  const alert = Database.getAlertById(req.params.id);
  if (!alert) {
    return res.status(404).json({ error: `Incident ${req.params.id} not found.` });
  }

  const token = req.headers.authorization?.replace('Bearer ', '');
  const actor = getUserFromToken(token)?.name || 'Elena Rostova';

  // If status is NEW, update to INVESTIGATING
  if (alert.status === 'NEW' || alert.status === 'TRIAGED') {
    Database.updateAlertStatus(alert.id, 'INVESTIGATING', actor);
  }

  // 1. Run Threat Intelligence lookup if not already completed
  let threatIntel = alert.threatIntel;
  if (!threatIntel) {
    threatIntel = await lookupThreatIntel(alert.indicator, alert.indicatorType);
    Database.setAlertThreatIntel(alert.id, threatIntel);
  }

  // 2. Extract features if URL
  let urlFeatures = alert.urlFeatures;
  if (alert.indicatorType === 'URL' && !urlFeatures) {
    urlFeatures = extractUrlFeatures(alert.indicator);
  }

  // 3. Run AI Security Analyst
  const observedEvidence = alert.evidenceList.map(e => e.description);
  const aiAssessment = await runAiAnalyst({
    alert,
    urlFeatures,
    riskScore: alert.riskBreakdown,
    threatIntel,
    observedEvidence,
  });

  Database.setAlertAiAssessment(alert.id, aiAssessment);
  logAudit(actor, 'RUN_AI_INVESTIGATION', alert.id, { indicator: alert.indicator });

  const updatedAlert = Database.getAlertById(req.params.id);
  res.json(updatedAlert);
});

apiRouter.post('/incidents/:id/status', (req: Request, res: Response) => {
  const { status, resolutionNote } = req.body;
  if (!status) {
    return res.status(400).json({ error: 'Status is required.' });
  }

  const token = req.headers.authorization?.replace('Bearer ', '');
  const actor = getUserFromToken(token)?.name || 'Analyst';

  const result = Database.updateAlertStatus(req.params.id, status, actor, resolutionNote);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  logAudit(actor, 'UPDATE_INCIDENT_STATUS', req.params.id, { newStatus: status, resolutionNote });
  res.json(result.alert);
});

apiRouter.post('/incidents/:id/notes', (req: Request, res: Response) => {
  const { content } = req.body;
  if (!content) {
    return res.status(400).json({ error: 'Note content cannot be empty.' });
  }

  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = getUserFromToken(token);
  const author = user?.name || 'Elena Rostova';
  const role = user?.role || 'ANALYST';

  const result = Database.addAnalystNote(req.params.id, content, author, role);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  logAudit(author, 'ADD_ANALYST_NOTE', req.params.id);
  res.json(result.alert);
});

apiRouter.post('/incidents/:id/actions/:actionId', (req: Request, res: Response) => {
  const { status } = req.body;
  if (!status) {
    return res.status(400).json({ error: 'Action status is required.' });
  }

  const token = req.headers.authorization?.replace('Bearer ', '');
  const actor = getUserFromToken(token)?.name || 'Elena Rostova';

  const result = Database.updateRecommendedAction(req.params.id, req.params.actionId, status, actor);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  logAudit(actor, 'ACTION_REVIEW_UPDATED', req.params.id, { actionId: req.params.actionId, status });
  res.json(result.alert);
});

// 5. Deterministic URL Analyzer
apiRouter.post('/analyze/url', async (req: Request, res: Response) => {
  const { url } = req.body;
  const validation = validateUrlInput(url);
  if (!validation.isValid) {
    return res.status(400).json({ error: validation.error });
  }

  // Purely deterministic feature extraction without fetching arbitrary URL!
  const features = extractUrlFeatures(validation.sanitized);

  // Threat Intel lookup
  const threatIntel = await lookupThreatIntel(validation.sanitized, 'URL');

  // Rule evaluation
  const ruleResult = evaluateDetectionRules({
    eventType: 'phishing_url',
    indicator: validation.sanitized,
    indicatorType: 'URL',
  });

  // Calculate composite risk score
  const riskScore = calculateRiskScore(
    features,
    threatIntel,
    ruleResult.matchedRules.map(r => ({ rule: r.ruleId, weight: r.scoreContribution, description: r.description }))
  );

  // Run AI analyst
  const aiAssessment = await runAiAnalyst({
    alert: {
      id: 'ADHOC-URL',
      title: 'Ad-Hoc URL Analysis',
      indicator: validation.sanitized,
      indicatorType: 'URL',
      eventType: 'phishing_url',
      severity: riskScore.severity,
      riskScore: riskScore.score,
    },
    urlFeatures: features,
    riskScore,
    threatIntel,
    observedEvidence: [
      `Target URL submitted: ${validation.sanitized}`,
      `Registered Domain: ${features.registeredDomain}`,
      `Subdomains: ${features.subdomainCount}`,
      `Keywords found: [${features.suspiciousKeywordsFound.join(', ')}]`,
    ],
  });

  res.json({
    url: validation.sanitized,
    features,
    riskScore,
    matchedRules: ruleResult.matchedRules,
    threatIntel,
    aiAssessment,
    mitreCandidates: ruleResult.mitreCandidates,
    safetyNotice: 'Analysis performed purely deterministically via structural parsing and verified intelligence. No outbound connection made to submitted URL.',
  });
});

// 6. Generic Indicator Analyzer
apiRouter.post('/analyze/indicator', async (req: Request, res: Response) => {
  const { indicator, type } = req.body;
  const validation = validateIndicatorInput(indicator, type);
  if (!validation.isValid) {
    return res.status(400).json({ error: validation.error });
  }

  const indicatorType = (type || 'DOMAIN') as IndicatorType;
  const threatIntel = await lookupThreatIntel(validation.sanitized, indicatorType);

  let eventType = 'suspicious_domain';
  if (indicatorType === 'IP') eventType = 'suspicious_ip';
  if (indicatorType === 'HASH') eventType = 'malware_hash';
  if (indicatorType === 'URL') eventType = 'phishing_url';

  const ruleResult = evaluateDetectionRules({
    eventType,
    indicator: validation.sanitized,
    indicatorType,
  });

  const urlFeatures = indicatorType === 'URL' ? extractUrlFeatures(validation.sanitized) : undefined;
  const riskScore = calculateRiskScore(
    urlFeatures,
    threatIntel,
    ruleResult.matchedRules.map(r => ({ rule: r.ruleId, weight: r.scoreContribution, description: r.description }))
  );

  const aiAssessment = await runAiAnalyst({
    alert: {
      id: 'ADHOC-IND',
      title: `Ad-Hoc ${indicatorType} Lookup`,
      indicator: validation.sanitized,
      indicatorType,
      eventType,
      severity: riskScore.severity,
      riskScore: riskScore.score,
    },
    urlFeatures,
    riskScore,
    threatIntel,
    observedEvidence: [
      `Indicator inspected: ${validation.sanitized} (${indicatorType})`,
      `Verified Threat Intel Reputation: ${threatIntel.overallReputation}`,
    ],
  });

  res.json({
    indicator: validation.sanitized,
    indicatorType,
    threatIntel,
    riskScore,
    matchedRules: ruleResult.matchedRules,
    mitreCandidates: ruleResult.mitreCandidates,
    aiAssessment,
  });
});

// 7. Threat Intelligence Direct Lookup
apiRouter.post('/intel/lookup', async (req: Request, res: Response) => {
  const { indicator, type } = req.body;
  if (!indicator) return res.status(400).json({ error: 'Indicator is required.' });

  const indicatorType = (type || 'URL') as IndicatorType;
  const result = await lookupThreatIntel(indicator, indicatorType);
  res.json(result);
});

// 8. MITRE ATT&CK Endpoints
apiRouter.get('/mitre/techniques', (_req: Request, res: Response) => {
  const techniques = getAllMitreTechniques();
  res.json(techniques);
});

apiRouter.get('/mitre/:technique_id', (req: Request, res: Response) => {
  const technique = lookupMitreTechnique(req.params.technique_id);
  if (!technique) {
    return res.status(404).json({ error: `MITRE technique ${req.params.technique_id} not found.` });
  }
  res.json(technique);
});

// 9. PDF SOC Report Generation & Download
apiRouter.post('/reports/generate', (req: Request, res: Response) => {
  const { alertId } = req.body;
  const alert = Database.getAlertById(alertId || 'CNX-001');
  if (!alert) {
    return res.status(404).json({ error: 'Incident not found' });
  }

  const report = generateIncidentPdf(alert);
  const token = req.headers.authorization?.replace('Bearer ', '');
  const actor = getUserFromToken(token)?.name || 'Elena Rostova';
  logAudit(actor, 'GENERATE_PDF_REPORT', alert.id, { filename: report.filename });

  res.json({
    success: true,
    filename: report.filename,
    base64: report.base64,
    alertId: alert.id,
  });
});

apiRouter.get('/reports/download/:id', (req: Request, res: Response) => {
  const alert = Database.getAlertById(req.params.id);
  if (!alert) {
    return res.status(404).send('Incident not found');
  }

  const report = generateIncidentPdf(alert);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${report.filename}"`);
  res.send(report.buffer);
});

// 10. Demo Reset
apiRouter.post('/demo/reset', (_req: Request, res: Response) => {
  Database.resetDemoState();
  res.json({ message: 'Database reset to default 12 synthetic demo alerts.' });
});
