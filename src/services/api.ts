/**
 * CYBERNEXUS SOC - Client API Service
 * Connects React client to full-stack Express API endpoints.
 */

import {
  Alert,
  AlertStatus,
  IndicatorType,
  MitreTechnique,
  SocDashboardStats,
  SystemHealthState,
  User,
} from '../types/soc';

const API_BASE = '/api';

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('cnx_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function fetchHealth(): Promise<SystemHealthState> {
  try {
    const res = await fetch(`${API_BASE}/system/health`);
    if (!res.ok) throw new Error('Health check failed');
    return await res.json();
  } catch {
    return {
      backend: 'OFFLINE',
      database: 'OFFLINE',
      aiProvider: 'OFFLINE',
      threatIntel: 'OFFLINE',
      mitre: 'OFFLINE',
      activeProviderName: 'None (Client Offline)',
      syntheticDataMode: true,
      timestamp: new Date().toISOString(),
    };
  }
}

export async function fetchAlerts(): Promise<{ alerts: Alert[]; stats: SocDashboardStats }> {
  const res = await fetch(`${API_BASE}/alerts`, {
    headers: { ...getAuthHeader() },
  });
  if (!res.ok) throw new Error('Failed to fetch alerts');
  return await res.json();
}

export async function fetchAlertById(id: string): Promise<Alert> {
  const res = await fetch(`${API_BASE}/alerts/${encodeURIComponent(id)}`, {
    headers: { ...getAuthHeader() },
  });
  if (!res.ok) throw new Error(`Alert ${id} not found`);
  return await res.json();
}

export async function runInvestigation(id: string): Promise<Alert> {
  const res = await fetch(`${API_BASE}/incidents/${encodeURIComponent(id)}/investigate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader(),
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Investigation run failed');
  }
  return await res.json();
}

export async function updateIncidentStatus(
  id: string,
  status: AlertStatus,
  resolutionNote?: string
): Promise<Alert> {
  const res = await fetch(`${API_BASE}/incidents/${encodeURIComponent(id)}/status`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader(),
    },
    body: JSON.stringify({ status, resolutionNote }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to update status');
  }
  return await res.json();
}

export async function addIncidentNote(id: string, content: string): Promise<Alert> {
  const res = await fetch(`${API_BASE}/incidents/${encodeURIComponent(id)}/notes`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader(),
    },
    body: JSON.stringify({ content }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to add note');
  }
  return await res.json();
}

export async function updateResponseAction(
  alertId: string,
  actionId: string,
  status: 'PENDING_REVIEW' | 'APPROVED' | 'DISMISSED'
): Promise<Alert> {
  const res = await fetch(`${API_BASE}/incidents/${encodeURIComponent(alertId)}/actions/${encodeURIComponent(actionId)}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader(),
    },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to update action');
  }
  return await res.json();
}

export async function analyzeUrl(url: string) {
  const res = await fetch(`${API_BASE}/analyze/url`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader(),
    },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'URL analysis failed');
  }
  return await res.json();
}

export async function analyzeIndicator(indicator: string, type: IndicatorType) {
  const res = await fetch(`${API_BASE}/analyze/indicator`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader(),
    },
    body: JSON.stringify({ indicator, type }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Indicator analysis failed');
  }
  return await res.json();
}

export async function fetchMitreTechniques(): Promise<MitreTechnique[]> {
  const res = await fetch(`${API_BASE}/mitre/techniques`);
  if (!res.ok) throw new Error('Failed to fetch MITRE techniques');
  return await res.json();
}

export async function generateReport(alertId: string): Promise<{ filename: string; base64: string; alertId: string }> {
  const res = await fetch(`${API_BASE}/reports/generate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader(),
    },
    body: JSON.stringify({ alertId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to generate PDF report');
  }
  return await res.json();
}

export async function loginUser(username: string): Promise<{ token: string; user: User }> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Login failed');
  }
  const data = await res.json();
  localStorage.setItem('cnx_token', data.token);
  localStorage.setItem('cnx_user', JSON.stringify(data.user));
  return data;
}

export async function resetDemoData(): Promise<void> {
  await fetch(`${API_BASE}/demo/reset`, {
    method: 'POST',
    headers: { ...getAuthHeader() },
  });
}
