/**
 * CYBERNEXUS SOC - Security Audit Logging & Rate Limiting
 */

export interface AuditRecord {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  targetId?: string;
  details: Record<string, unknown>;
  ip?: string;
}

const AUDIT_LOGS: AuditRecord[] = [];

export function logAudit(
  actor: string,
  action: string,
  targetId?: string,
  details: Record<string, unknown> = {},
  ip?: string
): void {
  const record: AuditRecord = {
    id: `AUD-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
    actor,
    action,
    targetId,
    details,
    ip,
  };
  AUDIT_LOGS.unshift(record);
  if (AUDIT_LOGS.length > 500) {
    AUDIT_LOGS.pop();
  }
}

export function getAuditLogs(): AuditRecord[] {
  return [...AUDIT_LOGS];
}

// In-memory rate limiter
const RATE_LIMIT_BUCKET: Map<string, { count: number; resetTime: number }> = new Map();

export function checkRateLimit(ip: string, maxRequests: number = 60, windowMs: number = 60000): boolean {
  const now = Date.now();
  const entry = RATE_LIMIT_BUCKET.get(ip);

  if (!entry || now > entry.resetTime) {
    RATE_LIMIT_BUCKET.set(ip, { count: 1, resetTime: now + windowMs });
    return true;
  }

  if (entry.count >= maxRequests) {
    return false;
  }

  entry.count++;
  return true;
}
