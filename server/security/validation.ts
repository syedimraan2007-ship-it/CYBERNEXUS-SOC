/**
 * CYBERNEXUS SOC - Security Validation & Anti-SSRF Guard
 * Non-Negotiable Safety Rule:
 * The backend must NEVER directly fetch arbitrary user-submitted URLs.
 */

export interface ValidationResult {
  isValid: boolean;
  sanitized: string;
  error?: string;
}

const FORBIDDEN_PROTOCOLS = ['file:', 'gopher:', 'ftp:', 'ssh:', 'ldap:', 'dict:'];
const METADATA_IP_PATTERNS = [
  '169.254.169.254',
  'metadata.google.internal',
  '127.0.0.1',
  'localhost',
  '0.0.0.0',
];

export function validateUrlInput(rawInput: string): ValidationResult {
  if (!rawInput || typeof rawInput !== 'string') {
    return { isValid: false, sanitized: '', error: 'URL input must be a non-empty string.' };
  }

  const trimmed = rawInput.trim();
  if (trimmed.length > 2048) {
    return { isValid: false, sanitized: '', error: 'URL exceeds maximum permitted length (2048 characters).' };
  }

  for (const proto of FORBIDDEN_PROTOCOLS) {
    if (trimmed.toLowerCase().startsWith(proto)) {
      return { isValid: false, sanitized: '', error: `Protocol ${proto} is prohibited by security policy.` };
    }
  }

  // Prevent SSRF attempts on internal cloud metadata
  for (const meta of METADATA_IP_PATTERNS) {
    if (trimmed.toLowerCase().includes(meta)) {
      return { isValid: false, sanitized: '', error: 'Target host is restricted by local security policy.' };
    }
  }

  // Safe to analyze purely syntactically without network fetching
  return { isValid: true, sanitized: trimmed };
}

export function validateIndicatorInput(indicator: string, type: string): ValidationResult {
  if (!indicator || typeof indicator !== 'string') {
    return { isValid: false, sanitized: '', error: 'Indicator must be a non-empty string.' };
  }

  const trimmed = indicator.trim();
  if (trimmed.length > 512) {
    return { isValid: false, sanitized: '', error: 'Indicator exceeds length limit.' };
  }

  if (type === 'HASH') {
    if (!/^[a-fA-F0-9]{32,64}$/.test(trimmed)) {
      return { isValid: false, sanitized: '', error: 'Invalid hash format. Must be MD5 (32 hex) or SHA-256 (64 hex).' };
    }
  }

  return { isValid: true, sanitized: trimmed };
}
