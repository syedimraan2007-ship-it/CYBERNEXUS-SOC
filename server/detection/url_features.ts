/**
 * CYBERNEXUS SOC - Deterministic Phishing URL Feature Extraction
 * Extracts structural signals from URL strings safely WITHOUT making external network requests.
 */

import { UrlFeatures } from '../../src/types/soc';

const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'sign-in',
  'verify',
  'verification',
  'secure',
  'security',
  'update',
  'account',
  'password',
  'confirm',
  'confirmation',
  'wallet',
  'invoice',
  'bank',
  'banking',
  'support',
  'auth',
  'sso',
  'portal',
  'checkpoint',
  'recover',
  'suspended'
];

const SHORTENER_DOMAINS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'is.gd',
  'buff.ly',
  'ow.ly',
  'cutt.ly',
  'rebrand.ly',
  'tiny.cc'
];

function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

function isIpAddress(hostname: string): boolean {
  // IPv4 regex check
  const ipv4Pattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  if (ipv4Pattern.test(hostname)) {
    const parts = hostname.split('.').map(Number);
    return parts.every(part => part >= 0 && part <= 255);
  }
  // IPv6 basic pattern
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    return true;
  }
  return false;
}

export function extractUrlFeatures(rawUrl: string): UrlFeatures {
  let normalized = rawUrl.trim();
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = 'http://' + normalized;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    // If URL parsing fails, create a safe fallback
    return {
      url: rawUrl,
      domain: 'malformed-url.test',
      registeredDomain: 'malformed-url.test',
      tld: 'test',
      protocol: 'unknown:',
      isHttps: false,
      hostIsIp: false,
      port: null,
      subdomainCount: 0,
      urlLength: rawUrl.length,
      domainLength: 0,
      containsAtSymbol: rawUrl.includes('@'),
      hyphenCount: (rawUrl.match(/-/g) || []).length,
      encodedCharCount: (rawUrl.match(/%[0-9a-fA-F]{2}/g) || []).length,
      isPunycode: rawUrl.includes('xn--'),
      isShortener: false,
      suspiciousKeywordsFound: SUSPICIOUS_KEYWORDS.filter(kw => rawUrl.toLowerCase().includes(kw)),
      pathDepth: 0,
      queryParamCount: 0,
      entropy: calculateEntropy(rawUrl),
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const hostIsIp = isIpAddress(hostname);
  const domainParts = hostname.split('.');

  let tld = '';
  let registeredDomain = hostname;
  let subdomainCount = 0;

  if (hostIsIp) {
    tld = 'ip';
    registeredDomain = hostname;
    subdomainCount = 0;
  } else if (domainParts.length >= 2) {
    tld = domainParts[domainParts.length - 1];
    registeredDomain = domainParts.slice(-2).join('.');
    subdomainCount = Math.max(0, domainParts.length - 2);
  }

  const urlLower = rawUrl.toLowerCase();
  const suspiciousKeywordsFound = SUSPICIOUS_KEYWORDS.filter(kw => urlLower.includes(kw));
  const isShortener = SHORTENER_DOMAINS.some(short => hostname === short || hostname.endsWith('.' + short));
  const isPunycode = hostname.includes('xn--');
  const pathDepth = parsed.pathname.split('/').filter(Boolean).length;
  const queryParamCount = Array.from(parsed.searchParams.keys()).length;

  return {
    url: rawUrl,
    domain: hostname,
    registeredDomain,
    tld,
    protocol: parsed.protocol,
    isHttps: parsed.protocol === 'https:',
    hostIsIp,
    port: parsed.port ? parseInt(parsed.port, 10) : null,
    subdomainCount,
    urlLength: rawUrl.length,
    domainLength: hostname.length,
    containsAtSymbol: rawUrl.includes('@'),
    hyphenCount: (rawUrl.match(/-/g) || []).length,
    encodedCharCount: (rawUrl.match(/%[0-9a-fA-F]{2}/g) || []).length,
    isPunycode,
    isShortener,
    suspiciousKeywordsFound,
    pathDepth,
    queryParamCount,
    entropy: calculateEntropy(hostname + parsed.pathname),
  };
}
