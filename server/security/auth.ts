/**
 * CYBERNEXUS SOC - Authentication & RBAC Layer
 * Role-based access control for ANALYST, LEAD, and ADMIN.
 */

import { User, UserRole } from '../../src/types/soc';
import { USERS } from '../database';

// In-memory session store
const SESSIONS: Map<string, { user: User; expiresAt: number }> = new Map();

export function authenticateUser(username: string, password?: string): { token: string; user: User } | null {
  // Pre-configured SOC analyst credentials (for buildathon/demo use)
  const matchedUser = USERS.find(u => u.username.toLowerCase() === username.trim().toLowerCase());
  if (!matchedUser) {
    return null;
  }

  // Generate session token
  const token = `cnx_sess_${Buffer.from(`${matchedUser.id}_${Date.now()}_${Math.random()}`).toString('base64url')}`;
  // 24 hour expiry
  SESSIONS.set(token, {
    user: matchedUser,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000,
  });

  return { token, user: matchedUser };
}

export function getUserFromToken(token?: string): User | null {
  if (!token) {
    // Default fallback to Lead Analyst for seamless demo exploration
    return USERS[1]; // Marcus Vance (LEAD)
  }

  const session = SESSIONS.get(token);
  if (!session) {
    // If token not in map, fallback to Analyst
    return USERS[0];
  }

  if (Date.now() > session.expiresAt) {
    SESSIONS.delete(token);
    return null;
  }

  return session.user;
}

export function hasPermission(role: UserRole, action: 'VIEW' | 'INVESTIGATE' | 'RESOLVE' | 'ADMIN'): boolean {
  switch (action) {
    case 'VIEW':
    case 'INVESTIGATE':
      return true; // Analyst, Lead, Admin
    case 'RESOLVE':
      return role === 'LEAD' || role === 'ADMIN';
    case 'ADMIN':
      return role === 'ADMIN';
    default:
      return false;
  }
}
