import crypto from 'node:crypto';
import type { AuthStatus, AuthUserSummary, SimulatedRole } from '../src/types/openshield.ts';
import type { SqlitePersistence } from './persistence.ts';

export const SESSION_COOKIE_NAME = 'openshield_session';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export interface SessionPayload {
  username: string;
  role: SimulatedRole;
  exp: number;
}

export function hashPassword(password: string, existingSalt?: string): { hash: string; salt: string } {
  const salt = existingSalt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash: derived, salt };
}

export function verifyPassword(password: string, expectedHash: string, salt: string): boolean {
  const derived = crypto.scryptSync(password, salt, 64);
  const expectedBuf = Buffer.from(expectedHash, 'hex');
  if (derived.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(derived, expectedBuf);
}

export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(val);
    } catch {
      out[key] = val;
    }
  }
  return out;
}

export class AuthService {
  private persistence: SqlitePersistence;
  private signingSecret: string;

  constructor(persistence: SqlitePersistence) {
    this.persistence = persistence;
    const envSecret = process.env.OPENSHIELD_SESSION_SECRET?.trim();
    this.signingSecret =
      envSecret && envSecret.length >= 16
        ? envSecret
        : this.persistence.getOrCreateAuthSigningSecret(crypto.randomBytes(32).toString('hex'));
  }

  private sign(payload: SessionPayload): string {
    const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig = crypto
      .createHmac('sha256', this.signingSecret)
      .update(encoded)
      .digest('base64url');
    return `${encoded}.${sig}`;
  }

  verifySessionToken(token: string | undefined): SessionPayload | null {
    if (!token || !token.includes('.')) return null;
    const [encoded, sig] = token.split('.', 2);
    if (!encoded || !sig) return null;
    const expectedSig = crypto
      .createHmac('sha256', this.signingSecret)
      .update(encoded)
      .digest('base64url');
    const sigBuf = Buffer.from(sig);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }
    try {
      const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as SessionPayload;
      if (!parsed.username || !parsed.role || !Number.isFinite(parsed.exp)) return null;
      if (Date.now() > parsed.exp) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  buildSessionCookieHeader(
    user: { username: string; role: SimulatedRole },
    isSecureRequest: boolean,
  ): string {
    const token = this.sign({
      username: user.username,
      role: user.role,
      exp: Date.now() + SESSION_TTL_MS,
    });
    const parts = [
      `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
    ];
    if (isSecureRequest) {
      parts.push('Secure');
    }
    return parts.join('; ');
  }

  buildClearCookieHeader(isSecureRequest: boolean): string {
    const parts = [
      `${SESSION_COOKIE_NAME}=`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      'Max-Age=0',
    ];
    if (isSecureRequest) {
      parts.push('Secure');
    }
    return parts.join('; ');
  }

  isEnvAdminConfigured(): boolean {
    return Boolean(process.env.OPENSHIELD_ADMIN_PASSWORD?.trim());
  }

  isAuthConfigured(): boolean {
    return this.persistence.countAuthUsers() > 0 || this.isEnvAdminConfigured();
  }

  isAuthRequired(): boolean {
    if (this.isAuthConfigured()) return true;
    return process.env.OPENSHIELD_AUTH_REQUIRED === 'true';
  }

  getAuthStatus(cookieHeader: string | undefined): AuthStatus {
    const cookies = parseCookies(cookieHeader);
    const session = this.verifySessionToken(cookies[SESSION_COOKIE_NAME]);
    const configured = this.isAuthConfigured();
    const required = this.isAuthRequired();
    return {
      authConfigured: configured,
      authRequired: required,
      authenticated: Boolean(session),
      envAdminEnabled: this.isEnvAdminConfigured(),
      user: session ? { username: session.username, role: session.role } : null,
    };
  }

  authenticateFromCookie(cookieHeader: string | undefined): SessionPayload | null {
    const cookies = parseCookies(cookieHeader);
    return this.verifySessionToken(cookies[SESSION_COOKIE_NAME]);
  }

  setupInitialAdmin(username: string, password: string): AuthUserSummary {
    if (this.persistence.countAuthUsers() > 0) {
      throw new Error('Já existe pelo menos um usuário configurado no painel.');
    }
    const cleanUser = username.trim().toLowerCase() || 'admin';
    if (cleanUser.length < 2 || cleanUser.length > 48 || !/^[a-z0-9._-]+$/.test(cleanUser)) {
      throw new Error('Nome de usuário inválido (use 2-48 caracteres alfanuméricos, ".", "_" ou "-").');
    }
    if (password.length < 8) {
      throw new Error('A senha deve ter pelo menos 8 caracteres.');
    }
    const { hash, salt } = hashPassword(password);
    return this.persistence.upsertAuthUser({
      username: cleanUser,
      role: 'admin',
      passwordHash: hash,
      salt,
    });
  }

  login(username: string, password: string): { username: string; role: SimulatedRole } {
    const cleanUser = username.trim().toLowerCase();
    if (!cleanUser || !password) {
      throw new Error('Usuário e senha são obrigatórios.');
    }

    const dbUser = this.persistence.getAuthUser(cleanUser);
    if (dbUser) {
      if (!verifyPassword(password, dbUser.passwordHash, dbUser.salt)) {
        throw new Error('Credenciais inválidas.');
      }
      return { username: dbUser.username, role: dbUser.role };
    }

    const envPass = process.env.OPENSHIELD_ADMIN_PASSWORD?.trim();
    const envUser = (process.env.OPENSHIELD_ADMIN_USERNAME?.trim() || 'admin').toLowerCase();
    if (envPass && cleanUser === envUser) {
      const a = Buffer.from(password, 'utf8');
      const b = Buffer.from(envPass, 'utf8');
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
        return { username: envUser, role: 'admin' };
      }
    }

    throw new Error('Credenciais inválidas.');
  }

  listUsers(): AuthUserSummary[] {
    return this.persistence.listAuthUsers();
  }

  upsertUser(input: { username: string; role: SimulatedRole; password: string }): AuthUserSummary {
    const cleanUser = input.username.trim().toLowerCase();
    if (cleanUser.length < 2 || cleanUser.length > 48 || !/^[a-z0-9._-]+$/.test(cleanUser)) {
      throw new Error('Nome de usuário inválido (use 2-48 caracteres alfanuméricos, ".", "_" ou "-").');
    }
    if (input.password.length < 8) {
      throw new Error('A senha deve ter pelo menos 8 caracteres.');
    }
    if (!['admin', 'operator', 'auditor'].includes(input.role)) {
      throw new Error('Papel RBAC inválido.');
    }
    const { hash, salt } = hashPassword(input.password);
    return this.persistence.upsertAuthUser({
      username: cleanUser,
      role: input.role,
      passwordHash: hash,
      salt,
    });
  }

  deleteUser(username: string, currentUsername?: string): void {
    const clean = username.trim().toLowerCase();
    if (currentUsername && clean === currentUsername.toLowerCase()) {
      throw new Error('Você não pode remover o usuário autenticado na sessão atual.');
    }
    const users = this.persistence.listAuthUsers();
    const target = users.find((u) => u.username === clean);
    if (!target) {
      throw new Error(`Usuário "${clean}" não encontrado.`);
    }
    if (target.role === 'admin') {
      const adminCount = users.filter((u) => u.role === 'admin').length;
      if (adminCount <= 1 && !this.isEnvAdminConfigured()) {
        throw new Error('Mantenha pelo menos um usuário Administrador configurado.');
      }
    }
    this.persistence.deleteAuthUser(clean);
  }
}
