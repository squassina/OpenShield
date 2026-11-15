import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { KeyRound, Lock, Plus, ShieldCheck, Trash2, UserCheck } from 'lucide-react';
import { api } from '../lib/api';
import type { AuthStatus, AuthUserSummary, SimulatedRole } from '../types/openshield';

interface AuthSecurityCardProps {
  authStatus: AuthStatus | null;
  persistentUciFirewall: boolean;
  onTogglePersistentUci: (enabled: boolean) => Promise<void>;
  onAuthStatusChange: (next: AuthStatus) => void;
  onNotifyToast: (kind: 'info' | 'error', message: string) => void;
  busyKey: string | null;
}

export function AuthSecurityCard({
  authStatus,
  persistentUciFirewall,
  onTogglePersistentUci,
  onAuthStatusChange,
  onNotifyToast,
  busyKey,
}: AuthSecurityCardProps) {
  const { t } = useTranslation();
  const [setupUsername, setSetupUsername] = useState('admin');
  const [setupPassword, setSetupPassword] = useState('');
  const [users, setUsers] = useState<AuthUserSummary[]>([]);
  const [newUsername, setNewUsername] = useState('');
  const [newRole, setNewRole] = useState<SimulatedRole>('operator');
  const [newPassword, setNewPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const isAdminSession = Boolean(authStatus?.authenticated && authStatus.user?.role === 'admin');

  const refreshUsers = useCallback(async () => {
    if (!isAdminSession) {
      setUsers([]);
      return;
    }
    try {
      const res = await api.listAuthUsers();
      setUsers(res.users);
    } catch {
      // Ignore if not admin
    }
  }, [isAdminSession]);

  useEffect(() => {
    void refreshUsers();
  }, [refreshUsers]);

  const handleSetupAdmin = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await api.setupInitialAdmin({
        username: setupUsername.trim() || 'admin',
        password: setupPassword,
      });
      setSetupPassword('');
      onAuthStatusChange(res.status);
      onNotifyToast('info', t('auth.setupSuccess', { username: res.user.username }));
    } catch (err) {
      onNotifyToast('error', err instanceof Error ? err.message : t('toasts.operationError'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpsertUser = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await api.upsertAuthUser({
        username: newUsername.trim(),
        role: newRole,
        password: newPassword,
      });
      setUsers(res.users);
      setNewUsername('');
      setNewPassword('');
      onNotifyToast('info', t('auth.userSaved', { username: res.user.username, role: res.user.role }));
    } catch (err) {
      onNotifyToast('error', err instanceof Error ? err.message : t('toasts.operationError'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteUser = async (username: string) => {
    setSubmitting(true);
    try {
      const res = await api.deleteAuthUser(username);
      setUsers(res.users);
      onNotifyToast('info', t('auth.userDeleted', { username }));
    } catch (err) {
      onNotifyToast('error', err instanceof Error ? err.message : t('toasts.operationError'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-slate-800 pb-3.5">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Lock className="w-4 h-4 text-blue-400 shrink-0" />
            <span>{t('auth.settingsTitle')}</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">{t('auth.settingsSubtitle')}</p>
        </div>

        <div className="flex items-center gap-3 text-xs shrink-0">
          <span className="text-slate-400">{t('auth.sessionStatusLabel')}</span>
          {authStatus?.authConfigured ? (
            <span className="inline-flex items-center gap-1.5 font-medium text-emerald-400">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>{t('auth.statusProtected')}</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 font-medium text-amber-300">
              <KeyRound className="w-3.5 h-3.5" />
              <span>{t('auth.statusLanOpen')}</span>
            </span>
          )}
        </div>
      </div>

      {/* Firewall Reboot Persistence Toggle */}
      <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="space-y-0.5 text-xs">
          <div className="font-semibold text-slate-100">{t('policies.uciPersistTitle')}</div>
          <p className="text-slate-400 leading-relaxed">{t('policies.uciPersistLongDesc')}</p>
        </div>
        <button
          type="button"
          disabled={busyKey === 'uci-persist'}
          onClick={() => void onTogglePersistentUci(!persistentUciFirewall)}
          className={`px-3.5 py-2 text-xs font-medium rounded-lg whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50 ${
            persistentUciFirewall
              ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-700/50'
              : 'bg-slate-900 text-slate-300 border border-slate-700 hover:bg-slate-800'
          }`}
        >
          {persistentUciFirewall ? t('common.enabled') : t('common.disabled')}
        </button>
      </div>

      {/* Initial Admin Setup vs Authenticated RBAC Users */}
      {!authStatus?.authConfigured ? (
        <form
          onSubmit={(e) => void handleSetupAdmin(e)}
          className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-4"
        >
          <div className="space-y-1 text-xs">
            <div className="font-semibold text-slate-100 flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-blue-400" />
              <span>{t('auth.setupCardTitle')}</span>
            </div>
            <p className="text-slate-400">{t('auth.setupCardDesc')}</p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">{t('auth.usernameLabel')}</span>
              <input
                type="text"
                required
                minLength={2}
                maxLength={48}
                value={setupUsername}
                onChange={(e) => setSetupUsername(e.target.value)}
                placeholder="admin"
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">{t('auth.passwordMinLabel')}</span>
              <input
                type="password"
                required
                minLength={8}
                autoComplete="new-password"
                value={setupPassword}
                onChange={(e) => setSetupPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <button
              type="submit"
              disabled={submitting}
              className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>{t('auth.enableAuthButton')}</span>
            </button>
          </div>
        </form>
      ) : (
        <div className="space-y-4">
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="space-y-0.5">
              <div className="text-slate-300">
                {t('auth.activeSessionSummary', {
                  username: authStatus.user?.username ?? 'env-admin',
                  role: authStatus.user?.role ?? 'admin',
                })}
              </div>
              <div className="text-[11px] text-slate-500">{t('auth.cookieHardeningNote')}</div>
            </div>
            {authStatus.envAdminEnabled && (
              <span className="font-mono text-[11px] text-emerald-400">
                OPENSHIELD_ADMIN_PASSWORD
              </span>
            )}
          </div>

          {isAdminSession ? (
            <div className="space-y-4">
              <form
                onSubmit={(e) => void handleUpsertUser(e)}
                className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-3"
              >
                <div className="text-xs font-semibold text-slate-200">{t('auth.manageUsersTitle')}</div>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
                  <label className="block space-y-1 text-xs">
                    <span className="text-slate-300 font-medium">{t('auth.usernameLabel')}</span>
                    <input
                      type="text"
                      required
                      minLength={2}
                      maxLength={48}
                      value={newUsername}
                      onChange={(e) => setNewUsername(e.target.value)}
                      placeholder="operador-soc"
                      className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
                    />
                  </label>

                  <label className="block space-y-1 text-xs">
                    <span className="text-slate-300 font-medium">{t('auth.roleLabel')}</span>
                    <select
                      value={newRole}
                      onChange={(e) => setNewRole(e.target.value as SimulatedRole)}
                      className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                    >
                      <option value="admin">{t('toolbar.roleAdmin')}</option>
                      <option value="operator">{t('toolbar.roleOperator')}</option>
                      <option value="auditor">{t('toolbar.roleAuditor')}</option>
                    </select>
                  </label>

                  <label className="block space-y-1 text-xs">
                    <span className="text-slate-300 font-medium">{t('auth.passwordMinLabel')}</span>
                    <input
                      type="password"
                      required
                      minLength={8}
                      autoComplete="new-password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="••••••••"
                      className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
                    />
                  </label>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>{t('auth.saveUserButton')}</span>
                  </button>
                </div>
              </form>

              {users.length > 0 && (
                <div className="rounded-lg border border-slate-800 bg-slate-950/40 divide-y divide-slate-800/80">
                  {users.map((user) => {
                    const isSelf =
                      authStatus.user?.username.toLowerCase() === user.username.toLowerCase();
                    return (
                      <div
                        key={user.username}
                        className="px-4 py-2.5 flex items-center justify-between gap-3 text-xs"
                      >
                        <div className="flex flex-wrap items-center gap-2 font-mono">
                          <span className="text-slate-100 font-semibold">{user.username}</span>
                          <span className="text-slate-500">·</span>
                          <span className="text-blue-300">{user.role}</span>
                          {isSelf && (
                            <span className="text-[11px] text-emerald-400">
                              ({t('auth.currentSessionTag')})
                            </span>
                          )}
                        </div>
                        <button
                          type="button"
                          disabled={submitting || isSelf}
                          onClick={() => void handleDeleteUser(user.username)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded border border-red-900/60 text-red-300 hover:bg-red-950/50 disabled:opacity-35 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          <Trash2 className="w-3 h-3" />
                          <span>{t('common.remove')}</span>
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-400">{t('auth.adminOnlyUsersNote')}</p>
          )}
        </div>
      )}
    </section>
  );
}
