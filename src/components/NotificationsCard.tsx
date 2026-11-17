import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertCircle,
  BellRing,
  CheckCircle2,
  Edit3,
  Mail,
  Pause,
  Play,
  Plus,
  Send,
  ShieldCheck,
  Trash2,
  Webhook,
  X,
} from 'lucide-react';
import { getIntlLocale } from '../i18n';
import { PaginationControls, usePagination } from './PaginationControls';
import type {
  NotificationChannelType,
  NotificationDestination,
  NotificationSeverityThreshold,
  NotificationTriggerEvent,
  WorkspaceState,
} from '../types/openshield';

export interface NotificationCreatePayload {
  name: string;
  type: NotificationChannelType;
  target: string;
  enabled?: boolean;
  minSeverity?: NotificationSeverityThreshold;
  triggers?: NotificationTriggerEvent[];
  emailFrom?: string;
  smtpHost?: string;
  smtpPort?: number;
  smtpSecure?: boolean;
  webhookMethod?: 'POST' | 'PUT';
  webhookFormat?: 'openshield_json' | 'slack' | 'discord';
  username?: string;
  secret?: string;
}

export interface NotificationUpdatePayload {
  name?: string;
  enabled?: boolean;
  minSeverity?: NotificationSeverityThreshold;
  triggers?: NotificationTriggerEvent[];
  target?: string;
  emailFrom?: string;
  smtpHost?: string;
  smtpPort?: number;
  smtpSecure?: boolean;
  webhookMethod?: 'POST' | 'PUT';
  webhookFormat?: 'openshield_json' | 'slack' | 'discord';
  username?: string;
  secret?: string;
  clearSecret?: boolean;
}

interface NotificationsCardProps {
  state: WorkspaceState;
  onAddNotification: (payload: NotificationCreatePayload) => Promise<void>;
  onUpdateNotification: (id: string, payload: NotificationUpdatePayload) => Promise<void>;
  onRemoveNotification: (id: string, name: string) => Promise<void>;
  onTestNotification: (id: string) => Promise<void>;
  busyKey: string | null;
}

const TRIGGER_IDS: NotificationTriggerEvent[] = [
  'critical_incident',
  'kill_switch',
  'endpoint_offline',
  'ai_anomaly',
];

function ChannelIcon({ type }: { type: NotificationChannelType }) {
  if (type === 'email') return <Mail className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />;
  if (type === 'telegram') return <Send className="w-4 h-4 text-teal-600 dark:text-teal-400 shrink-0" />;
  return <Webhook className="w-4 h-4 text-emerald-700 dark:text-emerald-300 shrink-0" />;
}

function formatTime(iso: string | undefined, locale: string): string {
  if (!iso) return '—';
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return iso;
  return new Intl.DateTimeFormat(locale, {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(ms));
}

export function NotificationsCard({
  state,
  onAddNotification,
  onUpdateNotification,
  onRemoveNotification,
  onTestNotification,
  busyKey,
}: NotificationsCardProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
  const destinations = state.notifications ?? [];
  const history = state.notificationHistory ?? [];
  const destPagination = usePagination(destinations, 10);
  const historyPagination = usePagination(history, 10);

  const channelLabel = (type: NotificationChannelType): string => {
    if (type === 'email') return t('notifications.channelEmail');
    if (type === 'telegram') return t('notifications.channelTelegram');
    return t('notifications.channelWebhook');
  };

  const severityLabel = (sev: NotificationSeverityThreshold): string => {
    if (sev === 'critical') return t('notifications.sevCritical');
    if (sev === 'high') return t('notifications.sevHigh');
    return t('notifications.sevMedium');
  };

  const triggerLabel = (triggerId: NotificationTriggerEvent): string =>
    t(`notifications.triggers.${triggerId}`);

  const [channelType, setChannelType] = useState<NotificationChannelType>('webhook');
  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [minSeverity, setMinSeverity] = useState<NotificationSeverityThreshold>('high');
  const [triggers, setTriggers] = useState<NotificationTriggerEvent[]>([
    'critical_incident',
    'kill_switch',
    'endpoint_offline',
  ]);

  // Email SMTP state
  const [emailFrom, setEmailFrom] = useState('');
  const [smtpHost, setSmtpHost] = useState('');
  const [smtpPort, setSmtpPort] = useState('587');
  const [smtpSecure, setSmtpSecure] = useState(false);
  const [username, setUsername] = useState('');

  // Webhook state
  const [webhookFormat, setWebhookFormat] = useState<'openshield_json' | 'slack' | 'discord'>(
    'openshield_json',
  );
  const [webhookMethod, setWebhookMethod] = useState<'POST' | 'PUT'>('POST');

  // Shared write-only secret (SMTP pass, Webhook Bearer token, Telegram Bot token)
  const [secret, setSecret] = useState('');

  // Inline edit state
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editDraft, setEditDraft] = useState<{
    name: string;
    target: string;
    minSeverity: NotificationSeverityThreshold;
    triggers: NotificationTriggerEvent[];
    emailFrom: string;
    smtpHost: string;
    smtpPort: string;
    smtpSecure: boolean;
    webhookFormat: 'openshield_json' | 'slack' | 'discord';
    webhookMethod: 'POST' | 'PUT';
    username: string;
    secret: string;
  } | null>(null);

  const toggleTrigger = (
    list: NotificationTriggerEvent[],
    setList: (next: NotificationTriggerEvent[]) => void,
    item: NotificationTriggerEvent,
  ) => {
    if (list.includes(item)) {
      if (list.length <= 1) return;
      setList(list.filter((t) => t !== item));
    } else {
      setList([...list, item]);
    }
  };

  const resetFormFields = (nextType: NotificationChannelType) => {
    setChannelType(nextType);
    setName('');
    setTarget('');
    setEmailFrom('');
    setSmtpHost('');
    setSmtpPort('587');
    setSmtpSecure(false);
    setUsername('');
    setSecret('');
  };

  const handleCreateSubmit = async (e: FormEvent) => {
    e.preventDefault();
    await onAddNotification({
      name:
        name.trim() ||
        (channelType === 'email'
          ? t('notifications.defaultNameEmail')
          : channelType === 'telegram'
            ? t('notifications.defaultNameTelegram')
            : t('notifications.defaultNameWebhook')),
      type: channelType,
      target: target.trim(),
      enabled: true,
      minSeverity,
      triggers,
      emailFrom: channelType === 'email' ? emailFrom.trim() || undefined : undefined,
      smtpHost: channelType === 'email' ? smtpHost.trim() || undefined : undefined,
      smtpPort: channelType === 'email' ? Number(smtpPort) || 587 : undefined,
      smtpSecure: channelType === 'email' ? smtpSecure : undefined,
      webhookFormat: channelType === 'webhook' ? webhookFormat : undefined,
      webhookMethod: channelType === 'webhook' ? webhookMethod : undefined,
      username: channelType === 'email' ? username.trim() || undefined : undefined,
      secret: secret.trim() || undefined,
    });
    setName('');
    setTarget('');
    setSecret('');
  };

  const startEdit = (dest: NotificationDestination) => {
    if (editingId === dest.id) {
      setEditingId(null);
      setEditDraft(null);
      return;
    }
    setEditingId(dest.id);
    setEditDraft({
      name: dest.name,
      target: dest.target,
      minSeverity: dest.minSeverity,
      triggers: dest.triggers,
      emailFrom: dest.emailFrom ?? '',
      smtpHost: dest.smtpHost ?? '',
      smtpPort: String(dest.smtpPort ?? 587),
      smtpSecure: Boolean(dest.smtpSecure),
      webhookFormat: dest.webhookFormat ?? 'openshield_json',
      webhookMethod: dest.webhookMethod ?? 'POST',
      username: dest.usernameHint ?? '',
      secret: '',
    });
  };

  const saveEdit = async (dest: NotificationDestination) => {
    if (!editDraft) return;
    await onUpdateNotification(dest.id, {
      name: editDraft.name,
      target: editDraft.target,
      minSeverity: editDraft.minSeverity,
      triggers: editDraft.triggers,
      emailFrom: dest.type === 'email' ? editDraft.emailFrom : undefined,
      smtpHost: dest.type === 'email' ? editDraft.smtpHost : undefined,
      smtpPort: dest.type === 'email' ? Number(editDraft.smtpPort) || 587 : undefined,
      smtpSecure: dest.type === 'email' ? editDraft.smtpSecure : undefined,
      webhookFormat: dest.type === 'webhook' ? editDraft.webhookFormat : undefined,
      webhookMethod: dest.type === 'webhook' ? editDraft.webhookMethod : undefined,
      username: dest.type === 'email' ? editDraft.username : undefined,
      secret: editDraft.secret ? editDraft.secret : undefined,
    });
    setEditingId(null);
    setEditDraft(null);
  };

  const activeCount = destinations.filter((d) => d.enabled).length;

  return (
    <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-5 space-y-5">
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <BellRing className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
            <span>{t('notifications.title')}</span>
          </h2>
          <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5 max-w-3xl">
            {t('notifications.subtitle')}
          </p>
        </div>

        <div className="text-xs text-slate-700 dark:text-slate-300 tabular-nums shrink-0">
          {t('notifications.activeSummary', {
            active: activeCount,
            total: destinations.length,
          })}
        </div>
      </div>

      {/* Add Notification Destination Form */}
      <form
        onSubmit={handleCreateSubmit}
        className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-4 space-y-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
            <Plus className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
            <span>{t('notifications.addDestinationTitle')}</span>
          </div>

          <div className="inline-flex flex-wrap items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-[#0B1120] border border-slate-200 dark:border-slate-800">
            {(['webhook', 'email', 'telegram'] as NotificationChannelType[]).map((type) => {
              const active = channelType === type;
              return (
                <button
                  key={type}
                  type="button"
                  onClick={() => resetFormFields(type)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    active
                      ? 'bg-emerald-600 text-white'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-900'
                  }`}
                >
                  <ChannelIcon type={type} />
                  <span>{channelLabel(type)}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 text-xs">
          <label className="space-y-1">
            <span className="text-slate-700 dark:text-slate-300 font-medium">{t('notifications.destName')}</span>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={
                channelType === 'email'
                  ? t('notifications.destNameEmailPh')
                  : channelType === 'telegram'
                    ? t('notifications.destNameTelegramPh')
                    : t('notifications.destNameWebhookPh')
              }
              className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-600 text-xs focus:outline-none focus:border-emerald-500"
            />
          </label>

          {channelType === 'webhook' && (
            <>
              <label className="space-y-1 md:col-span-2">
                <span className="text-slate-700 dark:text-slate-300 font-medium">{t('notifications.webhookUrl')}</span>
                <input
                  type="url"
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://hooks.slack.com/services/... | https://discord.com/api/webhooks/..."
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </label>

              <div className="grid grid-cols-2 gap-2">
                <label className="space-y-1">
                  <span className="text-slate-700 dark:text-slate-300 font-medium">
                    {t('notifications.formatLabel')}
                  </span>
                  <select
                    value={webhookFormat}
                    onChange={(e) =>
                      setWebhookFormat(
                        e.target.value as 'openshield_json' | 'slack' | 'discord',
                      )
                    }
                    className="w-full px-2.5 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-emerald-500"
                  >
                    <option value="openshield_json">
                      {t('notifications.formatOpenShieldJson')}
                    </option>
                    <option value="slack">Slack</option>
                    <option value="discord">Discord</option>
                  </select>
                </label>

                <label className="space-y-1">
                  <span className="text-slate-700 dark:text-slate-300 font-medium">
                    {t('notifications.methodLabel')}
                  </span>
                  <select
                    value={webhookMethod}
                    onChange={(e) => setWebhookMethod(e.target.value as 'POST' | 'PUT')}
                    className="w-full px-2.5 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                  >
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                  </select>
                </label>
              </div>

              <label className="space-y-1 md:col-span-2">
                <span className="text-slate-700 dark:text-slate-300 font-medium">
                  {t('notifications.webhookSecretLabel')}
                </span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder={t('notifications.webhookSecretPh')}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </label>
            </>
          )}

          {channelType === 'email' && (
            <>
              <label className="space-y-1">
                <span className="text-slate-700 dark:text-slate-300 font-medium">
                  {t('notifications.emailRecipient')}
                </span>
                <input
                  type="email"
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="security@company.com"
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </label>

              <label className="space-y-1">
                <span className="text-slate-700 dark:text-slate-300 font-medium">{t('notifications.smtpHost')}</span>
                <input
                  type="text"
                  required
                  value={smtpHost}
                  onChange={(e) => setSmtpHost(e.target.value)}
                  placeholder="smtp.gmail.com / 192.168.1.10"
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </label>

              <div className="grid grid-cols-2 gap-2">
                <label className="space-y-1">
                  <span className="text-slate-700 dark:text-slate-300 font-medium">{t('notifications.smtpPort')}</span>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={smtpPort}
                    onChange={(e) => setSmtpPort(e.target.value)}
                    className="w-full px-2.5 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                  />
                </label>

                <label className="flex items-center gap-2 pt-5 cursor-pointer text-slate-700 dark:text-slate-300">
                  <input
                    type="checkbox"
                    checked={smtpSecure}
                    onChange={(e) => setSmtpSecure(e.target.checked)}
                    className="rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-emerald-600 focus:ring-emerald-500"
                  />
                  <span>{t('notifications.smtpTls')}</span>
                </label>
              </div>

              <label className="space-y-1">
                <span className="text-slate-700 dark:text-slate-300 font-medium">{t('notifications.emailFrom')}</span>
                <input
                  type="email"
                  value={emailFrom}
                  onChange={(e) => setEmailFrom(e.target.value)}
                  placeholder="openshield@network.local"
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </label>

              <label className="space-y-1">
                <span className="text-slate-700 dark:text-slate-300 font-medium">{t('notifications.smtpUser')}</span>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={t('notifications.smtpUserPh')}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </label>

              <label className="space-y-1">
                <span className="text-slate-700 dark:text-slate-300 font-medium">{t('notifications.smtpPass')}</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder={t('notifications.smtpPassPh')}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </label>
            </>
          )}

          {channelType === 'telegram' && (
            <>
              <label className="space-y-1">
                <span className="text-slate-700 dark:text-slate-300 font-medium">
                  {t('notifications.telegramChatId')}
                </span>
                <input
                  type="text"
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="-1001987654321"
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </label>

              <label className="space-y-1 md:col-span-2">
                <span className="text-slate-700 dark:text-slate-300 font-medium">
                  {t('notifications.telegramBotToken')}
                </span>
                <input
                  type="password"
                  required
                  autoComplete="new-password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder="7123456789:AAF..."
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </label>
            </>
          )}

          <label className="space-y-1">
            <span className="text-slate-700 dark:text-slate-300 font-medium">{t('notifications.minSeverity')}</span>
            <select
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value as NotificationSeverityThreshold)}
              className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-emerald-500"
            >
              <option value="critical">{t('notifications.sevCritical')}</option>
              <option value="high">{t('notifications.sevHigh')}</option>
              <option value="medium">{t('notifications.sevMedium')}</option>
            </select>
          </label>
        </div>

        {/* Trigger Checkboxes + Save Button */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-200 dark:border-slate-800/80">
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <span className="text-slate-600 dark:text-slate-400 font-medium">{t('notifications.autoTriggers')}</span>
            {TRIGGER_IDS.map((triggerId) => (
              <label
                key={triggerId}
                className="inline-flex items-center gap-1.5 text-slate-700 dark:text-slate-300 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={triggers.includes(triggerId)}
                  onChange={() => toggleTrigger(triggers, setTriggers, triggerId)}
                  className="rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-emerald-600 focus:ring-emerald-500"
                />
                <span>{triggerLabel(triggerId)}</span>
              </label>
            ))}
          </div>

          <button
            type="submit"
            disabled={busyKey === 'notif-add'}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{t('notifications.saveDestination')}</span>
          </button>
        </div>
      </form>

      {/* Configured Destinations List */}
      {destinations.length === 0 ? (
        <div className="rounded-lg border border-dashed border-slate-300 dark:border-slate-800 bg-slate-50 dark:bg-[#0B1120]/60 p-6 text-center space-y-1.5">
          <BellRing className="w-6 h-6 text-slate-400 dark:text-slate-600 mx-auto" />
          <div className="text-xs font-medium text-slate-700 dark:text-slate-300">
            {t('notifications.emptyTitle')}
          </div>
          <p className="text-[11px] text-slate-500 max-w-lg mx-auto">
            {t('notifications.emptySubtitle')}
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#0B1120]/50 overflow-hidden">
          <div className="divide-y divide-slate-200 dark:divide-slate-800 max-h-[420px] overflow-y-auto">
            {destPagination.pagedItems.map((dest) => {
            const isEditing = editingId === dest.id && editDraft !== null;
            const isBusy =
              busyKey === `notif-upd-${dest.id}` ||
              busyKey === `notif-test-${dest.id}` ||
              busyKey === `notif-rm-${dest.id}`;

            return (
              <div key={dest.id} className="p-4 space-y-3">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <ChannelIcon type={dest.type} />
                      <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{dest.name}</span>
                      <span className="text-slate-400 dark:text-slate-500">·</span>
                      <span className="text-slate-700 dark:text-slate-300">{channelLabel(dest.type)}</span>
                      <span className="text-slate-400 dark:text-slate-500">·</span>
                      {dest.enabled ? (
                        <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>{t('common.active')}</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-slate-500 font-medium">
                          <Pause className="w-3.5 h-3.5" />
                          <span>{t('common.paused')}</span>
                        </span>
                      )}
                      {dest.hasSecret && (
                        <>
                          <span className="text-slate-400 dark:text-slate-500">·</span>
                          <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            <span>{t('notifications.secretInVault')}</span>
                          </span>
                        </>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-600 dark:text-slate-400">
                      <span className="font-mono text-slate-800 dark:text-slate-300 truncate max-w-md">
                        {dest.target}
                      </span>
                      {dest.type === 'email' && dest.smtpHost && (
                        <>
                          <span>·</span>
                          <span className="font-mono">
                            SMTP {dest.smtpHost}:{dest.smtpPort || 587}
                          </span>
                        </>
                      )}
                      {dest.type === 'webhook' && (
                        <>
                          <span>·</span>
                          <span>
                            {dest.webhookMethod || 'POST'} ({dest.webhookFormat || 'openshield_json'})
                          </span>
                        </>
                      )}
                      <span>·</span>
                      <span>
                        {t('notifications.severityLabel')} {severityLabel(dest.minSeverity)}
                      </span>
                      <span>·</span>
                      <span>
                        {t('notifications.triggersLabel')}{' '}
                        {dest.triggers.map((tr) => triggerLabel(tr)).join(', ')}
                      </span>
                    </div>

                    {dest.lastDispatchMessage && (
                      <div className="text-[11px] flex items-center gap-1.5 pt-0.5">
                        {dest.lastDispatchStatus === 'sent' ? (
                          <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400 shrink-0" />
                        ) : (
                          <AlertCircle className="w-3 h-3 text-amber-600 dark:text-amber-400 shrink-0" />
                        )}
                        <span
                          className={
                            dest.lastDispatchStatus === 'sent'
                              ? 'text-emerald-700 dark:text-emerald-300'
                              : 'text-amber-700 dark:text-amber-300'
                          }
                        >
                          {dest.lastDispatchMessage}
                        </span>
                        <span className="text-slate-500 font-mono tabular-nums">
                          ({formatTime(dest.lastDispatchedAt, locale)})
                        </span>
                      </div>
                    )}
                  </div>

                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() =>
                        void onUpdateNotification(dest.id, { enabled: !dest.enabled })
                      }
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      {dest.enabled ? (
                        <>
                          <Pause className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
                          <span>{t('notifications.pause')}</span>
                        </>
                      ) : (
                        <>
                          <Play className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                          <span>{t('notifications.activate')}</span>
                        </>
                      )}
                    </button>

                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => void onTestNotification(dest.id)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-emerald-200 bg-emerald-50 text-emerald-800 hover:bg-emerald-100 dark:border-emerald-700/60 dark:bg-emerald-950/40 dark:text-emerald-200 dark:hover:bg-emerald-900/40 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>{t('notifications.testDispatch')}</span>
                    </button>

                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => startEdit(dest)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      {isEditing ? <X className="w-3.5 h-3.5" /> : <Edit3 className="w-3.5 h-3.5" />}
                      <span>{isEditing ? t('common.close') : t('common.edit')}</span>
                    </button>

                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => void onRemoveNotification(dest.id, dest.name)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-red-200 text-red-700 hover:bg-red-50 dark:border-red-900/60 dark:text-red-300 dark:hover:bg-red-950/40 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>{t('common.remove')}</span>
                    </button>
                  </div>
                </div>

                {/* Inline Edit Panel */}
                {isEditing && editDraft && (
                  <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950/80 p-4 space-y-3 text-xs">
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
                      <label className="space-y-1">
                        <span className="text-slate-700 dark:text-slate-300 font-medium">
                          {t('notifications.editName')}
                        </span>
                        <input
                          type="text"
                          value={editDraft.name}
                          onChange={(e) =>
                            setEditDraft({ ...editDraft, name: e.target.value })
                          }
                          className="w-full px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-emerald-500"
                        />
                      </label>

                      <label className="space-y-1">
                        <span className="text-slate-700 dark:text-slate-300 font-medium">
                          {dest.type === 'email'
                            ? t('notifications.emailRecipient')
                            : dest.type === 'telegram'
                              ? t('notifications.telegramChatId')
                              : t('notifications.webhookUrl')}
                        </span>
                        <input
                          type="text"
                          value={editDraft.target}
                          onChange={(e) =>
                            setEditDraft({ ...editDraft, target: e.target.value })
                          }
                          className="w-full px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                        />
                      </label>

                      <label className="space-y-1">
                        <span className="text-slate-700 dark:text-slate-300 font-medium">
                          {t('notifications.minSeverity')}
                        </span>
                        <select
                          value={editDraft.minSeverity}
                          onChange={(e) =>
                            setEditDraft({
                              ...editDraft,
                              minSeverity: e.target.value as NotificationSeverityThreshold,
                            })
                          }
                          className="w-full px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-emerald-500"
                        >
                          <option value="critical">{t('notifications.sevCritical')}</option>
                          <option value="high">{t('notifications.sevHigh')}</option>
                          <option value="medium">{t('notifications.sevMedium')}</option>
                        </select>
                      </label>

                      <label className="space-y-1">
                        <span className="text-slate-700 dark:text-slate-300 font-medium">
                          {dest.type === 'telegram'
                            ? t('notifications.replaceBotToken')
                            : dest.type === 'email'
                              ? t('notifications.replaceSmtpPass')
                              : t('notifications.replaceBearerToken')}
                        </span>
                        <input
                          type="password"
                          autoComplete="new-password"
                          placeholder={
                            dest.hasSecret
                              ? t('notifications.keepCurrentSecretPh')
                              : t('notifications.optionalPh')
                          }
                          value={editDraft.secret}
                          onChange={(e) =>
                            setEditDraft({ ...editDraft, secret: e.target.value })
                          }
                          className="w-full px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                        />
                      </label>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-200 dark:border-slate-800">
                      <div className="flex flex-wrap items-center gap-3">
                        {TRIGGER_IDS.map((triggerId) => (
                          <label
                            key={triggerId}
                            className="inline-flex items-center gap-1.5 text-slate-700 dark:text-slate-300 cursor-pointer"
                          >
                            <input
                              type="checkbox"
                              checked={editDraft.triggers.includes(triggerId)}
                              onChange={() =>
                                toggleTrigger(
                                  editDraft.triggers,
                                  (next) => setEditDraft({ ...editDraft, triggers: next }),
                                  triggerId,
                                )
                              }
                              className="rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0B1120] text-emerald-600 focus:ring-emerald-500"
                            />
                            <span>{triggerLabel(triggerId)}</span>
                          </label>
                        ))}
                      </div>

                      <div className="flex items-center gap-2">
                        {dest.hasSecret && (
                          <button
                            type="button"
                            onClick={() =>
                              void onUpdateNotification(dest.id, { clearSecret: true })
                            }
                            className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer whitespace-nowrap"
                          >
                            {t('notifications.clearSecret')}
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => void saveEdit(dest)}
                          className="px-3.5 py-1.5 rounded-lg bg-emerald-600 text-white font-medium hover:bg-emerald-500 cursor-pointer whitespace-nowrap"
                        >
                          {t('common.saveChanges')}
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
          </div>
          <PaginationControls
            page={destPagination.page}
            pageSize={destPagination.pageSize}
            totalItems={destPagination.totalItems}
            totalPages={destPagination.totalPages}
            onPageChange={destPagination.setPage}
            onPageSizeChange={destPagination.setPageSize}
            compact
          />
        </div>
      )}

      {/* Recent External Alert Dispatches */}
      {history.length > 0 && (
        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#0B1120]/50 overflow-hidden">
          <div className="px-3.5 pt-3.5 pb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-400">
            {t('notifications.recentDispatchesTitle', { count: history.length })}
          </div>
          <div className="px-3.5 divide-y divide-slate-200 dark:divide-slate-800/70 text-xs max-h-[260px] overflow-y-auto">
            {historyPagination.pagedItems.map((rec) => (
              <div
                key={rec.id}
                className="py-2 flex flex-wrap items-center justify-between gap-2"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <ChannelIcon type={rec.channelType} />
                  <span className="font-medium text-slate-900 dark:text-slate-200 truncate">{rec.title}</span>
                  <span className="text-slate-400 dark:text-slate-500">→</span>
                  <span className="text-slate-600 dark:text-slate-400 truncate">{rec.destinationName}</span>
                </div>
                <div className="flex items-center gap-3 text-[11px] shrink-0">
                  <span
                    className={
                      rec.status === 'sent'
                        ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                        : 'text-amber-700 dark:text-amber-300 font-medium'
                    }
                  >
                    {rec.status === 'sent'
                      ? t('notifications.dispatchedSent')
                      : t('notifications.dispatchedFailed')}
                  </span>
                  <span className="font-mono tabular-nums text-slate-500">
                    {formatTime(rec.dispatchedAt, locale)}
                  </span>
                </div>
              </div>
            ))}
          </div>
          <PaginationControls
            page={historyPagination.page}
            pageSize={historyPagination.pageSize}
            totalItems={historyPagination.totalItems}
            totalPages={historyPagination.totalPages}
            onPageChange={historyPagination.setPage}
            onPageSizeChange={historyPagination.setPageSize}
            compact
          />
        </div>
      )}
    </section>
  );
}
