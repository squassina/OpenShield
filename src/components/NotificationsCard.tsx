import { useState, type FormEvent } from 'react';
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

const TRIGGER_OPTIONS: { id: NotificationTriggerEvent; label: string }[] = [
  { id: 'critical_incident', label: 'Incidentes Críticos / Altos' },
  { id: 'kill_switch', label: 'Acionamento do Kill Switch' },
  { id: 'endpoint_offline', label: 'Endpoints de Segurança Offline' },
  { id: 'ai_anomaly', label: 'Anomalias Detectadas pela IA' },
];

const SEVERITY_LABELS: Record<NotificationSeverityThreshold, string> = {
  critical: 'Somente Crítico',
  high: 'Alto e Crítico',
  medium: 'Médio, Alto e Crítico',
};

function ChannelIcon({ type }: { type: NotificationChannelType }) {
  if (type === 'email') return <Mail className="w-4 h-4 text-blue-400 shrink-0" />;
  if (type === 'telegram') return <Send className="w-4 h-4 text-sky-400 shrink-0" />;
  return <Webhook className="w-4 h-4 text-emerald-400 shrink-0" />;
}

function channelLabel(type: NotificationChannelType): string {
  if (type === 'email') return 'E-mail (SMTP)';
  if (type === 'telegram') return 'Telegram Bot';
  return 'Webhook HTTP';
}

function formatTime(iso?: string): string {
  if (!iso) return '—';
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return iso;
  return new Intl.DateTimeFormat('pt-BR', {
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
  const destinations = state.notifications ?? [];
  const history = state.notificationHistory ?? [];

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
          ? 'Alerta SOC E-mail'
          : channelType === 'telegram'
            ? 'Plantão Telegram'
            : 'Webhook Segurança'),
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
    <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-5">
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <BellRing className="w-4 h-4 text-blue-400 shrink-0" />
            <span>Notificações e Alertas</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5 max-w-3xl">
            Defina destinos externos (E-mail SMTP, Webhook HTTP/Slack/Discord ou Telegram Bot) para receber
            alertas críticos diretamente do servidor OpenShield, mesmo com a dashboard fechada.
          </p>
        </div>

        <div className="text-xs text-slate-300 tabular-nums shrink-0">
          <span className="font-semibold text-slate-100">{activeCount}</span> ativo(s) de{' '}
          <span className="font-semibold text-slate-100">{destinations.length}</span> destino(s)
        </div>
      </div>

      {/* Add Notification Destination Form */}
      <form
        onSubmit={handleCreateSubmit}
        className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
            <Plus className="w-3.5 h-3.5 text-blue-400" />
            <span>Adicionar Destino de Alerta</span>
          </div>

          <div className="inline-flex flex-wrap items-center gap-1 p-1 rounded-lg bg-[#0B1120] border border-slate-800">
            {(['webhook', 'email', 'telegram'] as NotificationChannelType[]).map((type) => {
              const active = channelType === type;
              return (
                <button
                  key={type}
                  type="button"
                  onClick={() => resetFormFields(type)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    active ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
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
            <span className="text-slate-300 font-medium">Nome do Destino</span>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={
                channelType === 'email'
                  ? 'ex: Plantão SOC E-mail'
                  : channelType === 'telegram'
                    ? 'ex: Bot Segurança Casa'
                    : 'ex: Webhook Discord / SIEM'
              }
              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs focus:outline-none focus:border-blue-500"
            />
          </label>

          {channelType === 'webhook' && (
            <>
              <label className="space-y-1 md:col-span-2">
                <span className="text-slate-300 font-medium">URL do Webhook</span>
                <input
                  type="url"
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://hooks.slack.com/services/... ou https://discord.com/api/webhooks/..."
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>

              <div className="grid grid-cols-2 gap-2">
                <label className="space-y-1">
                  <span className="text-slate-300 font-medium">Formato</span>
                  <select
                    value={webhookFormat}
                    onChange={(e) =>
                      setWebhookFormat(
                        e.target.value as 'openshield_json' | 'slack' | 'discord',
                      )
                    }
                    className="w-full px-2.5 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                  >
                    <option value="openshield_json">JSON OpenShield</option>
                    <option value="slack">Slack</option>
                    <option value="discord">Discord</option>
                  </select>
                </label>

                <label className="space-y-1">
                  <span className="text-slate-300 font-medium">Método</span>
                  <select
                    value={webhookMethod}
                    onChange={(e) => setWebhookMethod(e.target.value as 'POST' | 'PUT')}
                    className="w-full px-2.5 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
                  >
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                  </select>
                </label>
              </div>

              <label className="space-y-1 md:col-span-2">
                <span className="text-slate-300 font-medium">
                  Bearer Token / Secret Header (opcional, write-only)
                </span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder="Enviado em Authorization: Bearer e X-OpenShield-Token"
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>
            </>
          )}

          {channelType === 'email' && (
            <>
              <label className="space-y-1">
                <span className="text-slate-300 font-medium">E-mail Destinatário</span>
                <input
                  type="email"
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="seguranca@suaempresa.com"
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>

              <label className="space-y-1">
                <span className="text-slate-300 font-medium">Servidor SMTP (Host)</span>
                <input
                  type="text"
                  required
                  value={smtpHost}
                  onChange={(e) => setSmtpHost(e.target.value)}
                  placeholder="smtp.gmail.com ou 192.168.1.10"
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>

              <div className="grid grid-cols-2 gap-2">
                <label className="space-y-1">
                  <span className="text-slate-300 font-medium">Porta SMTP</span>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={smtpPort}
                    onChange={(e) => setSmtpPort(e.target.value)}
                    className="w-full px-2.5 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
                  />
                </label>

                <label className="flex items-center gap-2 pt-5 cursor-pointer text-slate-300">
                  <input
                    type="checkbox"
                    checked={smtpSecure}
                    onChange={(e) => setSmtpSecure(e.target.checked)}
                    className="rounded border-slate-700 bg-[#0B1120] text-blue-500"
                  />
                  <span>TLS Direto (465)</span>
                </label>
              </div>

              <label className="space-y-1">
                <span className="text-slate-300 font-medium">Remetente (From)</span>
                <input
                  type="email"
                  value={emailFrom}
                  onChange={(e) => setEmailFrom(e.target.value)}
                  placeholder="openshield@rede.local"
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>

              <label className="space-y-1">
                <span className="text-slate-300 font-medium">Usuário SMTP (opcional)</span>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="usuário ou e-mail SMTP"
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>

              <label className="space-y-1">
                <span className="text-slate-300 font-medium">
                  Senha / App Password (write-only)
                </span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder="Salva no cofre SQLite local"
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>
            </>
          )}

          {channelType === 'telegram' && (
            <>
              <label className="space-y-1">
                <span className="text-slate-300 font-medium">Chat ID / Canal Telegram</span>
                <input
                  type="text"
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="ex: -1001987654321 ou 551199999"
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>

              <label className="space-y-1 md:col-span-2">
                <span className="text-slate-300 font-medium">
                  Bot Token (@BotFather · write-only no cofre)
                </span>
                <input
                  type="password"
                  required
                  autoComplete="new-password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder="ex: 7123456789:AAF..."
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>
            </>
          )}

          <label className="space-y-1">
            <span className="text-slate-300 font-medium">Severidade Mínima</span>
            <select
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value as NotificationSeverityThreshold)}
              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs focus:outline-none focus:border-blue-500"
            >
              <option value="critical">Somente Crítico</option>
              <option value="high">Alto e Crítico</option>
              <option value="medium">Médio, Alto e Crítico</option>
            </select>
          </label>
        </div>

        {/* Trigger Checkboxes + Save Button */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <span className="text-slate-400 font-medium">Gatilhos automáticos:</span>
            {TRIGGER_OPTIONS.map((opt) => (
              <label
                key={opt.id}
                className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={triggers.includes(opt.id)}
                  onChange={() => toggleTrigger(triggers, setTriggers, opt.id)}
                  className="rounded border-slate-700 bg-[#0B1120] text-blue-500"
                />
                <span>{opt.label}</span>
              </label>
            ))}
          </div>

          <button
            type="submit"
            disabled={busyKey === 'notif-add'}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Salvar Destino</span>
          </button>
        </div>
      </form>

      {/* Configured Destinations List */}
      {destinations.length === 0 ? (
        <div className="rounded-lg border border-dashed border-slate-800 bg-[#0B1120]/60 p-6 text-center space-y-1.5">
          <BellRing className="w-6 h-6 text-slate-600 mx-auto" />
          <div className="text-xs font-medium text-slate-300">
            Nenhum destino de notificação externa configurado
          </div>
          <p className="text-[11px] text-slate-500 max-w-lg mx-auto">
            Adicione um e-mail SMTP, Webhook ou Bot Telegram acima para ser avisado imediatamente
            sobre incidentes críticos, falhas múltiplas de endpoints ou acionamento do Kill Switch.
          </p>
        </div>
      ) : (
        <div className="divide-y divide-slate-800 rounded-lg border border-slate-800 bg-[#0B1120]/50 overflow-hidden">
          {destinations.map((dest) => {
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
                      <span className="text-sm font-semibold text-slate-100">{dest.name}</span>
                      <span className="text-slate-500">·</span>
                      <span className="text-slate-300">{channelLabel(dest.type)}</span>
                      <span className="text-slate-500">·</span>
                      {dest.enabled ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Ativo</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-slate-500 font-medium">
                          <Pause className="w-3.5 h-3.5" />
                          <span>Pausado</span>
                        </span>
                      )}
                      {dest.hasSecret && (
                        <>
                          <span className="text-slate-500">·</span>
                          <span className="inline-flex items-center gap-1 text-emerald-400">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            <span>Segredo no cofre</span>
                          </span>
                        </>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-400">
                      <span className="font-mono text-slate-300 truncate max-w-md">
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
                      <span>Severidade: {SEVERITY_LABELS[dest.minSeverity]}</span>
                      <span>·</span>
                      <span>
                        Gatilhos:{' '}
                        {dest.triggers
                          .map((t) => TRIGGER_OPTIONS.find((o) => o.id === t)?.label ?? t)
                          .join(', ')}
                      </span>
                    </div>

                    {dest.lastDispatchMessage && (
                      <div className="text-[11px] flex items-center gap-1.5 pt-0.5">
                        {dest.lastDispatchStatus === 'sent' ? (
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                        ) : (
                          <AlertCircle className="w-3 h-3 text-amber-400 shrink-0" />
                        )}
                        <span
                          className={
                            dest.lastDispatchStatus === 'sent'
                              ? 'text-emerald-300'
                              : 'text-amber-300'
                          }
                        >
                          {dest.lastDispatchMessage}
                        </span>
                        <span className="text-slate-500 font-mono tabular-nums">
                          ({formatTime(dest.lastDispatchedAt)})
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
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      {dest.enabled ? (
                        <>
                          <Pause className="w-3.5 h-3.5 text-amber-400" />
                          <span>Pausar</span>
                        </>
                      ) : (
                        <>
                          <Play className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Ativar</span>
                        </>
                      )}
                    </button>

                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => void onTestNotification(dest.id)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-blue-800/70 bg-blue-950/30 text-blue-200 hover:bg-blue-900/40 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>Testar Envio</span>
                    </button>

                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => startEdit(dest)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      {isEditing ? <X className="w-3.5 h-3.5" /> : <Edit3 className="w-3.5 h-3.5" />}
                      <span>{isEditing ? 'Fechar' : 'Editar'}</span>
                    </button>

                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => void onRemoveNotification(dest.id, dest.name)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-red-900/60 text-red-300 hover:bg-red-950/40 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Remover</span>
                    </button>
                  </div>
                </div>

                {/* Inline Edit Panel */}
                {isEditing && editDraft && (
                  <div className="rounded-lg border border-slate-700 bg-slate-950/80 p-4 space-y-3 text-xs">
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
                      <label className="space-y-1">
                        <span className="text-slate-300 font-medium">Nome</span>
                        <input
                          type="text"
                          value={editDraft.name}
                          onChange={(e) =>
                            setEditDraft({ ...editDraft, name: e.target.value })
                          }
                          className="w-full px-3 py-1.5 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs"
                        />
                      </label>

                      <label className="space-y-1">
                        <span className="text-slate-300 font-medium">
                          {dest.type === 'email'
                            ? 'E-mail Destinatário'
                            : dest.type === 'telegram'
                              ? 'Chat ID Telegram'
                              : 'URL do Webhook'}
                        </span>
                        <input
                          type="text"
                          value={editDraft.target}
                          onChange={(e) =>
                            setEditDraft({ ...editDraft, target: e.target.value })
                          }
                          className="w-full px-3 py-1.5 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs"
                        />
                      </label>

                      <label className="space-y-1">
                        <span className="text-slate-300 font-medium">Severidade Mínima</span>
                        <select
                          value={editDraft.minSeverity}
                          onChange={(e) =>
                            setEditDraft({
                              ...editDraft,
                              minSeverity: e.target.value as NotificationSeverityThreshold,
                            })
                          }
                          className="w-full px-3 py-1.5 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs"
                        >
                          <option value="critical">Somente Crítico</option>
                          <option value="high">Alto e Crítico</option>
                          <option value="medium">Médio, Alto e Crítico</option>
                        </select>
                      </label>

                      <label className="space-y-1">
                        <span className="text-slate-300 font-medium">
                          {dest.type === 'telegram'
                            ? 'Substituir Bot Token'
                            : dest.type === 'email'
                              ? 'Substituir Senha SMTP'
                              : 'Substituir Bearer Token'}
                        </span>
                        <input
                          type="password"
                          autoComplete="new-password"
                          placeholder={dest.hasSecret ? '•••••••• (manter atual)' : 'Opcional'}
                          value={editDraft.secret}
                          onChange={(e) =>
                            setEditDraft({ ...editDraft, secret: e.target.value })
                          }
                          className="w-full px-3 py-1.5 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 font-mono text-xs"
                        />
                      </label>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800">
                      <div className="flex flex-wrap items-center gap-3">
                        {TRIGGER_OPTIONS.map((opt) => (
                          <label
                            key={opt.id}
                            className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer"
                          >
                            <input
                              type="checkbox"
                              checked={editDraft.triggers.includes(opt.id)}
                              onChange={() =>
                                toggleTrigger(
                                  editDraft.triggers,
                                  (next) => setEditDraft({ ...editDraft, triggers: next }),
                                  opt.id,
                                )
                              }
                              className="rounded border-slate-700 bg-[#0B1120] text-blue-500"
                            />
                            <span>{opt.label}</span>
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
                            className="px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 cursor-pointer whitespace-nowrap"
                          >
                            Limpar Segredo
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => void saveEdit(dest)}
                          className="px-3.5 py-1.5 rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-500 cursor-pointer whitespace-nowrap"
                        >
                          Salvar Alterações
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Recent External Alert Dispatches */}
      {history.length > 0 && (
        <div className="rounded-lg border border-slate-800 bg-[#0B1120]/50 p-3.5 space-y-2">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Últimos Disparos Externos ({history.length})
          </div>
          <div className="divide-y divide-slate-800/70 text-xs">
            {history.slice(0, 5).map((rec) => (
              <div
                key={rec.id}
                className="py-2 flex flex-wrap items-center justify-between gap-2"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <ChannelIcon type={rec.channelType} />
                  <span className="font-medium text-slate-200 truncate">{rec.title}</span>
                  <span className="text-slate-500">→</span>
                  <span className="text-slate-400 truncate">{rec.destinationName}</span>
                </div>
                <div className="flex items-center gap-3 text-[11px] shrink-0">
                  <span
                    className={
                      rec.status === 'sent'
                        ? 'text-emerald-400 font-medium'
                        : 'text-amber-300 font-medium'
                    }
                  >
                    {rec.status === 'sent' ? 'Enviado' : 'Falha no envio'}
                  </span>
                  <span className="font-mono tabular-nums text-slate-500">
                    {formatTime(rec.dispatchedAt)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
