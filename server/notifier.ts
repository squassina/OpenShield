import nodemailer from 'nodemailer';
import type {
  EventSeverity,
  NotificationDestination,
  NotificationTriggerEvent,
} from '../src/types/openshield.ts';

export interface AlertDispatchPayload {
  trigger: NotificationTriggerEvent;
  severity: EventSeverity;
  title: string;
  summary: string;
  source?: string;
  deviceHostname?: string;
  occurredAt: string;
  siteId?: string;
}

export interface DispatchOutcome {
  status: 'sent' | 'failed';
  message: string;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function severityLabel(severity: EventSeverity): string {
  switch (severity) {
    case 'critical':
      return 'CRÍTICO';
    case 'high':
      return 'ALTO';
    case 'medium':
      return 'MÉDIO';
    case 'low':
      return 'BAIXO';
    default:
      return 'INFO';
  }
}

export async function deliverNotification(
  destination: NotificationDestination,
  payload: AlertDispatchPayload,
  credentials?: { username?: string; secret?: string },
): Promise<DispatchOutcome> {
  if (destination.type === 'webhook') {
    return deliverWebhook(destination, payload, credentials?.secret);
  }
  if (destination.type === 'telegram') {
    return deliverTelegram(destination, payload, credentials?.secret);
  }
  return deliverEmail(destination, payload, credentials);
}

async function deliverWebhook(
  destination: NotificationDestination,
  payload: AlertDispatchPayload,
  secret?: string,
): Promise<DispatchOutcome> {
  const url = destination.target.trim();
  if (!/^https?:\/\//i.test(url)) {
    return { status: 'failed', message: 'URL do Webhook inválida (esperado http:// ou https://).' };
  }

  const format = destination.webhookFormat ?? 'openshield_json';
  const sev = severityLabel(payload.severity);

  let bodyObj: Record<string, unknown>;
  if (format === 'slack') {
    bodyObj = {
      text: `*[OpenShield · ${sev}]* ${payload.title}\n${payload.summary}\n• Gatilho: \`${payload.trigger}\`\n• Horário: ${payload.occurredAt}`,
    };
  } else if (format === 'discord') {
    bodyObj = {
      content: `**[OpenShield · ${sev}]** ${payload.title}`,
      embeds: [
        {
          title: payload.title,
          description: payload.summary,
          color: payload.severity === 'critical' ? 15158332 : payload.severity === 'high' ? 15105570 : 3447003,
          fields: [
            { name: 'Severidade', value: sev, inline: true },
            { name: 'Gatilho', value: payload.trigger, inline: true },
            ...(payload.deviceHostname
              ? [{ name: 'Dispositivo', value: payload.deviceHostname, inline: true }]
              : []),
          ],
          timestamp: payload.occurredAt,
        },
      ],
    };
  } else {
    bodyObj = {
      schemaVersion: 'openshield.alert.v1',
      destinationId: destination.id,
      destinationName: destination.name,
      trigger: payload.trigger,
      severity: payload.severity,
      title: payload.title,
      summary: payload.summary,
      source: payload.source ?? 'openshield-core',
      deviceHostname: payload.deviceHostname ?? null,
      siteId: payload.siteId ?? null,
      occurredAt: payload.occurredAt,
    };
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'OpenShield-Notifier/1.0',
  };
  if (secret) {
    headers.Authorization = `Bearer ${secret}`;
    headers['X-OpenShield-Token'] = secret;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(url, {
      method: destination.webhookMethod === 'PUT' ? 'PUT' : 'POST',
      headers,
      body: JSON.stringify(bodyObj),
      signal: controller.signal,
    });
    if (!res.ok) {
      return {
        status: 'failed',
        message: `Webhook respondeu HTTP ${res.status} (${res.statusText || 'erro'}).`,
      };
    }
    return {
      status: 'sent',
      message: `Webhook entregue com sucesso (HTTP ${res.status} · formato ${format}).`,
    };
  } catch (err) {
    const reason =
      err instanceof Error && err.name === 'AbortError'
        ? 'Timeout de 6s atingido ao conectar ao Webhook.'
        : err instanceof Error
          ? err.message
          : 'Falha de rede ao enviar Webhook.';
    return { status: 'failed', message: reason };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function deliverTelegram(
  destination: NotificationDestination,
  payload: AlertDispatchPayload,
  botToken?: string,
): Promise<DispatchOutcome> {
  const token = botToken?.trim();
  const chatId = destination.target.trim();
  if (!token) {
    return {
      status: 'failed',
      message: 'Bot Token do Telegram não configurado no cofre do servidor.',
    };
  }
  if (!chatId) {
    return {
      status: 'failed',
      message: 'Chat ID do Telegram não informado.',
    };
  }

  const sev = severityLabel(payload.severity);
  const text = [
    `<b>[OpenShield · ${escapeHtml(sev)}]</b> ${escapeHtml(payload.title)}`,
    '',
    escapeHtml(payload.summary),
    '',
    `<b>Gatilho:</b> <code>${escapeHtml(payload.trigger)}</code>`,
    payload.deviceHostname
      ? `<b>Dispositivo:</b> <code>${escapeHtml(payload.deviceHostname)}</code>`
      : null,
    `<b>Horário:</b> <code>${escapeHtml(payload.occurredAt)}</code>`,
  ]
    .filter(Boolean)
    .join('\n');

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(`https://api.telegram.org/bot${encodeURIComponent(token)}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      }),
      signal: controller.signal,
    });
    const json = (await res.json().catch(() => ({}))) as { ok?: boolean; description?: string };
    if (!res.ok || json.ok === false) {
      return {
        status: 'failed',
        message: `Telegram API erro (HTTP ${res.status}): ${json.description || 'verifique Bot Token e Chat ID.'}`,
      };
    }
    return {
      status: 'sent',
      message: `Mensagem Telegram entregue para chat "${chatId}".`,
    };
  } catch (err) {
    const reason =
      err instanceof Error && err.name === 'AbortError'
        ? 'Timeout de 6s ao conectar à API do Telegram.'
        : err instanceof Error
          ? err.message
          : 'Falha de rede ao enviar alerta Telegram.';
    return { status: 'failed', message: reason };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function deliverEmail(
  destination: NotificationDestination,
  payload: AlertDispatchPayload,
  credentials?: { username?: string; secret?: string },
): Promise<DispatchOutcome> {
  const to = destination.target.trim();
  const host = destination.smtpHost?.trim();
  const port = Number(destination.smtpPort) || 587;
  const from = destination.emailFrom?.trim() || credentials?.username?.trim() || 'openshield@localhost';

  if (!to || !to.includes('@')) {
    return { status: 'failed', message: 'Endereço de e-mail destinatário inválido.' };
  }
  if (!host) {
    return { status: 'failed', message: 'Servidor SMTP (host) não configurado para envio de e-mail.' };
  }

  try {
    const transporter = nodemailer.createTransport({
      host,
      port,
      secure: Boolean(destination.smtpSecure ?? port === 465),
      auth:
        credentials?.username || credentials?.secret
          ? {
              user: credentials.username || from,
              pass: credentials.secret || '',
            }
          : undefined,
      connectionTimeout: 6000,
      greetingTimeout: 6000,
      socketTimeout: 6000,
    });

    const sev = severityLabel(payload.severity);
    const info = await transporter.sendMail({
      from,
      to,
      subject: `[OpenShield · ${sev}] ${payload.title}`,
      text: [
        `OpenShield - Alerta de Segurança (${sev})`,
        `Título: ${payload.title}`,
        `Resumo: ${payload.summary}`,
        `Gatilho: ${payload.trigger}`,
        payload.deviceHostname ? `Dispositivo: ${payload.deviceHostname}` : '',
        payload.source ? `Origem: ${payload.source}` : '',
        `Horário (UTC): ${payload.occurredAt}`,
      ]
        .filter(Boolean)
        .join('\n'),
    });

    return {
      status: 'sent',
      message: `E-mail enviado para ${to} via ${host}:${port} (ID ${info.messageId || 'ok'}).`,
    };
  } catch (err) {
    return {
      status: 'failed',
      message: `Falha SMTP (${host}:${port}): ${err instanceof Error ? err.message : 'erro desconhecido.'}`,
    };
  }
}
