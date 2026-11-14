import type {
  AiSensitivityConfig,
  AuditEntry,
  AutonomyLevel,
  DnsInsight,
  EnvSecretStatus,
  Incident,
  IntegrationAdapter,
  NetworkDevice,
  NotificationChannelType,
  NotificationSeverityThreshold,
  NotificationTriggerEvent,
  OpenShieldEventV1,
  OperatingProfile,
  PeriodicSyncConfig,
  ServiceProviderMode,
  SimulatedRole,
  SyncAdapterResult,
  WorkspaceState,
} from '../types/openshield';

async function requestJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers ?? {}),
    },
  });

  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) {
    throw new Error(data.error || `Erro HTTP ${response.status} ao comunicar com o BFF.`);
  }
  return data;
}

export const api = {
  getState: () => requestJson<WorkspaceState>('/api/v1/state'),

  getEnvStatus: () => requestJson<{ variables: EnvSecretStatus[] }>('/api/v1/system/env-status'),

  updateContext: (patch: {
    profile?: OperatingProfile;
    simulatedRole?: SimulatedRole;
    globalAutonomy?: AutonomyLevel;
    cloudAiOptIn?: boolean;
    activeSiteId?: string;
    aiSensitivity?: AiSensitivityConfig;
    periodicSync?: PeriodicSyncConfig;
  }) =>
    requestJson<WorkspaceState>('/api/v1/context', {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),

  toggleNodeOutage: (nodeAvailable: boolean) =>
    requestJson<WorkspaceState>('/api/v1/simulator/node-outage', {
      method: 'POST',
      body: JSON.stringify({ nodeAvailable }),
    }),

  ingestLanEvents: (events: Partial<OpenShieldEventV1>[]) =>
    requestJson<{
      count: number;
      statuses: { eventId: string; status: string; correlatedIncidentId: string | null }[];
      state: WorkspaceState;
    }>('/api/v1/ingest/events', {
      method: 'POST',
      body: JSON.stringify({ events }),
    }),

  ingestEvent: (payload: {
    sourceIntegrationId: string;
    eventType: OpenShieldEventV1['eventType'];
    severity: OpenShieldEventV1['severity'];
    summary: string;
    deviceId?: string;
    payload?: Record<string, unknown>;
    simulateDuplicateId?: string;
  }) =>
    requestJson<{
      status: string;
      event: OpenShieldEventV1;
      correlatedIncidentId: string | null;
      state: WorkspaceState;
    }>('/api/v1/simulator/ingest-event', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  runHandshake: (integrationId: string) =>
    requestJson<WorkspaceState>(`/api/v1/integrations/${integrationId}/handshake`, {
      method: 'POST',
    }),

  syncIntegration: (integrationId: string) =>
    requestJson<{ result: SyncAdapterResult; state: WorkspaceState }>(
      `/api/v1/integrations/${integrationId}/sync`,
      {
        method: 'POST',
      },
    ),

  syncAllIntegrations: () =>
    requestJson<{
      results: SyncAdapterResult[];
      errors: { adapterId: string; name: string; error: string }[];
      state: WorkspaceState;
    }>('/api/v1/integrations/sync-all', {
      method: 'POST',
    }),

  switchIntegrationMode: (
    integrationId: string,
    mode: ServiceProviderMode,
    liveEndpointUrl?: string,
  ) =>
    requestJson<{ state: WorkspaceState; diagnostic: string }>(
      `/api/v1/integrations/${integrationId}/mode`,
      {
        method: 'PATCH',
        body: JSON.stringify({ mode, liveEndpointUrl }),
      },
    ),

  registerManualIntegration: (payload: {
    id: string;
    name: string;
    domain: IntegrationAdapter['domain'];
    kind: string;
    liveEndpointUrl: string;
    siteId?: string;
    mode?: ServiceProviderMode;
    modelName?: string;
    boardInfo?: IntegrationAdapter['boardInfo'];
    username?: string;
    secret?: string;
    configMetadata?: Record<string, string>;
  }) =>
    requestJson<WorkspaceState>('/api/v1/integrations', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateIntegrationConfig: (
    integrationId: string,
    payload: {
      name?: string;
      liveEndpointUrl?: string;
      siteId?: string;
      mode?: ServiceProviderMode;
      modelName?: string;
      boardInfo?: IntegrationAdapter['boardInfo'];
      username?: string;
      secret?: string;
      clearSecret?: boolean;
    },
  ) =>
    requestJson<WorkspaceState>(`/api/v1/integrations/${integrationId}/config`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  removeIntegration: (integrationId: string) =>
    requestJson<WorkspaceState>(`/api/v1/integrations/${integrationId}`, {
      method: 'DELETE',
    }),

  addDevice: (payload: {
    id?: string;
    hostname: string;
    ip: string;
    mac?: string;
    vendor?: string;
    interfaceName?: string;
    segment: NetworkDevice['segment'];
    siteId?: string;
    deviceType: NetworkDevice['deviceType'];
  }) =>
    requestJson<WorkspaceState>('/api/v1/devices', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  importOpenWrtMap: (payload: {
    rawOutput?: string;
    netDump?: unknown;
    hostHints?: unknown;
    ipNeighText?: string;
    siteId?: string;
  }) =>
    requestJson<{
      discoveredCount: number;
      devices: { hostname: string; ip: string; mac?: string; interfaceName?: string }[];
      state: WorkspaceState;
    }>('/api/v1/devices/import-openwrt-map', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateDevice: (
    deviceId: string,
    patch: Partial<
      Pick<
        NetworkDevice,
        'hostname' | 'ip' | 'mac' | 'vendor' | 'interfaceName' | 'segment' | 'siteId' | 'deviceType' | 'status'
      >
    >,
  ) =>
    requestJson<WorkspaceState>(`/api/v1/devices/${deviceId}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),

  removeDevice: (deviceId: string) =>
    requestJson<WorkspaceState>(`/api/v1/devices/${deviceId}`, {
      method: 'DELETE',
    }),

  loadDemoScenario: () =>
    requestJson<WorkspaceState>('/api/v1/workspace/load-demo', {
      method: 'POST',
    }),

  resetWorkspace: () =>
    requestJson<WorkspaceState>('/api/v1/workspace/reset', {
      method: 'POST',
    }),

  exportBackup: () => requestJson<Record<string, unknown>>('/api/v1/workspace/backup'),

  restoreBackup: (payload: Record<string, unknown>) =>
    requestJson<WorkspaceState>('/api/v1/workspace/restore', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  addSite: (payload: { name: string; profile: OperatingProfile }) =>
    requestJson<WorkspaceState>('/api/v1/sites', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  removeSite: (siteId: string) =>
    requestJson<WorkspaceState>(`/api/v1/sites/${siteId}`, {
      method: 'DELETE',
    }),

  addDnsInsight: (payload: {
    domain: string;
    category?: DnsInsight['category'];
    classification?: DnsInsight['classification'];
    deviceHostname?: string;
    listStatus?: DnsInsight['listStatus'];
  }) =>
    requestJson<WorkspaceState>('/api/v1/dns', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateDnsList: (dnsId: string, listStatus: DnsInsight['listStatus']) =>
    requestJson<WorkspaceState>(`/api/v1/dns/${dnsId}/list-status`, {
      method: 'POST',
      body: JSON.stringify({ listStatus }),
    }),

  investigateIncident: (incidentId: string, mode: 'local' | 'cloud_gemini') =>
    requestJson<WorkspaceState>(`/api/v1/incidents/${incidentId}/investigate`, {
      method: 'POST',
      body: JSON.stringify({ mode }),
    }),

  updateIncidentStatus: (incidentId: string, status: Incident['status']) =>
    requestJson<WorkspaceState>(`/api/v1/incidents/${incidentId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),

  togglePolicy: (policyId: string, enabled: boolean) =>
    requestJson<WorkspaceState>(`/api/v1/policies/${policyId}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    }),

  proposeAction: (incidentId: string, policyId: string, ttlSeconds?: number) =>
    requestJson<{ execution: unknown; state: WorkspaceState }>('/api/v1/actions/propose', {
      method: 'POST',
      body: JSON.stringify({ incidentId, policyId, ttlSeconds }),
    }),

  approveExecution: (executionId: string) =>
    requestJson<WorkspaceState>(`/api/v1/actions/${executionId}/approve`, {
      method: 'POST',
    }),

  rollbackExecution: (executionId: string) =>
    requestJson<WorkspaceState>(`/api/v1/actions/${executionId}/rollback`, {
      method: 'POST',
    }),

  triggerKillSwitch: (active: boolean) =>
    requestJson<WorkspaceState>('/api/v1/kill-switch', {
      method: 'POST',
      body: JSON.stringify({ active }),
    }),

  addNotificationDestination: (payload: {
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
  }) =>
    requestJson<WorkspaceState>('/api/v1/notifications', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateNotificationDestination: (
    id: string,
    payload: {
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
    },
  ) =>
    requestJson<WorkspaceState>(`/api/v1/notifications/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  removeNotificationDestination: (id: string) =>
    requestJson<WorkspaceState>(`/api/v1/notifications/${id}`, {
      method: 'DELETE',
    }),

  testNotificationDestination: (id: string) =>
    requestJson<{ status: 'sent' | 'failed'; message: string; state: WorkspaceState }>(
      `/api/v1/notifications/${id}/test`,
      {
        method: 'POST',
      },
    ),

  getAuditLog: (
    filtersOrLimit:
      | number
      | {
          limit?: number;
          eventType?: string;
          category?: string;
          from?: string;
          to?: string;
          outcome?: string;
          search?: string;
        } = 200,
  ) => {
    const params = new URLSearchParams();
    if (typeof filtersOrLimit === 'number') {
      params.set('limit', String(filtersOrLimit));
    } else {
      if (filtersOrLimit.limit !== undefined) params.set('limit', String(filtersOrLimit.limit));
      if (filtersOrLimit.eventType && filtersOrLimit.eventType !== 'all') {
        params.set('eventType', filtersOrLimit.eventType);
      }
      if (filtersOrLimit.category && filtersOrLimit.category !== 'all') {
        params.set('category', filtersOrLimit.category);
      }
      if (filtersOrLimit.from) params.set('from', filtersOrLimit.from);
      if (filtersOrLimit.to) params.set('to', filtersOrLimit.to);
      if (filtersOrLimit.outcome && filtersOrLimit.outcome !== 'all') {
        params.set('outcome', filtersOrLimit.outcome);
      }
      if (filtersOrLimit.search?.trim()) params.set('search', filtersOrLimit.search.trim());
    }
    return requestJson<{
      entries: AuditEntry[];
      totalMatched?: number;
      eventTypes?: string[];
    }>(`/api/v1/audit?${params.toString()}`);
  },

  getMetricsText: async () => {
    const res = await fetch('/metrics');
    return res.text();
  },
};
