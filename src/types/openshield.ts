export type OperatingProfile = 'residential' | 'business';

export type SimulatedRole = 'admin' | 'operator' | 'auditor';

export type AutonomyLevel = 'L0' | 'L1' | 'L2' | 'L3';

export type AdapterCapability =
  | 'discover'
  | 'health_check'
  | 'read_events'
  | 'read_configuration'
  | 'write_configuration'
  | 'execute_action'
  | 'verify_action';

export type ServiceProviderMode = 'mock' | 'live';

export type IntegrationDomain =
  | 'gateway'
  | 'ids'
  | 'analytics'
  | 'dns'
  | 'threat_intel'
  | 'ai_runtime';

export type IntegrationStatus = 'connected' | 'stale' | 'unavailable';

export interface IntegrationAdapter {
  id: string;
  name: string;
  domain: IntegrationDomain;
  kind: string;
  description: string;
  protocolVersion: string;
  mode: ServiceProviderMode;
  liveEndpointUrl: string;
  timeoutMs: number;
  status: IntegrationStatus;
  lastHeartbeatAt: string;
  lastSyncedAt?: string;
  lastLatencyMs?: number;
  capabilities: AdapterCapability[];
  outboxQueueCount: number;
  outboxCapacity: number;
  siteId: string;
  hasCredential?: boolean;
  usernameHint?: string;
  modelName?: string;
  boardInfo?: {
    model: string;
    firmware: string;
    interfaces: string[];
  };
  lastLiveCheckMessage?: string;
}

export type EventSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface OpenShieldEventV1 {
  eventId: string;
  schemaVersion: 'openshield.event.v1';
  occurredAt: string;
  sourceIntegrationId: string;
  eventType:
    | 'gateway.discovery'
    | 'gateway.health'
    | 'ids.alert'
    | 'zeek.connection'
    | 'dns.query'
    | 'threat.ioc';
  severity: EventSeverity;
  deviceId?: string;
  dataSource?: 'mock' | 'live';
  summary: string;
  payload: Record<string, unknown>;
}

export interface NetworkDevice {
  id: string;
  hostname: string;
  ip: string;
  mac: string;
  vendor: string;
  interfaceName: string;
  segment: 'LAN Confiável' | 'IoT / Convidados' | 'Escritório / VPN';
  siteId: string;
  riskScore: number;
  status: 'nominal' | 'attention' | 'isolated';
  lastSeenAt: string;
  dnsQueries24h: number;
  blockedQueries24h: number;
  deviceType: 'router' | 'workstation' | 'mobile' | 'iot' | 'server';
}

export interface DnsInsight {
  id: string;
  domain: string;
  category: 'Telemetria & Rastreador' | 'Suspeito / DGA' | 'Nuvem Corporativa' | 'Serviço Local';
  classification: 'tracker' | 'suspicious' | 'benign';
  deviceId: string;
  deviceHostname: string;
  queriesCount: number;
  blockedCount: number;
  listStatus: 'monitored' | 'blocked' | 'allowed';
  lastQueriedAt: string;
}

export interface IncidentTimelineStep {
  timestamp: string;
  sourceIntegrationId: string;
  eventId: string;
  description: string;
  severity: EventSeverity;
}

export interface AiInvestigation {
  provider: 'local-ollama-mock' | 'local-ollama-live' | 'gemini-sanitized';
  modelVersion: string;
  promptTemplateVersion: string;
  generatedAt: string;
  confidence: 'alta' | 'média' | 'baixa';
  observedFacts: string[];
  inferredHypotheses: string[];
  recommendedSteps: string[];
  sanitizedPayloadPreview?: string;
  promptInjectionGuardNote: string;
}

export interface Incident {
  id: string;
  title: string;
  summary: string;
  severity: EventSeverity;
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive';
  riskScore: number;
  riskFactors: string[];
  deviceId: string;
  deviceHostname: string;
  siteId: string;
  dataSource?: 'mock' | 'live';
  eventIds: string[];
  timeline: IncidentTimelineStep[];
  recommendedPolicyId: string;
  recommendedAction: string;
  investigation: AiInvestigation;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  eventPattern: string;
  maxAutonomyLevel: AutonomyLevel;
  maxScope: string;
  defaultTtlSeconds: number;
  rollbackSupported: boolean;
  enabled: boolean;
}

export interface ActionExecution {
  id: string;
  incidentId: string;
  policyId: string;
  targetLabel: string;
  targetDomain?: string;
  actionType: 'dns_block_domain' | 'nftables_temp_drop' | 'isolate_iot_segment' | 'dry_run_only';
  autonomyLevel: AutonomyLevel;
  status:
    | 'dry_run'
    | 'awaiting_approval'
    | 'active'
    | 'verified'
    | 'expired'
    | 'rolled_back'
    | 'aborted_kill_switch';
  ttlSeconds: number;
  expiresAt: string | null;
  executedBy: string;
  verificationDetail: string;
  rollbackAvailable: boolean;
  createdAt: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  eventType:
    | 'integration.registered'
    | 'integration.removed'
    | 'integration.synced'
    | 'credentials.updated'
    | 'device.added'
    | 'device.updated'
    | 'device.removed'
    | 'dns.added'
    | 'dns.list_updated'
    | 'site.added'
    | 'site.removed'
    | 'workspace.demo_loaded'
    | 'workspace.reset'
    | 'workspace.restored'
    | 'gateway.connected'
    | 'event.ingested'
    | 'authorization.denied'
    | 'ai.investigated'
    | 'action.proposed'
    | 'action.approved'
    | 'action.executed'
    | 'action.verified'
    | 'action.expired'
    | 'action.rolled_back'
    | 'kill_switch.triggered'
    | 'kill_switch.reset'
    | 'notification.added'
    | 'notification.updated'
    | 'notification.removed'
    | 'notification.dispatched'
    | 'notification.tested'
    | 'context.updated';
  actor: string;
  role: string;
  targetId: string;
  outcome: 'success' | 'denied' | 'simulated';
  detail: string;
  profile: OperatingProfile;
}

export interface OperationalMetrics {
  httpRequestsTotal: number;
  eventsIngestedTotal: number;
  gatewayConnectionsTotal: number;
  gatewayHeartbeatsTotal: number;
  authorizationDeniedTotal: number;
  outboxPendingTotal: number;
}

export type SensitivityPreset = 'conservador' | 'balanceado' | 'agressivo' | 'customizado';

export interface AiSensitivityConfig {
  preset: SensitivityPreset;
  minRiskScoreAlert: number;
  dnsBurstThresholdPerMin: number;
  latencySpikeFactor: number;
  flagLowSeverityEvents: boolean;
}

export interface OperatingContext {
  profile: OperatingProfile;
  simulatedRole: SimulatedRole;
  globalAutonomy: AutonomyLevel;
  killSwitchActive: boolean;
  nodeAvailable: boolean;
  gatewayForwardingActive: boolean;
  cloudAiOptIn: boolean;
  activeSiteId: string;
  sites: { id: string; name: string; profile: OperatingProfile }[];
  aiSensitivity?: AiSensitivityConfig;
}

export interface EnvSecretStatus {
  key: string;
  label: string;
  scope: string;
  configured: boolean;
}

export interface SyncAdapterResult {
  adapterId: string;
  mode: ServiceProviderMode;
  eventsIngested: number;
  devicesDiscovered: number;
  message: string;
  syncedAt: string;
}

export interface LatencySample {
  timestamp: string;
  avgLatencyMs: number;
  minLatencyMs: number;
  maxLatencyMs: number;
  measuredCount: number;
}

export type NotificationChannelType = 'email' | 'webhook' | 'telegram';

export type NotificationSeverityThreshold = 'critical' | 'high' | 'medium';

export type NotificationTriggerEvent =
  | 'critical_incident'
  | 'kill_switch'
  | 'endpoint_offline'
  | 'ai_anomaly';

export interface NotificationDestination {
  id: string;
  name: string;
  type: NotificationChannelType;
  enabled: boolean;
  minSeverity: NotificationSeverityThreshold;
  triggers: NotificationTriggerEvent[];
  target: string;
  emailFrom?: string;
  smtpHost?: string;
  smtpPort?: number;
  smtpSecure?: boolean;
  webhookMethod?: 'POST' | 'PUT';
  webhookFormat?: 'openshield_json' | 'slack' | 'discord';
  usernameHint?: string;
  hasSecret?: boolean;
  lastDispatchedAt?: string;
  lastDispatchStatus?: 'sent' | 'simulated' | 'failed';
  lastDispatchMessage?: string;
  createdAt: string;
}

export interface NotificationDispatchRecord {
  id: string;
  destinationId: string;
  destinationName: string;
  channelType: NotificationChannelType;
  trigger: NotificationTriggerEvent;
  severity: EventSeverity;
  title: string;
  status: 'sent' | 'simulated' | 'failed';
  detail: string;
  dispatchedAt: string;
}

export interface WorkspaceState {
  context: OperatingContext;
  integrations: IntegrationAdapter[];
  devices: NetworkDevice[];
  events: OpenShieldEventV1[];
  dnsInsights: DnsInsight[];
  incidents: Incident[];
  policies: PolicyRule[];
  executions: ActionExecution[];
  auditLog: AuditEntry[];
  metrics: OperationalMetrics;
  latencyHistory?: LatencySample[];
  notifications?: NotificationDestination[];
  notificationHistory?: NotificationDispatchRecord[];
}
