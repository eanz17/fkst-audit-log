export type SourceMode = 'live' | 'empty';

export type ServiceStatus = 'healthy' | 'idle' | 'warning' | 'error';

export interface PipelineService {
  id: 'audit-watcher' | 'audit-analyzer' | 'alert-proxy';
  label: string;
  role: string;
  status: ServiceStatus;
  lastSeen: string | null;
  detail: string;
}

export interface AuditEvent {
  id: string;
  source: 'file' | 'aevatar';
  timestamp: string;
  action: string;
  outcome: string;
  actor: string;
  scope: string;
  resource: string;
  correlationId: string;
  suspicious: boolean;
}

export interface Finding {
  id: string;
  batchId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  summary: string;
  evidence: string;
  recommendedAction: string;
  cached: boolean;
}

export interface AlertRecord {
  id: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  dedupKey: string;
  dedupStatus: 'new' | 'duplicate' | 'unknown';
  mode: 'dry-run' | 'real';
  delivery: 'sent' | 'skipped' | 'failed' | 'pending';
  summary: string;
  count?: number;
}

// Collapsed stability-sentinel view: one row per fingerprint with the latest
// INCIDENT transition's fields plus how long the transition history is.
export interface Incident {
  fp: string;
  signal: string;
  state: string;
  fails: number;
  total: number;
  bucketsCovered: number;
  transitions: number;
  lastSeen: string;
}

// One issue-proxy action row. `kind` carries the issue kind for
// outbound/filed/skip, the probe kind (auth) for probes, and the exhausted
// scope (day/open) for budget lines.
export interface IssueAction {
  id: string;
  timestamp: string;
  action: 'outbound' | 'filed' | 'skip' | 'probe' | 'budget';
  kind: string;
  mode?: string;
  fp?: string;
  severity?: string;
  signal?: string;
  title?: string;
  reason?: string;
  number?: number;
  url?: string;
  ok?: boolean;
  detail?: string;
  used?: number;
  cap?: number;
}

export interface IssuePosture {
  write: boolean;
  aevatarRepo: string;
  pipelineRepo: string;
  transport: string;
  autoclose: boolean;
  detectEnabled: boolean;
  devloopConfigured: boolean;
}

export interface ConfigItem {
  key: string;
  value: string;
  sensitive: boolean;
  source: 'env' | 'default' | 'unset';
}

export interface AevatarPoll {
  records: number;
  seen: number;
  batches: number;
  at: string | null;
}

export interface DashboardPayload {
  generatedAt: string;
  sourceMode: SourceMode;
  runtimeRoot: string;
  durableRoot: string;
  watchRoot: string;
  services: PipelineService[];
  polling: {
    enabled: boolean;
    service: string;
    path: string;
    take: number;
    maxRecords: number;
    maxPagesPerTick: number;
    lookbackHours: number;
    scope: string;
  };
  aevatarPoll: AevatarPoll;
  alertMode: 'dry-run' | 'real';
  events: AuditEvent[];
  findings: Finding[];
  alerts: AlertRecord[];
  incidents: Incident[];
  issueActions: IssueAction[];
  issuePosture: IssuePosture;
  config: ConfigItem[];
}

export type TabKey = 'pipeline' | 'events' | 'findings' | 'alerts' | 'config' | 'stability';
export type TimeRange = '15m' | '1h' | '6h' | '24h' | 'all';
export type EventFilter = 'all' | 'suspect' | 'normal';
