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
    sliceMinutes: number;
    scope: string;
  };
  aevatarPoll: AevatarPoll;
  alertMode: 'dry-run' | 'real';
  events: AuditEvent[];
  findings: Finding[];
  alerts: AlertRecord[];
  config: ConfigItem[];
}

export type TabKey = 'pipeline' | 'events' | 'findings' | 'alerts' | 'config';
export type TimeRange = '15m' | '1h' | '6h' | '24h' | 'all';
export type EventFilter = 'all' | 'suspect' | 'normal';
