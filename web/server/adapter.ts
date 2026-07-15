import express from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isAevatarRecordSuspicious } from './aevatar-risk.js';
import {
  issueActivity,
  latestIncidentsByFp,
  parseIncidentLine,
  parseIssueLine,
  type Incident,
  type IncidentEntry,
  type IssueAction,
  type IssueEntry
} from './issue-log.js';
import { cacheValueIsFresh, deadLetterBatchId, runtimeLogFailed } from './runtime-health.js';

type SourceMode = 'live' | 'empty';

interface PipelineService {
  id: 'audit-watcher' | 'audit-analyzer' | 'alert-proxy';
  label: string;
  role: string;
  status: 'healthy' | 'idle' | 'warning' | 'error';
  lastSeen: string | null;
  detail: string;
}

interface AuditEvent {
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

interface Finding {
  id: string;
  batchId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  summary: string;
  evidence: string;
  recommendedAction: string;
  cached: boolean;
}

interface AlertRecord {
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

interface ConfigItem {
  key: string;
  value: string;
  sensitive: boolean;
  source: 'env' | 'default' | 'unset';
}

interface AevatarPoll {
  records: number;
  seen: number;
  batches: number;
  at: string | null;
}

// Posture of the issue-filing surface: none of these are secrets, but WHETHER
// real GitHub writes are on is the single most important fact on the 稳定性 tab.
interface IssuePosture {
  write: boolean;
  aevatarRepo: string;
  pipelineRepo: string;
  transport: string;
  autoclose: boolean;
  detectEnabled: boolean;
  devloopConfigured: boolean;
}

interface DashboardPayload {
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

const app = express();
// Anchor the repo root to this file's location (open-design/server/adapter.ts),
// not process.cwd(). The adapter is launched with cwd=open-design/, so a
// cwd-relative '../..' would overshoot to the parent of the repo and every
// dataset would silently look empty.
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(process.env.FKST_REPO_ROOT || path.join(here, '..', '..'));
const runtimeRoot = path.resolve(process.env.FKST_RUNTIME_ROOT || path.join(repoRoot, '.fkst/run/runtime'));
const durableRoot = path.resolve(process.env.FKST_DURABLE_ROOT || path.join(repoRoot, '.fkst/run/durable'));
const watchRoot = path.resolve(process.env.FKST_WATCH_ROOT || path.join(repoRoot, 'watch'));
const port = Number(process.env.FKST_WEB_API_PORT || 5174);
const maxFiles = Number(process.env.FKST_WEB_MAX_LOG_FILES || 120);
// Cheap TTL cache: the dashboard is polled every 30s by the UI (and the manual
// refresh button), but each request otherwise re-stats/re-reads up to maxFiles
// runtime logs. Serving a payload at most a few seconds stale is fine here.
const cacheTtlMs = Number(process.env.FKST_WEB_CACHE_MS || 2500);
let payloadCache: { at: number; payload: DashboardPayload } | null = null;

const envKeys = [
  'FKST_RUNTIME_ROOT',
  'FKST_DURABLE_ROOT',
  'FKST_ALERT_WRITE',
  'AUDIT_ALERT_MIN_SEVERITY',
  'ALERT_WEBHOOK_URL',
  'ALERT_WEBHOOK_URL_CRITICAL',
  'ALERT_FALLBACK_WEBHOOK_URL',
  // Issue-filing / stability posture. FKST_REDACT_EXTRA_KEYS/PATTERNS are
  // deliberately NOT surfaced: the redaction patterns themselves describe what
  // secrets look like, which is exactly what a read-only dashboard must not leak.
  'FKST_ISSUE_WRITE',
  'FKST_ISSUE_REPO',
  'FKST_AEVATAR_ISSUE_REPO',
  'FKST_PIPELINE_ISSUE_REPO',
  'FKST_AEVATAR_DEVLOOP_ENABLED',
  'FKST_ISSUE_TRANSPORT',
  'FKST_ISSUE_AUTOCLOSE',
  'FKST_ISSUE_MAX_PER_DAY',
  'FKST_ISSUE_MAX_OPEN',
  'STABILITY_DETECT_ENABLED',
  'AEVATAR_AUDIT_ENABLED',
  'AEVATAR_AUDIT_NYXID_SERVICE',
  'AEVATAR_AUDIT_PATH',
  'AEVATAR_AUDIT_TAKE',
  'AEVATAR_AUDIT_MAX_RECORDS',
  'AEVATAR_AUDIT_MAX_PAGES_PER_TICK',
  'AEVATAR_AUDIT_LOOKBACK_HOURS',
  'AEVATAR_AUDIT_SCOPE',
  'AEVATAR_AUDIT_ACTOR_ID',
  'AEVATAR_AUDIT_IDENTITY_KEY_ID',
  'AEVATAR_AUDIT_FROM',
  'AEVATAR_AUDIT_TO'
];

function isSensitiveKey(key: string): boolean {
  return /(TOKEN|SECRET|KEY|PASSWORD|WEBHOOK|NYXID|IDENTITY)/i.test(key);
}

function maskValue(key: string, raw: string | undefined): string {
  if (!raw) return '未设置';
  if (!isSensitiveKey(key)) return raw;
  if (/^https?:\/\//i.test(raw)) {
    try {
      const url = new URL(raw);
      return `${url.origin}/.../${raw.slice(-4)}`;
    } catch {
      return `***${raw.slice(-4)}`;
    }
  }
  if (raw.length <= 4) return '****';
  return `${raw.slice(0, 2)}***${raw.slice(-2)}`;
}

function defaultFor(key: string): string | undefined {
  const defaults: Record<string, string> = {
    FKST_RUNTIME_ROOT: runtimeRoot,
    FKST_DURABLE_ROOT: durableRoot,
    FKST_ALERT_WRITE: '0',
    AUDIT_ALERT_MIN_SEVERITY: 'high',
    FKST_ISSUE_WRITE: '0',
    FKST_ISSUE_REPO: 'eanz17/fkst-audit-log',
    FKST_AEVATAR_ISSUE_REPO: 'aevatarAI/aevatar',
    FKST_PIPELINE_ISSUE_REPO: 'eanz17/fkst-audit-log',
    FKST_AEVATAR_DEVLOOP_ENABLED: '0',
    FKST_ISSUE_TRANSPORT: 'gh',
    FKST_ISSUE_AUTOCLOSE: '0',
    FKST_ISSUE_MAX_PER_DAY: '1',
    FKST_ISSUE_MAX_OPEN: '10',
    STABILITY_DETECT_ENABLED: '0',
    AEVATAR_AUDIT_ENABLED: '1',
    AEVATAR_AUDIT_NYXID_SERVICE: 'aevatar',
    AEVATAR_AUDIT_PATH: '/api/audit/trail',
    AEVATAR_AUDIT_TAKE: '500',
    AEVATAR_AUDIT_MAX_RECORDS: '1000',
    AEVATAR_AUDIT_MAX_PAGES_PER_TICK: '12',
    AEVATAR_AUDIT_LOOKBACK_HOURS: '2'
  };
  return defaults[key];
}

async function exists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

async function hasRecoveredAnalysis(batchId: string | null): Promise<boolean> {
  if (!batchId) return false;
  const file = path.join(runtimeRoot, 'cache', 'audit-analyzer', 'result', batchId, '=value');
  try {
    return cacheValueIsFresh(await fs.readFile(file, 'utf8'));
  } catch {
    return false;
  }
}

async function readDirFiles(root: string, matcher: (name: string) => boolean): Promise<string[]> {
  try {
    const entries = await fs.readdir(root, { withFileTypes: true });
    return entries
      .filter((entry) => entry.isFile() && matcher(entry.name))
      .map((entry) => path.join(root, entry.name));
  } catch {
    return [];
  }
}

async function listRuntimeLogs(): Promise<string[]> {
  // Only the per-department child logs carry service/finding/alert signal.
  // The top-level supervisor-*.log has no serviceFromFile mapping, so we skip
  // it rather than tail it on every request.
  const root = path.join(runtimeRoot, 'logs/framework-child');
  const files: Array<{ file: string; mtimeMs: number }> = [];
  const found = await readDirFiles(root, (name) => name.endsWith('.log') && serviceFromFile(name) !== null);
  for (const file of found) {
    try {
      const stat = await fs.stat(file);
      files.push({ file, mtimeMs: stat.mtimeMs });
    } catch {
      // Ignore files that rotated between listing and stat.
    }
  }
  return files
    .sort((a, b) => b.mtimeMs - a.mtimeMs)
    .slice(0, maxFiles)
    .map((entry) => entry.file);
}

async function tailFile(file: string, bytes = 64_000): Promise<string> {
  const handle = await fs.open(file, 'r');
  try {
    const stat = await handle.stat();
    const start = Math.max(0, stat.size - bytes);
    const length = stat.size - start;
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, start);
    return buffer.toString('utf8');
  } finally {
    await handle.close();
  }
}

function isoFromLogName(file: string): string | null {
  const name = path.basename(file);
  const match = name.match(/-(\d{10})\d{0,9}-/);
  if (!match) return null;
  const seconds = Number(match[1]);
  if (!Number.isFinite(seconds)) return null;
  return new Date(seconds * 1000).toISOString();
}

// The stability services are scraped for the 稳定性 tab but are not pipeline
// tiles — their health story is told by INCIDENT/ISSUE_* lines, not by tiles.
type ScrapedService = PipelineService['id'] | 'stability-sentinel' | 'issue-proxy';

function serviceFromFile(file: string): ScrapedService | null {
  const base = path.basename(file);
  if (base.startsWith('audit-watcher.')) return 'audit-watcher';
  if (base.startsWith('audit-analyzer.')) return 'audit-analyzer';
  if (base.startsWith('alert-proxy.')) return 'alert-proxy';
  if (base.startsWith('stability-sentinel.')) return 'stability-sentinel';
  if (base.startsWith('issue-proxy.')) return 'issue-proxy';
  return null;
}

function severityRank(value: string): Finding['severity'] {
  const normalized = value.toLowerCase();
  if (normalized.includes('critical')) return 'critical';
  if (normalized.includes('high')) return 'high';
  if (normalized.includes('medium') || normalized.includes('warn')) return 'medium';
  return 'low';
}

function suspiciousLine(line: string): boolean {
  return /(failed password|not in sudoers|denied|forbidden|unauthorized|critical|suspicious|brute|shadow|token|secret)/i.test(line);
}

function extractField(line: string, key: string): string {
  const match = line.match(new RegExp(`${key}=([^\\s]+)`));
  return match?.[1] || '';
}

// Pick the most human-meaningful line from a child log. Every log ends with
// `EXIT=N` then `ELAPSED_MS=NNN`, so the naive "last non-empty line" is always
// a meaningless elapsed-ms number. Prefer, in order: an explicit failure reason,
// then the department's MSG/OUTBOUND summary, then any keyword line, then the
// last line as a final fallback.
function meaningfulLine(text: string): string {
  const lines = text.split(/\r?\n/).filter(Boolean);
  const failure = [...lines].reverse().find((l) => /pipeline failed|WHY=|ERROR_CLASS=|codex-|webhook-failed|missing-webhook-config/i.test(l));
  if (failure) return failure.slice(0, 200);
  const msg = [...lines].reverse().find((l) => /\bMSG=|OUTBOUND|aevatar-poll|findings=|batches=/i.test(l));
  if (msg) return msg.replace(/^.*?MSG=/, '').slice(0, 200);
  return lines.slice(-1)[0]?.slice(0, 200) || '最近运行完成';
}

function prettyActor(auditActorId: string): string {
  const hmac = auditActorId.match(/hmac-sha256:([0-9a-f]{6,})/i);
  if (hmac) return `actor:${hmac[1].slice(0, 10)}`;
  return auditActorId || 'unknown';
}

function auditEventFromAevatarRecord(record: any): AuditEvent | null {
  const id = String(record?.id ?? record?.Id ?? '');
  if (!id) return null;
  const occurred = String(record?.occurredAtUtc ?? record?.OccurredAtUtc ?? '');
  const action = String(record?.action ?? record?.Action ?? '');
  const outcome = String(record?.outcome ?? record?.Outcome ?? '');
  const resourceType = String(record?.resourceType ?? record?.ResourceType ?? '');
  const rawResourceId = record?.resourceId ?? record?.ResourceId;
  const resourceId = rawResourceId == null ? '' : String(rawResourceId);
  const resource = (resourceId ? `${resourceType}/${resourceId}` : resourceType || '—').slice(0, 120);
  let timestamp = new Date().toISOString();
  if (occurred) {
    const parsed = new Date(occurred);
    if (!Number.isNaN(parsed.getTime())) timestamp = parsed.toISOString();
  }
  return {
    id: `aevatar-${id}`,
    source: 'aevatar',
    timestamp,
    action: action || 'audit_event',
    outcome: outcome || 'unknown',
    actor: prettyActor(String(record?.auditActorId ?? record?.AuditActorId ?? '')),
    scope: String(record?.scopeId || record?.ScopeId || '__all__'),
    resource,
    correlationId: String(record?.correlationId ?? record?.CorrelationId ?? ''),
    suspicious: isAevatarRecordSuspicious(action, outcome)
  };
}

// Salvage complete record objects from a possibly-truncated JSON excerpt. The
// runtime logs capture the nyxid response as STDOUT_EXCERPT which is capped at a
// few KB, so large audit pages arrive as JSON that is cut off mid-object. A
// plain JSON.parse fails; here we walk the `records` array and keep every object
// that closed before the truncation point.
function salvageRecords(excerpt: string): any[] {
  try {
    const parsed = JSON.parse(excerpt);
    const records = parsed?.records ?? parsed?.Records;
    if (Array.isArray(records)) return records;
  } catch {
    // fall through to salvage
  }
  const keyIdx = excerpt.search(/"[Rr]ecords"\s*:\s*\[/);
  if (keyIdx < 0) return [];
  let i = excerpt.indexOf('[', keyIdx) + 1;
  const records: any[] = [];
  while (i < excerpt.length) {
    while (i < excerpt.length && (excerpt[i] === ',' || /\s/.test(excerpt[i]))) i++;
    if (excerpt[i] !== '{') break;
    let depth = 0;
    let inStr = false;
    let esc = false;
    let j = i;
    for (; j < excerpt.length; j++) {
      const c = excerpt[j];
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (inStr) { if (c === '"') inStr = false; continue; }
      if (c === '"') { inStr = true; continue; }
      if (c === '{') depth++;
      else if (c === '}') { depth--; if (depth === 0) { j++; break; } }
    }
    if (depth !== 0) break; // last object truncated
    try {
      records.push(JSON.parse(excerpt.slice(i, j)));
    } catch {
      break;
    }
    i = j;
  }
  return records;
}

function aevatarEventsFromLog(text: string, file: string): AuditEvent[] {
  const events: AuditEvent[] = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const idx = line.indexOf('STDOUT_EXCERPT=');
    if (idx < 0) continue;
    let excerpt = line.slice(idx + 'STDOUT_EXCERPT='.length);
    const stderrIdx = excerpt.indexOf(' STDERR_EXCERPT=');
    if (stderrIdx >= 0) excerpt = excerpt.slice(0, stderrIdx);
    if (!excerpt.trimStart().startsWith('{')) continue;
    for (const record of salvageRecords(excerpt)) {
      const event = auditEventFromAevatarRecord(record);
      if (event) events.push(event);
    }
  }
  return events;
}

async function readCachedAevatarEvents(): Promise<AuditEvent[]> {
  const file = path.join(runtimeRoot, 'aevatar-events.jsonl');
  let text = '';
  try {
    text = await fs.readFile(file, 'utf8');
  } catch {
    return [];
  }
  const events: AuditEvent[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const event = auditEventFromAevatarRecord(JSON.parse(line));
      if (event) events.push(event);
    } catch {
      // Keep serving the rest of the dashboard if one cache line is truncated.
    }
  }
  return events;
}

async function parseWatchEvents(): Promise<AuditEvent[]> {
  const files = await readDirFiles(watchRoot, (name) => name.endsWith('.log'));
  const events: AuditEvent[] = [];
  for (const file of files.slice(0, 20)) {
    let content = '';
    try {
      content = await tailFile(file, 48_000);
    } catch {
      continue;
    }
    const lines = content.split(/\r?\n/).filter(Boolean).slice(-200);
    lines.forEach((line, index) => {
      const ts = line.match(/^(\d{4}-\d{2}-\d{2}T[^\s]+)/)?.[1];
      // Strip a leading ISO timestamp token before deriving the actor, otherwise
      // lines without a "for <name>" clause latch onto the timestamp fragment.
      const body = /^\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s/.test(line) ? line.replace(/^\S+\s+/, '') : line;
      const failed = /failed|denied|not in sudoers|unauthorized/i.test(line);
      const actor = body.match(/\bfor\s+([a-zA-Z0-9._-]+)/)?.[1]
        || body.match(/^([a-zA-Z0-9._-]+)/)?.[1]
        || 'unknown';
      const ip = line.match(/\b(?:from|addr=)\s+([0-9a-fA-F:.]+)/)?.[1] || 'local';
      const command = line.match(/COMMAND=([^\s]+)/)?.[1] || '';
      events.push({
        id: `${path.basename(file)}-${index}`,
        source: 'file',
        timestamp: ts ? new Date(ts).toISOString() : new Date().toISOString(),
        action: failed ? 'auth_failure' : command ? 'privilege_command' : 'log_observed',
        outcome: failed ? 'failed' : 'observed',
        actor,
        scope: path.basename(file),
        resource: command || ip,
        correlationId: ip,
        suspicious: suspiciousLine(line)
      });
    });
  }
  return events;
}

interface RuntimeParse {
  services: PipelineService[];
  findings: Finding[];
  alerts: AlertRecord[];
  aevatarEvents: AuditEvent[];
  aevatarPoll: AevatarPoll;
  incidents: Incident[];
  issueActions: IssueAction[];
}

async function parseRuntime(): Promise<RuntimeParse> {
  const files = await listRuntimeLogs();
  const serviceMap = new Map<ScrapedService, PipelineService>([
    ['audit-watcher', { id: 'audit-watcher', label: '日志采集 · watcher', role: '采集入口', status: 'idle', lastSeen: null, detail: '待启动：还没有采集日志' }],
    ['audit-analyzer', { id: 'audit-analyzer', label: 'LLM 分析 · analyzer', role: '分析阶段', status: 'idle', lastSeen: null, detail: '待触发：有 batch 才会运行分析' }],
    ['alert-proxy', { id: 'alert-proxy', label: '告警投递 · proxy', role: '告警阶段', status: 'idle', lastSeen: null, detail: '待触发：有高风险 finding 才会投递' }]
  ]);
  const findings: Finding[] = [];
  const alertsByKey = new Map<string, AlertRecord>();
  const aevatarEvents: AuditEvent[] = [];
  const seenAevatar = new Set<string>();
  const aevatarPoll: AevatarPoll = { records: 0, seen: 0, batches: 0, at: null };
  const deadLetters: Array<{ timestamp: string; why: string; batchId: string | null }> = [];
  // Stability lines carry no per-line timestamp, so ordering is the log file's
  // name-encoded time plus line order. Files iterate newest-first here; one
  // batch per file lets a single reverse() restore oldest-first afterwards.
  const incidentBatches: IncidentEntry[][] = [];
  const issueBatches: IssueEntry[][] = [];

  for (const file of files) {
    const service = serviceFromFile(file);
    const timestamp = isoFromLogName(file) || new Date().toISOString();
    let text = '';
    try {
      text = await tailFile(file);
    } catch {
      continue;
    }
    if (service) {
      const current = serviceMap.get(service);
      if (current && (!current.lastSeen || timestamp > current.lastSeen)) {
        current.lastSeen = timestamp;
        current.status = runtimeLogFailed(file, text) ? 'error' : 'healthy';
        current.detail = meaningfulLine(text);
      }
    }

    if (service === 'audit-watcher') {
      for (const event of aevatarEventsFromLog(text, file)) {
        if (seenAevatar.has(event.id)) continue;
        seenAevatar.add(event.id);
        aevatarEvents.push(event);
      }
      const poll = text.match(/aevatar-poll(?:\s+mode=\S+)?\s+records=(\d+)\s+seen=(\d+)\s+batches=(\d+)/);
      if (poll && (!aevatarPoll.at || timestamp > aevatarPoll.at)) {
        aevatarPoll.records = Number(poll[1]);
        aevatarPoll.seen = Number(poll[2]);
        aevatarPoll.batches = Number(poll[3]);
        aevatarPoll.at = timestamp;
      }
    }

    if (service === 'audit-analyzer') {
      const batch = extractField(text, 'batch') || path.basename(file);
      const findingCount = Number(extractField(text, 'findings') || 0);
      const alertCount = Number(extractField(text, 'alerts') || 0);
      if (findingCount > 0 || alertCount > 0) {
        findings.push({
          id: `finding-${path.basename(file)}`,
          batchId: batch,
          severity: alertCount > 0 ? severityRank(process.env.AUDIT_ALERT_MIN_SEVERITY || 'high') : 'medium',
          category: 'llm_analysis',
          summary: `分析完成：${findingCount || alertCount} 条发现，${alertCount} 条进入告警阈值`,
          evidence: text.split(/\r?\n/).find((line) => /DROP|findings=|alerts=/.test(line)) || 'runtime 日志未暴露 evidence 明细',
          recommendedAction: '打开对应 audit_batch 缓存或源日志复核证据行',
          cached: /cached_result=true/i.test(text)
        });
      }
      if (/DEAD_LETTER|dead_letter/.test(text) && /WHY=/.test(text)) {
        const why = (text.match(/WHY=([^\n]*)/)?.[1] || '').slice(0, 200);
        deadLetters.push({ timestamp, why, batchId: deadLetterBatchId(text) });
      }
    }

    if (service === 'stability-sentinel') {
      const batch: IncidentEntry[] = [];
      for (const line of text.split(/\r?\n/)) {
        const incident = parseIncidentLine(line);
        if (incident) batch.push({ ...incident, timestamp });
      }
      if (batch.length) incidentBatches.push(batch);
    }

    if (service === 'issue-proxy') {
      const batch: IssueEntry[] = [];
      for (const line of text.split(/\r?\n/)) {
        const parsed = parseIssueLine(line);
        if (parsed) batch.push({ line: parsed, timestamp });
      }
      if (batch.length) issueBatches.push(batch);
    }

    if (service === 'alert-proxy') {
      const duplicate = /SKIP duplicate/i.test(text);
      const outbound = /OUTBOUND/i.test(text);
      const failed = /webhook-failed|missing-webhook-config/i.test(text);
      if (duplicate || outbound || failed) {
        const mode = /mode=real/i.test(text) ? 'real' : 'dry-run';
        const dedupKey = extractField(text, 'dedup_key') || 'unknown';
        const key = `${dedupKey}|${mode}`;
        const record: AlertRecord = {
          id: `alert-${path.basename(file)}`,
          timestamp,
          severity: severityRank(extractField(text, 'severity') || process.env.AUDIT_ALERT_MIN_SEVERITY || 'high'),
          category: extractField(text, 'category') || 'audit_alert',
          dedupKey,
          dedupStatus: duplicate ? 'duplicate' : 'new',
          mode,
          delivery: failed ? 'failed' : mode === 'dry-run' ? 'skipped' : 'sent',
          summary: meaningfulLine(text),
          count: 1
        };
        // Collapse the many near-identical alerts that share a dedup_key (the
        // dry-run dead-letter meta-alert fires every minute) into one row that
        // keeps the newest timestamp and an occurrence count.
        const prev = alertsByKey.get(key);
        if (!prev) {
          alertsByKey.set(key, record);
        } else {
          prev.count = (prev.count || 1) + 1;
          if (record.timestamp > prev.timestamp) {
            prev.timestamp = record.timestamp;
            prev.summary = record.summary;
            prev.dedupStatus = record.dedupStatus;
            prev.delivery = record.delivery;
          }
        }
      }
    }
  }

  // Synthesize a real pipeline-health finding from the analyzer dead letters so
  // the operator sees the ACTUAL failure (analyzer batches dead-lettering,
  // typically because the codex CLI is unavailable) instead of a blank tab.
  const unresolvedDeadLetters = (
    await Promise.all(deadLetters.map(async (dead) => ({ dead, recovered: await hasRecoveredAnalysis(dead.batchId) })))
  )
    .filter(({ recovered }) => !recovered)
    .map(({ dead }) => dead);
  if (unresolvedDeadLetters.length > 0) {
    unresolvedDeadLetters.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    const latest = unresolvedDeadLetters[0];
    findings.push({
      id: 'finding-pipeline-health',
      batchId: 'pipeline-health',
      severity: 'high',
      category: 'pipeline_health',
      summary: `audit-analyzer 有 ${unresolvedDeadLetters.length} 个批次进入死信（LLM 分析未产出）`,
      evidence: latest.why || 'analyzer 投递进入 dead_letter',
      recommendedAction: '确认 host 上 codex CLI 已安装并登录（spawn_codex_sync 依赖它）；或查看 audit-analyzer.dead_letter 日志定位 analyze 部门错误',
      cached: false
    });
  }

  const alerts = Array.from(alertsByKey.values()).sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  // Oldest-first replay so the last INCIDENT transition per fingerprint wins;
  // the activity list flips to most-recent-first for display.
  const incidents = latestIncidentsByFp(incidentBatches.reverse().flat());
  const issueActions = issueActivity(issueBatches.reverse().flat()).reverse().slice(0, 80);
  return {
    services: Array.from(serviceMap.values()),
    findings: findings.slice(0, 80),
    alerts: alerts.slice(0, 80),
    aevatarEvents,
    aevatarPoll,
    incidents,
    issueActions
  };
}

function configItems(): ConfigItem[] {
  return envKeys.map((key) => {
    const envValue = process.env[key];
    const fallback = defaultFor(key);
    const value = envValue ?? fallback ?? '';
    return {
      key,
      value: maskValue(key, value),
      sensitive: isSensitiveKey(key),
      source: envValue !== undefined ? 'env' : fallback !== undefined ? 'default' : 'unset'
    };
  });
}

async function dashboardPayload(): Promise<DashboardPayload> {
  const [{ services, findings, alerts, aevatarEvents, aevatarPoll, incidents, issueActions }, cachedAevatarEvents, fileEvents] = await Promise.all([
    parseRuntime(),
    readCachedAevatarEvents(),
    parseWatchEvents()
  ]);
  const runtimeExists = await exists(runtimeRoot);
  const maxEvents = Math.max(1, Number(process.env.AEVATAR_AUDIT_MAX_RECORDS || 1000));
  const aevatarById = new Map<string, AuditEvent>();
  for (const event of [...aevatarEvents, ...cachedAevatarEvents]) {
    aevatarById.set(event.id, event);
  }

  // Merge live event sources (aevatar audit trail + local watch files), newest
  // first. The aevatar trail is the primary source for this monitor.
  const liveEvents = [...aevatarById.values(), ...fileEvents]
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    .slice(0, maxEvents);

  const events = liveEvents;
  const sourceMode: SourceMode = !runtimeExists && liveEvents.length === 0 ? 'empty' : 'live';

  return {
    generatedAt: new Date().toISOString(),
    sourceMode,
    runtimeRoot,
    durableRoot,
    watchRoot,
    services: runtimeExists ? services : services.map((service) => ({
      ...service,
      status: 'warning',
      detail: '未启动：运行 ./boot.sh 后开始写入 runtime'
    })),
    polling: {
      enabled: (process.env.AEVATAR_AUDIT_ENABLED ?? '1') === '1',
      service: process.env.AEVATAR_AUDIT_NYXID_SERVICE || 'aevatar',
      path: process.env.AEVATAR_AUDIT_PATH || '/api/audit/trail',
      take: Number(process.env.AEVATAR_AUDIT_TAKE || 500),
      maxRecords: Number(process.env.AEVATAR_AUDIT_MAX_RECORDS || 1000),
      maxPagesPerTick: Number(process.env.AEVATAR_AUDIT_MAX_PAGES_PER_TICK || 12),
      lookbackHours: Number(process.env.AEVATAR_AUDIT_LOOKBACK_HOURS || 2),
      scope: process.env.AEVATAR_AUDIT_SCOPE || ''
    },
    aevatarPoll,
    alertMode: process.env.FKST_ALERT_WRITE === '1' ? 'real' : 'dry-run',
    events,
    findings,
    alerts,
    // Honest-empty doctrine: incidents/issueActions come only from real
    // runtime logs — never fabricate sample issues, demo mode included.
    incidents,
    issueActions,
    issuePosture: {
      write: process.env.FKST_ISSUE_WRITE === '1',
      aevatarRepo: process.env.FKST_AEVATAR_ISSUE_REPO || 'aevatarAI/aevatar',
      pipelineRepo: process.env.FKST_PIPELINE_ISSUE_REPO || 'eanz17/fkst-audit-log',
      transport: process.env.FKST_ISSUE_TRANSPORT || 'gh',
      autoclose: (process.env.FKST_ISSUE_AUTOCLOSE ?? '0') === '1',
      detectEnabled: process.env.STABILITY_DETECT_ENABLED === '1',
      devloopConfigured: process.env.FKST_AEVATAR_DEVLOOP_ENABLED === '1'
    },
    config: configItems()
  };
}

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    generatedAt: new Date().toISOString(),
    repoRoot,
    runtimeRoot
  });
});

app.get('/api/dashboard', async (_req, res) => {
  try {
    const now = Date.now();
    if (payloadCache && now - payloadCache.at < cacheTtlMs) {
      res.json(payloadCache.payload);
      return;
    }
    const payload = await dashboardPayload();
    payloadCache = { at: now, payload };
    res.json(payload);
  } catch (error) {
    res.status(500).json({
      error: 'adapter_failed',
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

app.listen(port, '127.0.0.1', () => {
  console.log(`fkst-web-adapter: http://127.0.0.1:${port}`);
  console.log(`fkst-web-adapter: repo=${repoRoot}`);
  console.log('fkst-web-adapter: read-only runtime/watch/config view; sensitive values are masked');
});
