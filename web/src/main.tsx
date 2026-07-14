import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  AlertTriangle,
  Bell,
  Boxes,
  CheckCircle2,
  Clock3,
  Database,
  FileSearch,
  Filter,
  KeyRound,
  RefreshCw,
  Search,
  ShieldAlert,
  SlidersHorizontal
} from 'lucide-react';
import { wouldHaveFiled } from '../server/issue-log';
import { fetchDashboard } from './lib/api';
import { formatDateTime, formatRelative, inTimeRange } from './lib/format';
import { Badge } from './components/Badge';
import { EmptyState } from './components/EmptyState';
import type {
  AlertRecord,
  AuditEvent,
  DashboardPayload,
  EventFilter,
  Finding,
  Incident,
  IssueAction,
  IssuePosture,
  PipelineService,
  TabKey,
  TimeRange
} from './types';
import './styles.css';

const tabs: Array<{ key: TabKey; label: string; icon: React.ReactNode }> = [
  { key: 'pipeline', label: '管线状态', icon: <Database size={16} /> },
  { key: 'events', label: '审计事件', icon: <FileSearch size={16} /> },
  { key: 'findings', label: '分析发现', icon: <ShieldAlert size={16} /> },
  { key: 'alerts', label: '告警', icon: <Bell size={16} /> },
  { key: 'config', label: '配置', icon: <SlidersHorizontal size={16} /> },
  { key: 'stability', label: '稳定性', icon: <Activity size={16} /> }
];

const timeRanges: Array<{ value: TimeRange; label: string }> = [
  { value: '15m', label: '15 分钟' },
  { value: '1h', label: '1 小时' },
  { value: '6h', label: '6 小时' },
  { value: '24h', label: '24 小时' },
  { value: 'all', label: '全部' }
];

const eventFilters: Array<{ value: EventFilter; label: string }> = [
  { value: 'all', label: '全部' },
  { value: 'suspect', label: '可疑' },
  { value: 'normal', label: '正常' }
];

// Which persistent controls make sense per tab. Rendering them where they do
// nothing (e.g. the time range on Config) just misleads the operator.
const tabControls: Record<TabKey, { search: boolean; range: boolean }> = {
  pipeline: { search: false, range: false },
  events: { search: true, range: true },
  findings: { search: true, range: false },
  alerts: { search: true, range: true },
  config: { search: false, range: false },
  stability: { search: false, range: false }
};

const activeTabStorageKey = 'fkst-audit-monitor.activeTab';
const tabKeys = new Set<TabKey>(tabs.map((tab) => tab.key));

function isTabKey(value: string | null): value is TabKey {
  return value !== null && tabKeys.has(value as TabKey);
}

function tabFromHash(hash: string): TabKey | null {
  const raw = hash.replace(/^#\/?/, '').split(/[?&]/)[0];
  let decoded = '';
  try {
    decoded = raw ? decodeURIComponent(raw).trim() : '';
  } catch {
    decoded = '';
  }
  return isTabKey(decoded) ? decoded : null;
}

function readStoredTab(): TabKey | null {
  try {
    const stored = window.localStorage.getItem(activeTabStorageKey);
    return isTabKey(stored) ? stored : null;
  } catch {
    return null;
  }
}

function storeTab(tab: TabKey) {
  try {
    window.localStorage.setItem(activeTabStorageKey, tab);
  } catch {
    // localStorage can be disabled; the URL hash still preserves refresh state.
  }
}

function writeTabHash(tab: TabKey, mode: 'push' | 'replace' = 'push') {
  const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  const next = `${window.location.pathname}${window.location.search}#${tab}`;
  if (current === next) return;
  window.history[mode === 'replace' ? 'replaceState' : 'pushState']({ tab }, '', next);
}

function initialTab(): TabKey {
  return tabFromHash(window.location.hash) ?? readStoredTab() ?? 'pipeline';
}

function useActiveTab() {
  const [activeTab, setActiveTabState] = useState<TabKey>(() => initialTab());

  useEffect(() => {
    const syncFromLocation = () => {
      const tab = tabFromHash(window.location.hash) ?? readStoredTab() ?? 'pipeline';
      setActiveTabState(tab);
      storeTab(tab);
      if (tabFromHash(window.location.hash) !== tab) writeTabHash(tab, 'replace');
    };

    window.addEventListener('hashchange', syncFromLocation);
    window.addEventListener('popstate', syncFromLocation);
    return () => {
      window.removeEventListener('hashchange', syncFromLocation);
      window.removeEventListener('popstate', syncFromLocation);
    };
  }, []);

  useEffect(() => {
    storeTab(activeTab);
    writeTabHash(activeTab, tabFromHash(window.location.hash) ? 'push' : 'replace');
  }, [activeTab]);

  return [activeTab, setActiveTabState] as const;
}

function severityTone(severity: string) {
  if (severity === 'critical') return 'danger';
  if (severity === 'high') return 'warning';
  if (severity === 'medium') return 'info';
  return 'neutral';
}

function statusTone(status: PipelineService['status']) {
  if (status === 'healthy') return 'success';
  if (status === 'error') return 'danger';
  if (status === 'warning') return 'warning';
  return 'neutral';
}

function statusCopy(status: PipelineService['status']) {
  if (status === 'healthy') return '正常';
  if (status === 'error') return '异常';
  if (status === 'warning') return '需启动';
  return '待触发';
}

function newestTimestamp(items: Array<{ timestamp: string }>): string | null {
  return items.reduce<string | null>((latest, item) => {
    if (!item.timestamp) return latest;
    return latest === null || item.timestamp > latest ? item.timestamp : latest;
  }, null);
}

function serviceDetail(service: PipelineService) {
  if (service.status !== 'idle' || service.detail !== '等待 runtime 日志') return service.detail;
  if (service.id === 'audit-watcher') return '待启动：还没有采集日志';
  if (service.id === 'audit-analyzer') return '待触发：有 batch 才会运行分析';
  return '待触发：有高风险 finding 才会投递';
}

function sourceModeCopy(mode: DashboardPayload['sourceMode']) {
  if (mode === 'live') return '实时数据';
  return '暂无数据';
}

function useDashboard() {
  const [data, setData] = useState<DashboardPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const controllerRef = useRef<AbortController | null>(null);

  async function load(kind: 'initial' | 'refresh') {
    // Cancel any in-flight request so only the latest response is applied and
    // we never setState after unmount.
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    if (kind === 'initial') setLoading(true);
    else setRefreshing(true);
    try {
      const payload = await fetchDashboard(controller.signal);
      if (controller.signal.aborted) return;
      setData(payload);
      setError(null);
    } catch (err) {
      if (controller.signal.aborted) return;
      if (err instanceof DOMException && err.name === 'AbortError') return;
      // Only surface errors on a terminal failure — never optimistically clear
      // the banner at the start of every 30s background poll.
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (controller.signal.aborted) return;
      if (kind === 'initial') setLoading(false);
      else setRefreshing(false);
    }
  }

  useEffect(() => {
    load('initial');
    const timer = window.setInterval(() => load('refresh'), 30_000);
    return () => {
      controllerRef.current?.abort();
      window.clearInterval(timer);
    };
  }, []);

  return { data, error, loading, refreshing, reload: () => load('refresh') };
}

function Header({
  data,
  busy,
  onRefresh
}: {
  data: DashboardPayload | null;
  busy: boolean;
  onRefresh: () => void;
}) {
  return (
    <header className="app-header" data-od-id="app-header">
      <div className="title-block">
        <span className="eyebrow">FKST Audit Monitor</span>
        <h1 data-od-id="page-title">本地审计管线监控</h1>
      </div>
      <div className="header-meta">
        <Badge tone={data?.sourceMode === 'live' ? 'success' : 'warning'}>
          {data ? sourceModeCopy(data.sourceMode) : '连接中'}
        </Badge>
        <span className="meta-line">刷新：{data ? formatRelative(data.generatedAt) : '等待数据'}</span>
        <button className="icon-button" type="button" onClick={onRefresh} aria-label="刷新数据" data-od-id="refresh-button">
          <RefreshCw size={17} className={busy ? 'spin' : ''} />
        </button>
      </div>
    </header>
  );
}

function Toolbar({
  query,
  setQuery,
  range,
  setRange,
  showSearch,
  showRange
}: {
  query: string;
  setQuery: (value: string) => void;
  range: TimeRange;
  setRange: (value: TimeRange) => void;
  showSearch: boolean;
  showRange: boolean;
}) {
  if (!showSearch && !showRange) return null;
  return (
    <div className={`toolbar ${showSearch && showRange ? '' : 'toolbar-single'}`} data-od-id="filter-toolbar">
      {showSearch ? (
        <label className="search-box">
          <Search size={16} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索 actor、resource、batch、dedup..."
            aria-label="搜索审计数据"
          />
        </label>
      ) : null}
      {showRange ? (
        <label className="select-box">
          <Filter size={16} />
          <select value={range} onChange={(event) => setRange(event.target.value as TimeRange)} aria-label="时间范围">
            {timeRanges.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
      ) : null}
    </div>
  );
}

type Tone = 'success' | 'warning' | 'danger' | 'info' | 'neutral';

function hasPipelineHealthFinding(data: DashboardPayload) {
  return data.findings.some((f) => f.category === 'pipeline_health' || f.batchId === 'pipeline-health');
}

// A correct one-line verdict on the pipeline. Idle services are NORMAL (they
// wait for input) — only real errors or dead-lettered batches are "异常". This
// replaces the misleading "healthy/total" count that read idle as broken.
function pipelineHealth(data: DashboardPayload): { tone: Tone; label: string; note: string } {
  const hasError = data.services.some((s) => s.status === 'error');
  const needsBoot = data.services.some((s) => s.status === 'warning');
  if (hasError || hasPipelineHealthFinding(data)) {
    return { tone: 'danger', label: '异常', note: '有服务报错或批次进入死信' };
  }
  if (needsBoot) return { tone: 'warning', label: '需启动', note: 'runtime 未就绪，运行 ./boot.sh' };
  const active = data.services.filter((s) => s.status === 'healthy').length;
  return { tone: 'success', label: '正常', note: `${active}/${data.services.length} 活跃，其余待触发` };
}

// Meta-alerts describe the monitoring machinery itself (dead-lettered
// deliveries, issue-filing budget) — they surface via pipeline health and the
// 稳定性 tab, and must not masquerade as audit findings sent to on-call.
const metaAlertCategories = new Set(['pipeline-dead-letter', 'issue-filing-dead-letter', 'issue-budget-exhausted']);

// The single most urgent thing to act on, or null when all clear. Level-
// triggered from data — we never nag on warnings, only surface real danger.
function topAttention(data: DashboardPayload): { text: string; tab: TabKey } | null {
  if (pipelineHealth(data).tone === 'danger') {
    const dl = data.findings.find((f) => f.category === 'pipeline_health' || f.batchId === 'pipeline-health');
    return {
      text: dl ? dl.summary : '管线中有服务报错，采集 / 分析 / 投递可能中断',
      tab: dl ? 'findings' : 'pipeline'
    };
  }
  const realHigh = data.alerts.filter(
    (a) => !metaAlertCategories.has(a.category)
      && a.mode === 'real'
      && (a.severity === 'critical' || a.severity === 'high')
  );
  if (realHigh.length) {
    return { text: `有 ${realHigh.length} 条高危告警已真实发送到值班渠道`, tab: 'alerts' };
  }
  return null;
}

const ribbonToneClass: Record<Tone, string> = {
  success: 'ribbon-success',
  warning: 'ribbon-warning',
  danger: 'ribbon-danger',
  info: 'ribbon-info',
  neutral: ''
};

type RibbonJump = (tab: TabKey, options?: { eventFilter?: EventFilter }) => void;

// Persistent, severity-aware summary shown on EVERY tab so "is anything wrong?"
// is answerable without hopping to the pipeline view. Each cell jumps to the
// tab that explains it.
function StatusRibbon({ data, onJump }: { data: DashboardPayload; onJump: RibbonJump }) {
  const health = pipelineHealth(data);
  const highSev = [...data.findings, ...data.alerts].filter(
    (x) => x.severity === 'high' || x.severity === 'critical'
  ).length;
  const suspicious = data.events.filter((e) => e.suspicious).length;
  const realAlerts = data.alerts.filter((a) => a.mode === 'real').length;
  const dryRun = data.alertMode === 'dry-run';
  const cells: Array<{ tone: Tone; label: string; value: string; note: string; tab: TabKey; eventFilter?: EventFilter }> = [
    { tone: health.tone, label: '管线', value: health.label, note: health.note, tab: 'pipeline' },
    { tone: highSev > 0 ? 'danger' : 'neutral', label: '高危信号', value: String(highSev), note: 'high / critical 发现与告警', tab: 'findings' },
    { tone: suspicious > 0 ? 'warning' : 'neutral', label: '可疑事件', value: String(suspicious), note: '已标记 suspect 的事件', tab: 'events', eventFilter: 'suspect' },
    { tone: dryRun ? 'info' : 'danger', label: '告警姿态', value: dryRun ? 'dry-run' : `real · ${realAlerts}`, note: dryRun ? '仅记录，不外发' : '真实发送已开启', tab: 'alerts' }
  ];
  return (
    <section className="status-ribbon" aria-label="总览指标" data-od-id="status-ribbon">
      {cells.map((cell) => (
        <button
          type="button"
          key={cell.label}
          className={`ribbon-cell ${ribbonToneClass[cell.tone]}`}
          onClick={() => onJump(cell.tab, { eventFilter: cell.eventFilter })}
          title={`${cell.note} · 点击查看`}
        >
          <span className="ribbon-label">{cell.label}</span>
          <strong className="ribbon-value">{cell.value}</strong>
          <span className="ribbon-note">{cell.note}</span>
        </button>
      ))}
    </section>
  );
}

function AttentionCallout({ data, onJump }: { data: DashboardPayload; onJump: (tab: TabKey) => void }) {
  const item = topAttention(data);
  if (!item) return null;
  return (
    <button type="button" className="attention" onClick={() => onJump(item.tab)} data-od-id="attention-callout">
      <ShieldAlert size={18} />
      <span className="attention-text">{item.text}</span>
      <span className="attention-cta">查看 →</span>
    </button>
  );
}

function PipelineView({ data }: { data: DashboardPayload }) {
  const poll = data.aevatarPoll;
  const latestEvent = newestTimestamp(data.events);
  return (
    <div className="view-stack" data-od-id="pipeline-view">
      <section className="panel grid-panel" data-od-id="service-status-panel">
        {data.services.map((service) => (
          <article className="service-tile" key={service.id} data-od-id={`service-${service.id}`}>
            <div className="service-head">
              <div>
                <span className="tile-label">{service.role}</span>
                <h2>{service.label}</h2>
              </div>
              <Badge tone={statusTone(service.status)} title={service.status}>{statusCopy(service.status)}</Badge>
            </div>
            <p>{serviceDetail(service)}</p>
            <div className="tile-foot">
              <Clock3 size={15} />
              <span>{formatRelative(service.lastSeen)}</span>
            </div>
          </article>
        ))}
      </section>

      <section className="panel split-panel" data-od-id="runtime-summary-panel">
        <div>
          <div className="section-heading">
            <Boxes size={17} />
            <h2>Aevatar 采集</h2>
          </div>
          <dl className="kv-grid">
            <div><dt>状态</dt><dd>{data.polling.enabled ? '已启用' : '已关闭'}</dd></div>
            <div><dt>service</dt><dd>{data.polling.service}</dd></div>
            <div><dt>path</dt><dd>{data.polling.path}</dd></div>
            <div><dt>默认窗口</dt><dd>最近 {data.polling.lookbackHours} 小时</dd></div>
            <div><dt>时间片</dt><dd>{data.polling.sliceMinutes} 分钟</dd></div>
            <div><dt>最多记录</dt><dd>{data.polling.maxRecords}</dd></div>
            <div><dt>take</dt><dd>{data.polling.take}</dd></div>
            <div><dt>最多页数</dt><dd>{data.polling.maxPagesPerTick}</dd></div>
            <div><dt>scope</dt><dd>{data.polling.scope || '未限制'}</dd></div>
            <div><dt>最近一轮</dt><dd>{poll.at ? formatRelative(poll.at) : '无记录'}</dd></div>
            <div><dt>最新事件</dt><dd>{latestEvent ? formatDateTime(latestEvent) : '无记录'}</dd></div>
            <div><dt>缓存 / 已见</dt><dd>{poll.records} / {poll.seen}</dd></div>
            <div><dt>待分析批次</dt><dd>{poll.batches}</dd></div>
          </dl>
        </div>
        <div>
          <div className="section-heading">
            <AlertTriangle size={17} />
            <h2>运行边界</h2>
          </div>
          <dl className="kv-grid">
            <div><dt>runtime</dt><dd>{data.runtimeRoot}</dd></div>
            <div><dt>durable</dt><dd>{data.durableRoot}</dd></div>
            <div><dt>watch</dt><dd>{data.watchRoot}</dd></div>
            <div><dt>alert</dt><dd>{data.alertMode === 'real' ? '真实发送' : '仅 dry-run'}</dd></div>
          </dl>
        </div>
      </section>
    </div>
  );
}

function useSearchFilter<T>(items: T[], query: string, fields: (item: T) => Array<string | undefined>) {
  return useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((item) => fields(item).filter(Boolean).join(' ').toLowerCase().includes(q));
  }, [items, query, fields]);
}

function EventFilterControl({
  value,
  onChange,
  counts
}: {
  value: EventFilter;
  onChange: (value: EventFilter) => void;
  counts: Record<EventFilter, number>;
}) {
  return (
    <div className="event-filter" role="group" aria-label="事件可疑状态筛选" data-od-id="event-filter">
      {eventFilters.map((item) => (
        <button
          key={item.value}
          type="button"
          className={value === item.value ? 'filter-chip active' : 'filter-chip'}
          aria-pressed={value === item.value}
          onClick={() => onChange(item.value)}
        >
          <span>{item.label}</span>
          <span className="chip-count">{counts[item.value]}</span>
        </button>
      ))}
    </div>
  );
}

function EventsView({
  events,
  query,
  range,
  eventFilter,
  setEventFilter
}: {
  events: AuditEvent[];
  query: string;
  range: TimeRange;
  eventFilter: EventFilter;
  setEventFilter: (value: EventFilter) => void;
}) {
  const q = query.trim().toLowerCase();
  const searchMatched = useMemo(() => {
    if (!q) return events;
    return events.filter((event) =>
      [event.source, event.action, event.outcome, event.actor, event.scope, event.resource, event.correlationId]
        .join(' ')
        .toLowerCase()
        .includes(q)
    );
  }, [events, q]);
  const timeMatched = useMemo(
    () => searchMatched.filter((event) => inTimeRange(event.timestamp, range)),
    [searchMatched, range]
  );
  const counts = useMemo<Record<EventFilter, number>>(
    () => ({
      all: timeMatched.length,
      suspect: timeMatched.filter((event) => event.suspicious).length,
      normal: timeMatched.filter((event) => !event.suspicious).length
    }),
    [timeMatched]
  );
  const filtered = useMemo(() => {
    if (eventFilter === 'suspect') return timeMatched.filter((event) => event.suspicious);
    if (eventFilter === 'normal') return timeMatched.filter((event) => !event.suspicious);
    return timeMatched;
  }, [timeMatched, eventFilter]);
  const latestEvent = events[0] || null;
  const visibleLatest = latestEvent ? filtered.some((event) => event.id === latestEvent.id) : false;

  const filterControl = (
    <>
      <EventSummary
        latest={latestEvent}
        total={events.length}
        timeMatched={timeMatched.length}
        visible={filtered.length}
        visibleLatest={visibleLatest}
        eventFilter={eventFilter}
        range={range}
      />
      <EventFilterControl value={eventFilter} onChange={setEventFilter} counts={counts} />
    </>
  );

  if (!filtered.length) {
    if (timeMatched.length) {
      return (
        <>
          {filterControl}
          <EmptyState
            title={eventFilter === 'suspect' ? '当前结果中无可疑事件' : '当前结果中无正常事件'}
            detail="搜索词和时间范围已有匹配事件，切换可疑状态筛选即可查看其他事件。"
          />
        </>
      );
    }
    if (searchMatched.length) {
      return (
        <>
          {filterControl}
          <EmptyState
            title="当前时间范围内无事件"
            detail={`有 ${searchMatched.length} 条事件落在所选时间范围之外，切换到更大的范围（如“全部”）即可查看。`}
          />
        </>
      );
    }
    return (
      <>
        {filterControl}
        <EmptyState title="没有匹配事件" detail="调整搜索词，或等待 audit-watcher 写入最近 24 小时 Aevatar 缓存。" />
      </>
    );
  }

  return (
    <>
      {filterControl}
      <section className="panel table-panel" aria-label="审计事件" data-od-id="events-view">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>时间</th>
                <th>来源</th>
                <th>action / outcome</th>
                <th>actor</th>
                <th>scope</th>
                <th>resource</th>
                <th>correlation id</th>
                <th>可疑</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((event) => (
                <tr key={event.id}>
                  <td data-label="时间">{formatDateTime(event.timestamp)}</td>
                  <td data-label="来源">
                    <Badge tone={event.source === 'aevatar' ? 'info' : 'neutral'}>{event.source}</Badge>
                  </td>
                  <td data-label="action / outcome">
                    <span className="mono">{event.action}</span>
                    <span className="muted"> / {event.outcome}</span>
                  </td>
                  <td data-label="actor">{event.actor}</td>
                  <td data-label="scope"><span className="compact">{event.scope}</span></td>
                  <td data-label="resource"><span className="compact">{event.resource}</span></td>
                  <td data-label="correlation id"><span className="mono compact">{event.correlationId}</span></td>
                  <td data-label="可疑">
                    {event.suspicious ? <Badge tone="warning">suspect</Badge> : <Badge>normal</Badge>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

function EventSummary({
  latest,
  total,
  timeMatched,
  visible,
  visibleLatest,
  eventFilter,
  range
}: {
  latest: AuditEvent | null;
  total: number;
  timeMatched: number;
  visible: number;
  visibleLatest: boolean;
  eventFilter: EventFilter;
  range: TimeRange;
}) {
  return (
    <section className="event-summary" aria-label="审计事件摘要" data-od-id="event-summary">
      <div>
        <span className="summary-label">最新事件</span>
        <strong>{latest ? formatDateTime(latest.timestamp) : '无记录'}</strong>
      </div>
      <div>
        <span className="summary-label">当前展示</span>
        <strong>{visible}</strong>
        <span className="summary-subtle"> / {timeMatched} / {total}</span>
      </div>
      <div>
        <span className="summary-label">筛选</span>
        <strong>{eventFilter}</strong>
        <span className="summary-subtle"> · {range}</span>
      </div>
      <div>
        <span className="summary-label">最新状态</span>
        {latest ? (
          <>
            <Badge tone={latest.suspicious ? 'warning' : 'neutral'}>
              {latest.suspicious ? 'suspect' : 'normal'}
            </Badge>
            {!visibleLatest ? <span className="summary-subtle">不在当前筛选</span> : null}
          </>
        ) : (
          <strong>无记录</strong>
        )}
      </div>
    </section>
  );
}

function FindingsView({ findings, query }: { findings: Finding[]; query: string }) {
  const filtered = useSearchFilter(findings, query, (finding) => [
    finding.batchId,
    finding.severity,
    finding.category,
    finding.summary,
    finding.evidence,
    finding.recommendedAction
  ]);

  if (!filtered.length) {
    return <EmptyState title="没有匹配 finding" detail="等待 audit-analyzer 产出；若 analyzer 持续失败（如 codex 不可用），这里会出现一条 pipeline_health 发现。" />;
  }

  return (
    <section className="finding-list" aria-label="批次与发现" data-od-id="findings-view">
      {filtered.map((finding) => (
        <article className="finding-card" key={finding.id} data-severity={finding.severity} data-od-id={`finding-${finding.id}`}>
          <div className="finding-main">
            <div className="finding-head">
              <Badge tone={severityTone(finding.severity)}>{finding.severity}</Badge>
              <span className="mono compact">{finding.batchId}</span>
              {finding.cached ? <Badge>cached</Badge> : null}
            </div>
            <h2>{finding.summary}</h2>
            <p>{finding.evidence}</p>
          </div>
          <div className="finding-side">
            <span className="tile-label">category</span>
            <strong>{finding.category}</strong>
            <span className="tile-label">recommended action</span>
            <p>{finding.recommendedAction}</p>
          </div>
        </article>
      ))}
    </section>
  );
}

function AlertsView({ alerts, query, range }: { alerts: AlertRecord[]; query: string; range: TimeRange }) {
  const q = query.trim().toLowerCase();
  const searchMatched = useMemo(() => {
    if (!q) return alerts;
    return alerts.filter((alert) =>
      [alert.severity, alert.category, alert.dedupKey, alert.dedupStatus, alert.mode, alert.delivery, alert.summary]
        .join(' ')
        .toLowerCase()
        .includes(q)
    );
  }, [alerts, q]);
  const filtered = useMemo(
    () => searchMatched.filter((alert) => inTimeRange(alert.timestamp, range)),
    [searchMatched, range]
  );

  if (!filtered.length) {
    if (searchMatched.length) {
      return (
        <EmptyState
          title="当前时间范围内无告警"
          detail={`有 ${searchMatched.length} 条告警落在所选时间范围之外，切换到更大的范围（如“全部”）即可查看。`}
        />
      );
    }
    return <EmptyState title="没有匹配告警" detail="dry-run 模式会记录请求但不发送 webhook；相同 dedup_key 的重复项已折叠。" />;
  }

  return (
    <section className="panel table-panel" aria-label="告警" data-od-id="alerts-view">
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>severity</th>
              <th>category</th>
              <th>dedup</th>
              <th>mode</th>
              <th>delivery</th>
              <th>summary</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((alert) => (
              <tr key={alert.id} data-severity={alert.severity}>
                <td data-label="时间">
                  {formatDateTime(alert.timestamp)}
                  {alert.count && alert.count > 1 ? <Badge title="相同 dedup_key 的出现次数">×{alert.count}</Badge> : null}
                </td>
                <td data-label="severity"><Badge tone={severityTone(alert.severity)}>{alert.severity}</Badge></td>
                <td data-label="category">{alert.category}</td>
                <td data-label="dedup">
                  <span className="mono compact">{alert.dedupKey}</span>
                  <Badge tone={alert.dedupStatus === 'duplicate' ? 'warning' : 'neutral'}>{alert.dedupStatus}</Badge>
                </td>
                <td data-label="mode"><Badge tone={alert.mode === 'real' ? 'danger' : 'info'}>{alert.mode}</Badge></td>
                <td data-label="delivery">{alert.delivery}</td>
                <td data-label="summary">
                  {alert.summary}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// 中文信号名 for display; the raw slug stays visible as the machine name.
const signalNames: Record<string, string> = {
  'recurring-failure': '反复失败',
  'error-spike': '错误激增',
  flapping: '状态抖动',
  'pipeline-dead-letter': '管线死信'
};

function signalName(signal: string) {
  return signalNames[signal] || signal;
}

function incidentStateTone(state: string): Tone {
  if (state === 'open') return 'danger';
  if (state === 'recovering') return 'warning';
  if (state === 'closed') return 'success';
  if (state === 'candidate') return 'info';
  return 'neutral';
}

// Reuse the existing severity accents: an open incident deserves the danger
// edge, a recovering one the warning edge; candidate/closed stay plain.
function incidentEdgeSeverity(state: string): string | undefined {
  if (state === 'open') return 'critical';
  if (state === 'recovering') return 'high';
  return undefined;
}

function issueActionBadge(action: IssueAction) {
  if (action.action === 'outbound') {
    return action.mode === 'dry-run'
      ? <Badge tone="info" title="dry-run：仅记录，未真实提单">演练</Badge>
      : <Badge tone="danger" title="真实外发到 GitHub">外发</Badge>;
  }
  if (action.action === 'filed') return <Badge tone="success">已提单</Badge>;
  if (action.action === 'skip') return <Badge>跳过</Badge>;
  if (action.action === 'probe') return <Badge tone="info">探测</Badge>;
  return <Badge tone="warning">预算耗尽</Badge>;
}

function issueActionDetail(action: IssueAction) {
  if (action.action === 'filed' && action.url) {
    return (
      <a href={action.url} target="_blank" rel="noreferrer" className="mono">
        {action.number != null ? `#${action.number}` : action.url}
      </a>
    );
  }
  if (action.action === 'outbound') {
    return (
      <>
        {action.severity ? <Badge tone={severityTone(action.severity)}>{action.severity}</Badge> : null}
        <span className="compact"> {action.title}</span>
      </>
    );
  }
  if (action.action === 'skip') {
    return <Badge tone="warning" title="跳过原因">{action.reason}</Badge>;
  }
  if (action.action === 'probe') {
    return (
      <>
        <Badge tone={action.ok ? 'success' : 'danger'}>{action.ok ? 'ok' : 'fail'}</Badge>
        {action.detail ? <span className="muted"> {action.detail}</span> : null}
      </>
    );
  }
  return <span className="mono">{action.used} / {action.cap}</span>;
}

function StabilityView({
  incidents,
  actions,
  posture
}: {
  incidents: Incident[];
  actions: IssueAction[];
  posture: IssuePosture;
}) {
  // Calibration signal: what the proxy WOULD have filed with write enabled.
  const rehearsed = wouldHaveFiled(actions).length;
  const empty = incidents.length === 0 && actions.length === 0;

  return (
    <div className="view-stack" data-od-id="stability-view">
      <section className="event-summary" aria-label="提单姿态" data-od-id="issue-posture">
        <div>
          <span className="summary-label">提单模式</span>
          <Badge tone={posture.write ? 'danger' : 'info'}>{posture.write ? '真实提单' : 'dry-run'}</Badge>
          <span className="summary-subtle">
            {posture.write ? '真实创建 GitHub issue' : rehearsed > 0 ? `演练中会提单 ${rehearsed} 次` : '仅记录，不外发'}
          </span>
        </div>
        <div>
          <span className="summary-label">目标仓库</span>
          <strong>{posture.repo}</strong>
          <span className="summary-subtle">via {posture.transport}</span>
        </div>
        <div>
          <span className="summary-label">自动关单</span>
          <Badge tone={posture.autoclose ? 'success' : 'neutral'}>{posture.autoclose ? '开启' : '关闭'}</Badge>
        </div>
        <div>
          <span className="summary-label">稳定性检测</span>
          <Badge tone={posture.detectEnabled ? 'success' : 'warning'}>{posture.detectEnabled ? '开启' : '关闭'}</Badge>
          {!posture.detectEnabled ? <span className="summary-subtle">STABILITY_DETECT_ENABLED=1 后生效</span> : null}
        </div>
      </section>

      {empty ? (
        <EmptyState
          title="尚无稳定性事件"
          detail="stability-sentinel 还没有产出 INCIDENT 状态转换，issue-proxy 也没有提单活动；检测到 recurring-failure / error-spike 等信号后此处自动展示。"
        />
      ) : (
        <>
          {incidents.length ? (
            <section className="finding-list" aria-label="稳定性事件" data-od-id="incidents-view">
              {incidents.map((incident) => (
                <article
                  className="finding-card"
                  key={incident.fp}
                  data-severity={incidentEdgeSeverity(incident.state)}
                  data-od-id={`incident-${incident.fp}`}
                >
                  <div className="finding-main">
                    <div className="finding-head">
                      <Badge tone={incidentStateTone(incident.state)}>{incident.state}</Badge>
                      <Badge title="事件指纹（djb2 校验和）">fp:{incident.fp}</Badge>
                      <span className="mono compact muted">{incident.signal}</span>
                    </div>
                    <h2>{signalName(incident.signal)}</h2>
                    <p>失败 {incident.fails} / 总量 {incident.total} · 覆盖 {incident.bucketsCovered} 个时间桶</p>
                  </div>
                  <div className="finding-side">
                    <span className="tile-label">状态转换</span>
                    <strong>{incident.transitions} 次</strong>
                    <span className="tile-label">最近转换</span>
                    <p>{formatDateTime(incident.lastSeen)}</p>
                  </div>
                </article>
              ))}
            </section>
          ) : (
            <EmptyState title="尚无稳定性事件" detail="stability-sentinel 检测到信号后会在这里出现事件卡片；下方的提单活动可用于校准阈值。" />
          )}

          {actions.length ? (
            <section className="panel table-panel" aria-label="提单活动" data-od-id="issue-activity-view">
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>时间</th>
                      <th>动作</th>
                      <th>kind</th>
                      <th>fp</th>
                      <th>详情</th>
                    </tr>
                  </thead>
                  <tbody>
                    {actions.map((action) => (
                      <tr key={action.id}>
                        <td data-label="时间">{formatDateTime(action.timestamp)}</td>
                        <td data-label="动作">{issueActionBadge(action)}</td>
                        <td data-label="kind"><span className="mono">{action.kind}</span></td>
                        <td data-label="fp"><span className="mono compact">{action.fp || '—'}</span></td>
                        <td data-label="详情">{issueActionDetail(action)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : (
            <EmptyState title="尚无提单活动" detail="issue-proxy 的每次演练 / 提单 / 跳过都会追加一行；dry-run 行用于在开启真实提单前校准检测阈值。" />
          )}
        </>
      )}
    </div>
  );
}

function ConfigView({ data }: { data: DashboardPayload }) {
  return (
    <section className="panel table-panel" aria-label="配置" data-od-id="config-view">
      <div className="config-note">
        <KeyRound size={17} />
        <span>敏感项只显示脱敏摘要；NyxID、webhook、identity key 不会在 UI 中原样展示。</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>变量</th>
              <th>值</th>
              <th>来源</th>
              <th>敏感</th>
            </tr>
          </thead>
          <tbody>
            {data.config.map((item) => (
              <tr key={item.key}>
                <td data-label="变量"><span className="mono">{item.key}</span></td>
                <td data-label="值"><span className="mono compact">{item.value}</span></td>
                <td data-label="来源"><Badge tone={item.source === 'env' ? 'success' : item.source === 'default' ? 'info' : 'neutral'}>{item.source}</Badge></td>
                <td data-label="敏感">{item.sensitive ? <Badge tone="warning">masked</Badge> : <Badge>plain</Badge>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function SourceBanner({ data }: { data: DashboardPayload }) {
  if (data.sourceMode === 'empty') {
    return (
      <div className="source-warning source-empty" role="status" aria-live="polite" data-od-id="source-warning">
        <AlertTriangle size={16} />
        <span>尚未读取到 runtime 数据：在仓库根运行 <code>./boot.sh</code> 启动引擎后，本页会自动切换到实时数据。</span>
      </div>
    );
  }
  return (
    <div className="source-warning source-live" role="status" aria-live="polite" data-od-id="source-warning">
      <CheckCircle2 size={16} />
      <span>正在读取本机 FKST runtime / watch 数据；空闲阶段显示为“待触发”。</span>
    </div>
  );
}

function App() {
  const { data, error, loading, refreshing, reload } = useDashboard();
  const [activeTab, setActiveTab] = useActiveTab();
  const [query, setQuery] = useState('');
  const [range, setRange] = useState<TimeRange>('24h');
  const [eventFilter, setEventFilter] = useState<EventFilter>('all');

  const controls = tabControls[activeTab];
  const jumpTo: RibbonJump = (tab, options) => {
    setActiveTab(tab);
    if (options?.eventFilter) setEventFilter(options.eventFilter);
  };

  return (
    <main className="app-shell" data-od-id="app-shell">
      <Header data={data} busy={loading || refreshing} onRefresh={reload} />
      <nav className="tab-bar" aria-label="监控视图" data-od-id="tab-bar">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            className={activeTab === tab.key ? 'tab active' : 'tab'}
            type="button"
            aria-current={activeTab === tab.key ? 'page' : undefined}
            onClick={() => setActiveTab(tab.key)}
            data-od-id={`tab-${tab.key}`}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </nav>
      {data ? <AttentionCallout data={data} onJump={setActiveTab} /> : null}
      {data ? <StatusRibbon data={data} onJump={jumpTo} /> : null}
      <Toolbar
        query={query}
        setQuery={setQuery}
        range={range}
        setRange={setRange}
        showSearch={controls.search}
        showRange={controls.range}
      />
      {error ? (
        <div className="error-panel" role="alert" aria-live="assertive" data-od-id="error-panel">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      ) : null}
      {!data && !error ? (
        <div className="loading-panel" role="status" aria-live="polite" data-od-id="loading-panel">
          <RefreshCw size={18} className="spin" />
          <span>读取本地 runtime 与 watch 日志...</span>
        </div>
      ) : null}
      {data ? (
        <>
          {data.sourceMode !== 'live' ? <SourceBanner data={data} /> : null}
          {activeTab === 'pipeline' ? <PipelineView data={data} /> : null}
          {activeTab === 'events' ? (
            <EventsView
              events={data.events}
              query={query}
              range={range}
              eventFilter={eventFilter}
              setEventFilter={setEventFilter}
            />
          ) : null}
          {activeTab === 'findings' ? <FindingsView findings={data.findings} query={query} /> : null}
          {activeTab === 'alerts' ? <AlertsView alerts={data.alerts} query={query} range={range} /> : null}
          {activeTab === 'config' ? <ConfigView data={data} /> : null}
          {activeTab === 'stability' ? (
            // A dev-server hot reload can briefly pair the new UI with an
            // older adapter whose payload lacks these fields; degrade to the
            // honest empty view instead of white-screening the whole app.
            <StabilityView
              incidents={data.incidents ?? []}
              actions={data.issueActions ?? []}
              posture={data.issuePosture ?? { write: false, repo: '未知（adapter 需重启）', transport: 'gh', autoclose: true, detectEnabled: false }}
            />
          ) : null}
        </>
      ) : null}
    </main>
  );
}

createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
