// Pure parsers for the stability surface. stability-sentinel's detect
// department and issue-proxy's file department emit single-line key=value
// records (SHARED CONTRACT v1); this module turns those lines into typed rows
// and collapses them for the dashboard. No fs access here — the adapter feeds
// log tails in and the node:test suite feeds fixtures.

export type IssueKind = 'open' | 'comment' | 'close';
export type IssueSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface IssueOutboundLine {
  type: 'outbound';
  mode: string;
  kind: IssueKind;
  fp: string;
  severity: IssueSeverity;
  signal: string;
  title: string;
}

export interface IssueFiledLine {
  type: 'filed';
  kind: IssueKind;
  fp: string;
  number: number;
  url: string;
}

export interface IssueSkipLine {
  type: 'skip';
  kind: IssueKind;
  fp: string;
  reason: string;
}

export interface IssueProbeLine {
  type: 'probe';
  kind: string;
  ok: boolean;
  detail: string;
}

export interface IssueBudgetLine {
  type: 'budget';
  scope: 'day' | 'open';
  used: number;
  cap: number;
}

export type IssueLine = IssueOutboundLine | IssueFiledLine | IssueSkipLine | IssueProbeLine | IssueBudgetLine;

export interface IncidentLine {
  fp: string;
  signal: string;
  fromState: string;
  toState: string;
  fails: number;
  total: number;
  bucketsCovered: number;
}

// One INCIDENT transition plus the timestamp the adapter derived for its line
// (child logs carry no per-line time in these records, so this is the log
// file's name-encoded timestamp; intra-file order is the tiebreak).
export interface IncidentEntry extends IncidentLine {
  timestamp: string;
}

// Collapsed view: one row per fingerprint with the latest transition's fields.
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

export interface IssueEntry {
  line: IssueLine;
  timestamp: string;
}

// Flat action row for the 提单活动 list. `kind` carries the issue kind for
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

const issueMarker = /\b(ISSUE_OUTBOUND|ISSUE_FILED|ISSUE_SKIP|ISSUE_PROBE|ISSUE_BUDGET_EXCEEDED)\b/;
const incidentMarker = /\bINCIDENT\b/;

function isIssueKind(value: string | undefined): value is IssueKind {
  return value === 'open' || value === 'comment' || value === 'close';
}

function isSeverity(value: string | undefined): value is IssueSeverity {
  return value === 'low' || value === 'medium' || value === 'high' || value === 'critical';
}

// Fingerprints are the sentinel's 8-char lowercase-hex djb2 checksum; anything
// else on that field means the line is not ours (or is corrupted mid-write).
function isFingerprint(value: string | undefined): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}$/.test(value);
}

function toInt(value: string | undefined): number | null {
  if (value === undefined || !/^-?\d+$/.test(value)) return null;
  return Number(value);
}

// key=value tokenizer for the tail after a recognized marker. Values are
// either bare (run to the next space) or single-quoted (titles contain spaces
// and Chinese; the Lua side never puts a quote inside the redacted title, so
// the quoted value runs to the next closing quote). Object.create(null) keeps
// hostile keys like __proto__ from touching the prototype.
function parseFields(rest: string): Record<string, string> {
  const fields: Record<string, string> = Object.create(null);
  const token = /([A-Za-z_][A-Za-z0-9_]*)=(?:'([^']*)'|([^\s]*))/g;
  for (const match of rest.matchAll(token)) {
    fields[match[1]] = match[2] ?? match[3] ?? '';
  }
  return fields;
}

// Parse one issue-proxy file-department line. The marker may sit anywhere in
// the framework's `TIMESTAMP=... LEVEL=info MSG=... <marker> ...` wrapper.
// Malformed lines return null; this must never throw on arbitrary log text.
export function parseIssueLine(line: string): IssueLine | null {
  if (typeof line !== 'string' || !line) return null;
  const marker = line.match(issueMarker);
  if (!marker || marker.index === undefined) return null;
  const rest = line.slice(marker.index + marker[1].length);
  const fields = parseFields(rest);

  if (marker[1] === 'ISSUE_OUTBOUND') {
    const { mode, kind, fp, severity, signal, title } = fields;
    if (!mode || !isIssueKind(kind) || !isFingerprint(fp) || !isSeverity(severity) || !signal || title === undefined) {
      return null;
    }
    return { type: 'outbound', mode, kind, fp, severity, signal, title };
  }

  if (marker[1] === 'ISSUE_FILED') {
    const { kind, fp, url } = fields;
    const number = toInt(fields.number);
    if (!isIssueKind(kind) || !isFingerprint(fp) || number === null || !url) return null;
    return { type: 'filed', kind, fp, number, url };
  }

  if (marker[1] === 'ISSUE_SKIP') {
    const { kind, fp, reason } = fields;
    if (!isIssueKind(kind) || !isFingerprint(fp) || !reason) return null;
    return { type: 'skip', kind, fp, reason };
  }

  if (marker[1] === 'ISSUE_PROBE') {
    const { kind, ok } = fields;
    if (!kind || (ok !== '0' && ok !== '1')) return null;
    // detail is the last field and may contain spaces — take the raw tail.
    const detail = rest.match(/\bdetail=(.*)$/)?.[1]?.trim() ?? '';
    return { type: 'probe', kind, ok: ok === '1', detail };
  }

  // ISSUE_BUDGET_EXCEEDED
  const { scope } = fields;
  const used = toInt(fields.used);
  const cap = toInt(fields.cap);
  if ((scope !== 'day' && scope !== 'open') || used === null || cap === null) return null;
  return { type: 'budget', scope, used, cap };
}

// Parse one stability-sentinel detect-department transition line:
//   INCIDENT fp=<hex> signal=<sig> state=<from>-><to> fails=<n> total=<n> buckets=<n-covered>
// `buckets` carries the covered-bucket count with an optional "-covered"
// suffix; only the leading integer matters here.
export function parseIncidentLine(line: string): IncidentLine | null {
  if (typeof line !== 'string' || !line) return null;
  const marker = line.match(incidentMarker);
  if (!marker || marker.index === undefined) return null;
  const fields = parseFields(line.slice(marker.index + 'INCIDENT'.length));

  const { fp, signal, state } = fields;
  const fails = toInt(fields.fails);
  const total = toInt(fields.total);
  const buckets = fields.buckets?.match(/^(\d+)/)?.[1];
  if (!isFingerprint(fp) || !signal || !state || fails === null || total === null || buckets === undefined) {
    return null;
  }
  const arrow = state.indexOf('->');
  if (arrow <= 0 || arrow + 2 >= state.length) return null;
  return {
    fp,
    signal,
    fromState: state.slice(0, arrow),
    toState: state.slice(arrow + 2),
    fails,
    total,
    bucketsCovered: Number(buckets)
  };
}

// One row per fingerprint. Entries must arrive oldest-first (the adapter
// replays log files by mtime, lines in file order) so the last transition per
// fp wins; the transition count is the incident's full history length. Rows
// come back newest-first for display.
export function latestIncidentsByFp(entries: IncidentEntry[]): Incident[] {
  const byFp = new Map<string, Incident>();
  for (const entry of entries) {
    byFp.set(entry.fp, {
      fp: entry.fp,
      signal: entry.signal,
      state: entry.toState,
      fails: entry.fails,
      total: entry.total,
      bucketsCovered: entry.bucketsCovered,
      transitions: (byFp.get(entry.fp)?.transitions ?? 0) + 1,
      lastSeen: entry.timestamp
    });
  }
  return Array.from(byFp.values()).sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
}

// Flatten parsed issue lines into chronological action rows (same order as
// the input; the adapter feeds oldest-first and reverses for display).
export function issueActivity(entries: IssueEntry[]): IssueAction[] {
  return entries.map(({ line, timestamp }, index) => {
    const id = `issue-${index}-${timestamp}`;
    switch (line.type) {
      case 'outbound':
        return {
          id,
          timestamp,
          action: 'outbound' as const,
          kind: line.kind,
          mode: line.mode,
          fp: line.fp,
          severity: line.severity,
          signal: line.signal,
          title: line.title
        };
      case 'filed':
        return { id, timestamp, action: 'filed' as const, kind: line.kind, fp: line.fp, number: line.number, url: line.url };
      case 'skip':
        return { id, timestamp, action: 'skip' as const, kind: line.kind, fp: line.fp, reason: line.reason };
      case 'probe':
        return { id, timestamp, action: 'probe' as const, kind: line.kind, ok: line.ok, detail: line.detail };
      case 'budget':
        return { id, timestamp, action: 'budget' as const, kind: line.scope, used: line.used, cap: line.cap };
    }
  });
}

// Calibration selector: the dry-run OUTBOUND rows are exactly what the proxy
// WOULD have filed with FKST_ISSUE_WRITE=1 — the operator tunes sentinel
// thresholds against this list before flipping the switch.
export function wouldHaveFiled(actions: IssueAction[]): IssueAction[] {
  return actions.filter((action) => action.action === 'outbound' && action.mode === 'dry-run');
}
