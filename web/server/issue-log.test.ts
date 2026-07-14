import assert from 'node:assert/strict';
import test from 'node:test';
import {
  issueActivity,
  latestIncidentsByFp,
  parseIncidentLine,
  parseIssueLine,
  wouldHaveFiled,
  type IncidentEntry,
  type IssueEntry,
  type IssueLine
} from './issue-log.js';

test('ISSUE_OUTBOUND parses inside the framework wrapper, quoted Chinese title intact', () => {
  const line =
    "TIMESTAMP=2026-07-12T08:00:00Z LEVEL=info MSG=issue-proxy dept=file ISSUE_OUTBOUND mode=dry-run kind=open fp=1a2b3c4d severity=high signal=recurring-failure title='[fkst-stability] 反复失败: audit-analyzer.analyze (fp:1a2b3c4d)'";
  assert.deepEqual(parseIssueLine(line), {
    type: 'outbound',
    mode: 'dry-run',
    kind: 'open',
    fp: '1a2b3c4d',
    severity: 'high',
    signal: 'recurring-failure',
    title: '[fkst-stability] 反复失败: audit-analyzer.analyze (fp:1a2b3c4d)'
  });
});

test('ISSUE_FILED parses number and url', () => {
  const line = 'ISSUE_FILED kind=comment fp=deadbeef number=42 url=https://github.com/eanz17/fkst-audit-log/issues/42';
  assert.deepEqual(parseIssueLine(line), {
    type: 'filed',
    kind: 'comment',
    fp: 'deadbeef',
    number: 42,
    url: 'https://github.com/eanz17/fkst-audit-log/issues/42'
  });
});

test('ISSUE_SKIP keeps hyphenated reasons whole', () => {
  assert.deepEqual(parseIssueLine('ISSUE_SKIP kind=open fp=0badcafe reason=open-issue-adopted'), {
    type: 'skip',
    kind: 'open',
    fp: '0badcafe',
    reason: 'open-issue-adopted'
  });
  assert.deepEqual(parseIssueLine('ISSUE_SKIP kind=close fp=0badcafe reason=autoclose-disabled'), {
    type: 'skip',
    kind: 'close',
    fp: '0badcafe',
    reason: 'autoclose-disabled'
  });
});

test('ISSUE_PROBE takes the whole tail as detail, including spaces', () => {
  assert.deepEqual(parseIssueLine('ISSUE_PROBE kind=auth ok=1 detail=gh auth status ok'), {
    type: 'probe',
    kind: 'auth',
    ok: true,
    detail: 'gh auth status ok'
  });
  assert.deepEqual(parseIssueLine('ISSUE_PROBE kind=auth ok=0 detail='), {
    type: 'probe',
    kind: 'auth',
    ok: false,
    detail: ''
  });
});

test('ISSUE_BUDGET_EXCEEDED parses scope and counters', () => {
  assert.deepEqual(parseIssueLine('ISSUE_BUDGET_EXCEEDED scope=day used=5 cap=5'), {
    type: 'budget',
    scope: 'day',
    used: 5,
    cap: 5
  });
  assert.deepEqual(parseIssueLine('ISSUE_BUDGET_EXCEEDED scope=open used=10 cap=10'), {
    type: 'budget',
    scope: 'open',
    used: 10,
    cap: 10
  });
});

test('malformed issue lines return null and never throw', () => {
  const malformed = [
    '',
    'EXIT=0',
    'LEVEL=info MSG=issue-proxy dept=file nothing to see',
    // missing / invalid required fields
    'ISSUE_OUTBOUND mode=dry-run kind=open',
    "ISSUE_OUTBOUND mode=dry-run kind=reopen fp=1a2b3c4d severity=high signal=flapping title='x'",
    "ISSUE_OUTBOUND mode=dry-run kind=open fp=1a2b3c4d severity=urgent signal=flapping title='x'",
    'ISSUE_FILED kind=open fp=XYZ12345 number=1 url=https://example.com', // fp not lowercase hex
    'ISSUE_FILED kind=open fp=1a2b3c4 number=1 url=https://example.com', // fp too short
    'ISSUE_FILED kind=open fp=1a2b3c4d number=abc url=https://example.com',
    'ISSUE_FILED kind=open fp=1a2b3c4d number=1',
    'ISSUE_SKIP kind=open fp=1a2b3c4d',
    'ISSUE_PROBE kind=auth ok=2 detail=x',
    'ISSUE_BUDGET_EXCEEDED scope=week used=1 cap=5',
    'ISSUE_BUDGET_EXCEEDED scope=day used= cap=5'
  ];
  for (const line of malformed) {
    assert.equal(parseIssueLine(line), null, `expected null for: ${line}`);
  }
});

test('INCIDENT parses states, counts, and the covered-bucket suffix', () => {
  const line =
    'TIMESTAMP=2026-07-12T08:30:00Z LEVEL=info MSG=stability-sentinel dept=detect INCIDENT fp=deadbeef signal=error-spike state=candidate->open fails=7 total=12 buckets=6-covered';
  assert.deepEqual(parseIncidentLine(line), {
    fp: 'deadbeef',
    signal: 'error-spike',
    fromState: 'candidate',
    toState: 'open',
    fails: 7,
    total: 12,
    bucketsCovered: 6
  });
  // A bare bucket count (no -covered suffix) still parses.
  assert.equal(
    parseIncidentLine('INCIDENT fp=deadbeef signal=flapping state=open->recovering fails=3 total=9 buckets=8')?.bucketsCovered,
    8
  );
});

test('malformed INCIDENT lines return null and never throw', () => {
  const malformed = [
    '',
    'INCIDENT',
    'INCIDENT fp=deadbeef signal=error-spike state=open fails=1 total=2 buckets=3', // no transition arrow
    'INCIDENT fp=deadbeef signal=error-spike state=->open fails=1 total=2 buckets=3',
    'INCIDENT fp=nothexoo signal=error-spike state=candidate->open fails=1 total=2 buckets=3',
    'INCIDENT fp=deadbeef state=candidate->open fails=1 total=2 buckets=3',
    'INCIDENT fp=deadbeef signal=error-spike state=candidate->open fails=x total=2 buckets=3',
    'INCIDENT fp=deadbeef signal=error-spike state=candidate->open fails=1 total=2 buckets=covered',
    'a stray INCIDENT word in prose does not parse'
  ];
  for (const line of malformed) {
    assert.equal(parseIncidentLine(line), null, `expected null for: ${line}`);
  }
});

test('latestIncidentsByFp keeps one row per fp with the last state and full history count', () => {
  const entry = (fp: string, toState: string, timestamp: string, fails: number): IncidentEntry => ({
    fp,
    signal: 'recurring-failure',
    fromState: 'x',
    toState,
    fails,
    total: fails * 2,
    bucketsCovered: 6,
    timestamp
  });
  const rows = latestIncidentsByFp([
    entry('1a2b3c4d', 'candidate', '2026-07-12T08:00:00.000Z', 5),
    entry('deadbeef', 'candidate', '2026-07-12T08:10:00.000Z', 6),
    entry('1a2b3c4d', 'open', '2026-07-12T08:30:00.000Z', 9),
    entry('1a2b3c4d', 'recovering', '2026-07-12T09:00:00.000Z', 2)
  ]);
  assert.equal(rows.length, 2);
  // Newest lastSeen first.
  assert.equal(rows[0].fp, '1a2b3c4d');
  assert.equal(rows[0].state, 'recovering');
  assert.equal(rows[0].fails, 2);
  assert.equal(rows[0].total, 4);
  assert.equal(rows[0].transitions, 3);
  assert.equal(rows[0].lastSeen, '2026-07-12T09:00:00.000Z');
  assert.equal(rows[1].fp, 'deadbeef');
  assert.equal(rows[1].transitions, 1);
});

test('issueActivity flattens mixed lines in input order', () => {
  const at = (line: IssueLine, timestamp: string): IssueEntry => ({ line, timestamp });
  const actions = issueActivity([
    at({ type: 'probe', kind: 'auth', ok: true, detail: 'ok' }, '2026-07-12T08:00:00.000Z'),
    at(
      { type: 'outbound', mode: 'dry-run', kind: 'open', fp: '1a2b3c4d', severity: 'high', signal: 'flapping', title: 't' },
      '2026-07-12T08:01:00.000Z'
    ),
    at({ type: 'filed', kind: 'open', fp: '1a2b3c4d', number: 7, url: 'https://example.com/7' }, '2026-07-12T08:02:00.000Z'),
    at({ type: 'skip', kind: 'open', fp: '1a2b3c4d', reason: 'muted' }, '2026-07-12T08:03:00.000Z'),
    at({ type: 'budget', scope: 'day', used: 5, cap: 5 }, '2026-07-12T08:04:00.000Z')
  ]);
  assert.deepEqual(
    actions.map((action) => action.action),
    ['probe', 'outbound', 'filed', 'skip', 'budget']
  );
  assert.equal(actions[1].mode, 'dry-run');
  assert.equal(actions[1].signal, 'flapping');
  assert.equal(actions[2].number, 7);
  assert.equal(actions[2].url, 'https://example.com/7');
  assert.equal(actions[3].reason, 'muted');
  assert.equal(actions[4].kind, 'day');
  assert.equal(actions[4].used, 5);
  // Ids stay unique for React keys even with identical timestamps.
  assert.equal(new Set(actions.map((action) => action.id)).size, actions.length);
});

test('wouldHaveFiled selects only dry-run OUTBOUND rows', () => {
  const actions = issueActivity([
    {
      line: { type: 'outbound', mode: 'dry-run', kind: 'open', fp: '1a2b3c4d', severity: 'high', signal: 'flapping', title: 'a' },
      timestamp: '2026-07-12T08:00:00.000Z'
    },
    {
      line: { type: 'outbound', mode: 'real', kind: 'open', fp: 'deadbeef', severity: 'critical', signal: 'error-spike', title: 'b' },
      timestamp: '2026-07-12T08:01:00.000Z'
    },
    {
      line: { type: 'filed', kind: 'open', fp: 'deadbeef', number: 8, url: 'https://example.com/8' },
      timestamp: '2026-07-12T08:02:00.000Z'
    }
  ]);
  const dryRun = wouldHaveFiled(actions);
  assert.equal(dryRun.length, 1);
  assert.equal(dryRun[0].fp, '1a2b3c4d');
  assert.equal(dryRun[0].mode, 'dry-run');
});
