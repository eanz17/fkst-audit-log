import assert from 'node:assert/strict';
import test from 'node:test';
import { cacheValueIsFresh, deadLetterBatchId, runtimeLogFailed } from './runtime-health.js';

test('successful analyzer logs are healthy despite timeout config and failure words', () => {
  const text = [
    'SPAWN: log=/tmp/codex.log cd=. timeout=600',
    'LEVEL=info MSG=audit-analyzer dept=analyze action=scheduled.dispatch.fire.failed findings=1 alerts=0',
    'EXIT=0',
    'ELAPSED_MS=19410'
  ].join('\n');
  assert.equal(runtimeLogFailed('audit-analyzer.analyze-1.log', text), false);
});

test('nonzero terminal exit and framework failure are errors', () => {
  assert.equal(runtimeLogFailed('audit-analyzer.analyze-1.log', 'EXIT=1\nELAPSED_MS=4'), true);
  assert.equal(
    runtimeLogFailed('audit-analyzer.analyze-2.log', '[framework] pipeline failed: runtime error'),
    true
  );
});

test('handled dead letters still mark pipeline health as error', () => {
  const text = 'LEVEL=error MSG=audit-analyzer dept=dead_letter tag=DEAD_LETTER\nEXIT=0';
  assert.equal(runtimeLogFailed('audit-analyzer.dead_letter-1.log', text), true);
});

test('an in-progress child is not failed merely because a timeout is configured', () => {
  assert.equal(runtimeLogFailed('audit-analyzer.analyze-1.log', 'SPAWN: timeout=600'), false);
  assert.equal(runtimeLogFailed('audit-analyzer.analyze-1.log', 'TIMED_OUT=true'), true);
});

test('dead letter delivery ids recover the original analyzer batch id', () => {
  const text = [
    'tag=DEAD_LETTER',
    'DELIVERY=delivery/v3/raised/queue/audit-watcher.audit_batch/dept/audit-analyzer.analyze/dedup/audit-batch_2F_aevatar_5F__5F_api-123-1'
  ].join(' ');
  assert.equal(deadLetterBatchId(text), 'aevatar__api-123-1');
  assert.equal(deadLetterBatchId('DELIVERY=delivery/v1/no-dedup'), null);
});

test('cache freshness uses the runtime nanosecond expiry header', () => {
  const nowMs = 1_000;
  assert.equal(cacheValueIsFresh('fkst-cache-v1 expires_at=1000000001\n[]', nowMs), true);
  assert.equal(cacheValueIsFresh('fkst-cache-v1 expires_at=1000000000\n[]', nowMs), false);
  assert.equal(cacheValueIsFresh('[]', nowMs), false);
});
