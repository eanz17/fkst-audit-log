import assert from 'node:assert/strict';
import test from 'node:test';
import { aevatarRiskReason, isAevatarRecordSuspicious } from './aevatar-risk.js';

test('normal reads and attempt records remain normal', () => {
  assert.equal(aevatarRiskReason('workflow.run.started', 'Success'), null);
  assert.equal(aevatarRiskReason('workflow.observatory.get-run', 'Accepted'), null);
  assert.equal(aevatarRiskReason('service.policy.updated.attempted', 'Accepted'), null);
});

test('negative outcomes are suspicious', () => {
  for (const outcome of ['Denied', 'Error', 'Cancelled', 'Unspecified']) {
    assert.equal(isAevatarRecordSuspicious('workflow.run.started', outcome), true);
  }
  assert.equal(aevatarRiskReason('workflow.run.started', ''), 'missing-outcome');
});

test('failed domain facts remain suspicious when artifact outcome is success', () => {
  assert.equal(
    aevatarRiskReason('scheduled.skill-runner.execution.failed', 'Success'),
    'failure-action'
  );
  assert.equal(
    aevatarRiskReason('scheduled.skill-runner.external-trigger.rejected', 'Success'),
    'failure-action'
  );
});

test('successful high-impact changes are selected for review', () => {
  for (const action of [
    'service.policy.updated',
    'identity.oauth-client.hmac-key.rotated',
    'service.binding.created',
    'studio.team.entry-member.changed',
    'service.revision.published'
  ]) {
    assert.equal(aevatarRiskReason(action, 'Success'), 'high-impact-action');
  }
});
