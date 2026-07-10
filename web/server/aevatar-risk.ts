const normalOutcomes = new Set(['accepted', 'success', 'succeeded']);

const failureActionPatterns = [
  /\.failed$/,
  /\.rejected$/,
  /\.denied$/,
  /\.error$/,
  /\.cancelled$/
];

// Keep this list aligned with packages/audit-watcher/core.lua. The public
// audit DTO omits sensitivity_level and is_destructive, so stable action names
// are the only available signal for successful control-plane mutations.
const reviewActionPatterns = [
  /\.deleted$/,
  /\.retired$/,
  /\.revoked$/,
  /\.unregistered$/,
  /\.tombstoned$/,
  /\.cleared$/,
  /\.archived$/,
  /\.deactivated$/,
  /\.disabled$/,
  /\.rollback\.requested$/,
  /\.rolled[-_]back$/,
  /policy/,
  /permission/,
  /credential/,
  /secret/,
  /^identity\.binding\./,
  /^identity\.external-binding\./,
  /^identity\.oauth-client\./,
  /^service\.binding\./,
  /^service\.endpoint_catalog\./,
  /^service\.configuration\.imported$/,
  /^service\.default-serving\.changed$/,
  /^service\.serving_set\.updated$/,
  /^service\.deployment\.activated$/,
  /^service\.revision\.published$/,
  /^script\.catalog\.revision\.promoted$/,
  /^script\.definition\.upserted$/,
  /^device\.registration\./,
  /^scheduled\.dispatch\.configured$/,
  /^scheduled\.dispatch\.enabled$/,
  /^scheduled\.skill-runner\.enabled$/,
  /^scheduled\.user-agent-catalog\.shared$/,
  /^scheduled\.user-agent-catalog\.unshared$/,
  /^studio\.member\.reassigned$/,
  /^studio\.team\.entry-member\.changed$/
];

export type AevatarRiskReason =
  | 'missing-outcome'
  | `outcome:${string}`
  | 'missing-action'
  | 'failure-action'
  | 'high-impact-action';

export function aevatarRiskReason(actionValue: string, outcomeValue: string): AevatarRiskReason | null {
  const outcome = outcomeValue.trim().toLowerCase();
  if (!outcome) return 'missing-outcome';
  if (!normalOutcomes.has(outcome)) return `outcome:${outcome}`;

  const action = actionValue.trim().toLowerCase();
  if (!action) return 'missing-action';
  // Attempt records do not prove a mutation happened. The paired terminal
  // record carries the final outcome and is classified independently.
  if (action.endsWith('.attempted')) return null;
  if (failureActionPatterns.some((pattern) => pattern.test(action))) return 'failure-action';
  if (reviewActionPatterns.some((pattern) => pattern.test(action))) return 'high-impact-action';
  return null;
}

export function isAevatarRecordSuspicious(action: string, outcome: string): boolean {
  return aevatarRiskReason(action, outcome) !== null;
}
