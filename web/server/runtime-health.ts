export function runtimeLogFailed(file: string, text: string): boolean {
  // A dead-letter department exits successfully after handling the failed
  // delivery, so its terminal EXIT=0 does not mean the pipeline is healthy.
  if (file.includes('.dead_letter-') && /\btag=DEAD_LETTER\b/i.test(text)) {
    return true;
  }

  if (/\[framework\]\s+pipeline failed:/i.test(text)) {
    return true;
  }

  // Child logs contain many nested command fields such as `timeout=600`,
  // `ERROR_CLASS=...`, and `EXIT=0`. Only the standalone final EXIT line is
  // the child process outcome; scanning arbitrary payload text causes false
  // failures whenever an audit action or analyzer prompt says "failed".
  const terminalExits = Array.from(text.matchAll(/^EXIT=(-?\d+)\s*$/gm));
  if (terminalExits.length > 0) {
    return Number(terminalExits[terminalExits.length - 1][1]) !== 0;
  }

  // While a log is still being written there may be no terminal EXIT yet. An
  // explicit command timeout is actionable; otherwise treat the active child
  // as healthy until it publishes a terminal outcome.
  return /\bTIMED_OUT=true\b/.test(text);
}

export function deadLetterBatchId(text: string): string | null {
  const deliveryId = text.match(/\bDELIVERY=([^\s]+)/)?.[1];
  const encodedDedup = deliveryId?.split('/dedup/')[1];
  if (!encodedDedup) return null;

  const decodedDedup = encodedDedup.replace(/_([0-9a-f]{2})_/gi, (_token, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16))
  );
  const prefix = 'audit-batch/';
  if (!decodedDedup.startsWith(prefix)) return null;

  const batchId = decodedDedup.slice(prefix.length);
  return /^[a-zA-Z0-9._-]+$/.test(batchId) ? batchId : null;
}

export function cacheValueIsFresh(text: string, nowMs = Date.now()): boolean {
  const expiresAt = text.match(/^fkst-cache-v1 expires_at=(\d+)\s*$/m)?.[1];
  if (!expiresAt) return false;
  try {
    return BigInt(expiresAt) > BigInt(Math.trunc(nowMs)) * 1_000_000n;
  } catch {
    return false;
  }
}
