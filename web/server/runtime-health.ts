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
