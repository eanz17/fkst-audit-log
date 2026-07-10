import type { DashboardPayload } from '../types';

export async function fetchDashboard(signal?: AbortSignal): Promise<DashboardPayload> {
  const response = await fetch('/api/dashboard', {
    headers: { Accept: 'application/json' },
    signal
  });
  if (!response.ok) {
    throw new Error(`dashboard api failed: ${response.status}`);
  }
  return response.json() as Promise<DashboardPayload>;
}
