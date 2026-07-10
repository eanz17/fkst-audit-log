import type { TimeRange } from '../types';

export function formatDateTime(value: string | null): string {
  if (!value) return '尚未运行';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).format(date);
}

export function formatRelative(value: string | null): string {
  if (!value) return '无记录';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const diff = Date.now() - date.getTime();
  const minutes = Math.round(diff / 60000);
  if (minutes < 1) return '刚刚';
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  return `${Math.round(hours / 24)} 天前`;
}

export function inTimeRange(timestamp: string, range: TimeRange): boolean {
  if (range === 'all') return true;
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return true;
  const spans: Record<Exclude<TimeRange, 'all'>, number> = {
    '15m': 15 * 60 * 1000,
    '1h': 60 * 60 * 1000,
    '6h': 6 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000
  };
  return Date.now() - date.getTime() <= spans[range];
}
