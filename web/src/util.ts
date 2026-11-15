// 표시용 도우미 (시각, 기간, 라벨).
import type { Severity, Status } from './types';

export const STATUS_LABEL: Record<string, string> = {
  draft: '초안',
  silent: '조용히 운영',
  active: '운영',
  disabled: '중지',
};

export const SEVERITY_LABEL: Record<string, string> = {
  critical: '긴급',
  high: '높음',
  medium: '중간',
  low: '낮음',
};

export const VERDICT_LABEL: Record<string, string> = {
  true_positive: '정탐',
  false_positive: '오탐',
  benign: '정상 행위',
};

export const DELIVERY_LABEL: Record<string, string> = {
  pending: '전달 대기',
  sent: '전달됨',
  failed: '전달 실패',
  skipped: '전달 안 함(silent)',
};

export const ROLE_LABEL: Record<string, string> = {
  viewer: '조회자',
  analyst: '분석가',
  author: '작성자',
  admin: '관리자',
};

export const NODE_TYPE_LABEL: Record<string, string> = {
  start: '시작',
  rule: '단일룰',
  check: '룰 확인(마름모)',
  asset: '자산 확인(마름모)',
  and: '모두 합류(AND)',
  or: '하나 합류(OR)',
  alert: '경보',
};

export const STATUSES: Status[] = ['draft', 'silent', 'active', 'disabled'];
export const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical'];

/** ISO 시각 → "2026-11-13 10:20:30" (서버가 +09:00 로 준다). */
export function fmtTime(v: unknown): string {
  if (typeof v !== 'string' || !v) return '-';
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/.exec(v);
  return m ? `${m[1]} ${m[2]}` : v;
}

const UNIT_LABEL: Record<string, string> = { s: '초', m: '분', h: '시간', d: '일' };

/** "30m" → "30분" */
export function fmtDuration(v: string | undefined | null): string {
  if (!v) return '';
  const m = /^(\d+)\s*([smhd])$/.exec(v.trim());
  return m ? `${m[1]}${UNIT_LABEL[m[2]]}` : v;
}

export function parseDurationSec(v: string | undefined | null): number | null {
  if (!v) return null;
  const m = /^(\d+)\s*([smhd])$/.exec(v.trim());
  if (!m) return null;
  const mult: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
  return Number(m[1]) * mult[m[2]];
}

export function isDuration(v: string | undefined | null): boolean {
  return parseDurationSec(v) !== null && (parseDurationSec(v) ?? 0) > 0;
}

export function fmtSec(sec: number | null | undefined): string {
  if (sec === null || sec === undefined) return '-';
  const s = Math.round(sec);
  if (s < 60) return `${s}초`;
  if (s < 3600) return `${Math.floor(s / 60)}분 ${s % 60}초`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간 ${Math.floor((s % 3600) / 60)}분`;
  return `${Math.floor(s / 86400)}일 ${Math.floor((s % 86400) / 3600)}시간`;
}

export function fmtPct(v: number | null | undefined): string {
  if (v === null || v === undefined) return '-';
  return `${(v * 100).toFixed(1)}%`;
}

export function fmtNum(v: unknown): string {
  if (typeof v === 'number') return Number.isInteger(v) ? v.toLocaleString('ko-KR') : v.toFixed(1);
  return v === null || v === undefined ? '-' : String(v);
}

/** datetime-local 입력값 (로컬 시각) */
export function toLocalInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** datetime-local 값 → +09:00 ISO (서버는 KST 기준). 브라우저 시간대가 달라도 입력값을 KST 로 본다. */
export function localInputToIso(v: string): string {
  if (!v) return '';
  const base = v.length === 16 ? `${v}:00` : v;
  return `${base}+09:00`;
}

/** 지금 KST 시각을 datetime-local 형식으로 (offsetHours 만큼 이동). */
export function kstInput(offsetHours = 0): string {
  const now = Date.now() + offsetHours * 3600_000;
  const kst = new Date(now + 9 * 3600_000);
  return kst.toISOString().slice(0, 16);
}

export function cellText(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(v) ? fmtTime(v) : v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return JSON.stringify(v);
}

export function downloadJson(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function truthy(v: unknown): boolean {
  return v === true || v === 1 || v === '1' || v === 'true';
}

export function splitList(s: string): string[] {
  return s
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);
}
