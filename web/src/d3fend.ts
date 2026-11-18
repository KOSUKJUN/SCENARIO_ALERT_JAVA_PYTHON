// MITRE D3FEND (대응방책) 화면 공통 도우미.
import { api } from './api';
import type { D3fendLookup } from './types';

export const D3FEND_RE = /^D3-[A-Z0-9]{1,16}$/;

/** D3FEND 전술 한글 이름. 사고 대응은 격리·퇴출·복구, 재발 방지는 탐지·강화. */
export const TACTIC_KO: Record<string, string> = {
  Model: '모델링', Harden: '강화', Detect: '탐지', Isolate: '격리', Deceive: '기만', Evict: '퇴출', Restore: '복구',
};
export const RESPONSE_TACTICS = ['Isolate', 'Evict', 'Restore'];

export function tacticLabel(t: string | null | undefined): string {
  if (!t) return '';
  return TACTIC_KO[t] ? `${TACTIC_KO[t]} (${t})` : t;
}

/** D3FEND 설명(마크다운 + 링크 HTML)을 읽기 쉬운 평문으로. */
export function d3fendText(s: string | null | undefined): string {
  if (!s) return '';
  return s
    .replace(/<a [^>]*>([^<]*)<\/a>/g, '$1')
    .replace(/<[^>]+>/g, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/^#{1,6}\s*/gm, '')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** 대응 기법 ID 들의 활성 버전 정보 (칩 표시). */
export async function lookupD3fend(ids: string[]): Promise<Record<string, D3fendLookup>> {
  const valid = ids.filter((i) => D3FEND_RE.test(i));
  if (!valid.length) return {};
  return api.post<Record<string, D3fendLookup>>('/d3fend/techniques/lookup', { ids: valid });
}
