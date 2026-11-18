// MITRE ATT&CK 화면 공통 도우미.
import { api } from './api';
import type { AttackLookup } from './types';

export const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;

/** ATT&CK 설명 원문(마크다운 + 인용 표기 + <code>)을 읽기 쉬운 평문으로. */
export function attackText(s: string | null | undefined): string {
  if (!s) return '';
  return s
    .replace(/\(Citation:[^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/<\/?code>/g, '`')
    .replace(/<[^>]+>/g, '')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/ {2,}/g, ' ')
    .trim();
}

/** 기법 ID 들의 활성 버전 정보. 화면의 칩 표시에 쓴다. */
export async function lookupTechniques(ids: string[]): Promise<Record<string, AttackLookup>> {
  const valid = ids.filter((i) => TECHNIQUE_RE.test(i));
  if (!valid.length) return {};
  return api.post<Record<string, AttackLookup>>('/attack/techniques/lookup', { ids: valid });
}

export const STATUS_KO: Record<string, string> = { missing: '없음', revoked: '폐기', deprecated: '사용 중단' };
