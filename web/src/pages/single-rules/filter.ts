// 조건(filter) 트리 도우미. 필드·연산자 목록은 /meta/fields 에서 받은 것만 쓴다.
import type { ApiIssue } from '../../api';
import type { FieldMeta, FilterLeaf, FilterNode, Json, MetaFields } from '../../types';

export type FormIssue = ApiIssue & { level?: 'error' | 'warn' };

export interface FilterCtx {
  meta: MetaFields;
  dataTp: string[];
  issues: FormIssue[];
  readOnly?: boolean;
}

export const MAX_DEPTH = 5;
export const SCALAR_LIST_OPS = new Set(['in', 'not_in']);
export const LIST_ID_OPS = new Set(['in_list', 'not_in_list', 'contains_list']);

export function isGroup(n: FilterNode): n is { all: FilterNode[] } | { any: FilterNode[] } {
  return 'all' in n || 'any' in n;
}

export function isNot(n: FilterNode): n is { not: FilterNode } {
  return 'not' in n;
}

/** path 에 해당하는 이슈 (prefix=true 면 하위 경로 포함). */
export function issuesFor(issues: FormIssue[], path: string, prefix = true): FormIssue[] {
  return issues.filter(
    (i) =>
      i.path !== undefined &&
      (i.path === path || (prefix && (i.path.startsWith(`${path}.`) || i.path.startsWith(`${path}[`)))),
  );
}

export function fieldAvailability(f: FieldMeta | undefined, dataTp: string[]): { none: boolean; missing: string[] } {
  if (!f || !dataTp.length) return { none: false, missing: [] };
  const missing = dataTp.filter((d) => !f.available.includes(d));
  return { none: missing.length === dataTp.length, missing };
}

export function defaultValue(meta: MetaFields, f: FieldMeta, op: string): Json | undefined {
  if (op === 'exists') return undefined;
  if (SCALAR_LIST_OPS.has(op)) return [];
  if (LIST_ID_OPS.has(op)) return meta.lists[0]?.list_id ?? '';
  if (op === 'has_tag') return meta.asset_tags[0] ?? '';
  if (f.type === 'bool' || f.type === 'peer') return true;
  if (f.type === 'int') return 0;
  if (f.enum.length) return f.enum[0];
  return '';
}

export function leaf(field: string, op: string, value: Json | undefined): FilterLeaf {
  return value === undefined ? { field, op } : { field, op, value };
}

export function makeLeaf(meta: MetaFields, fieldName?: string, op?: string): FilterLeaf {
  const f = meta.fields.find((x) => x.name === fieldName) ?? meta.fields[0];
  const o = op && f.ops.includes(op) ? op : f.ops[0];
  return leaf(f.name, o, defaultValue(meta, f, o));
}
