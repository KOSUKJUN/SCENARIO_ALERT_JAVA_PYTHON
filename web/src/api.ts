// 탐지 서버 API 클라이언트. 모든 경로는 /api/v1 아래, 인증은 Bearer 토큰.
import type { Json } from './types';

const BASE = '/api/v1';
const TOKEN_KEY = 'scenario_token';

/** 검증 오류 한 줄. 단일룰은 path, 순서도는 target/id 를 쓴다. */
export interface ApiIssue {
  message: string;
  path?: string;
  target?: 'node' | 'edge' | 'graph';
  id?: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;
  readonly errors: ApiIssue[];
  readonly warnings: ApiIssue[];

  constructor(status: number, detail: string, errors: ApiIssue[] = [], warnings: ApiIssue[] = []) {
    super(detail);
    this.status = status;
    this.detail = detail;
    this.errors = errors;
    this.warnings = warnings;
  }
}

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* 저장소를 쓸 수 없는 환경 */
  }
}

let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorized = fn;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function toIssues(v: unknown): ApiIssue[] {
  if (!Array.isArray(v)) return [];
  return v.filter(isRecord).map((x) => ({
    message: String(x.message ?? x.msg ?? ''),
    path: typeof x.path === 'string' ? x.path : undefined,
    target: x.target === 'node' || x.target === 'edge' || x.target === 'graph' ? x.target : undefined,
    id: typeof x.id === 'string' ? x.id : undefined,
  }));
}

function parseError(status: number, body: unknown, fallback: string): ApiError {
  if (isRecord(body)) {
    const d = body.detail;
    if (typeof d === 'string') return new ApiError(status, d, toIssues(body.errors), toIssues(body.warnings));
    if (Array.isArray(d)) {
      // FastAPI 요청 형식 오류: [{loc, msg}]
      const errs = d.filter(isRecord).map((x) => ({
        message: String(x.msg ?? ''),
        path: Array.isArray(x.loc) ? x.loc.filter((p) => p !== 'body').join('.') : undefined,
      }));
      return new ApiError(status, '요청 형식이 올바르지 않습니다', errs);
    }
  }
  return new ApiError(status, fallback);
}

export interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined | null>;
  /** 401 이어도 로그인 화면으로 보내지 않는다 (로그인 요청 자체). */
  noRedirect?: boolean;
}

export async function request<T>(method: string, path: string, body?: unknown, opts: RequestOptions = {}): Promise<T> {
  let url = BASE + path;
  if (opts.query) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
    }
    const s = qs.toString();
    if (s) url += (url.includes('?') ? '&' : '?') + s;
  }
  const headers: Record<string, string> = { Accept: 'application/json' };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let res: Response;
  try {
    res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError(0, '서버에 연결할 수 없습니다');
  }
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const err = parseError(res.status, data, `요청 실패 (${res.status})`);
    if (res.status === 401 && !opts.noRedirect) {
      setToken(null);
      onUnauthorized?.();
    }
    throw err;
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, query?: RequestOptions['query']) => request<T>('GET', path, undefined, { query }),
  post: <T>(path: string, body?: unknown, query?: RequestOptions['query']) =>
    request<T>('POST', path, body ?? {}, { query }),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
  del: <T>(path: string) => request<T>('DELETE', path),
};

/** 오류를 사람이 읽을 문장으로 (detail + errors). */
export function errorText(e: unknown): string {
  if (e instanceof ApiError) {
    const lines = [e.detail];
    for (const i of e.errors) {
      const where = i.path ?? (i.id ? `${i.target ?? ''} ${i.id}`.trim() : '');
      lines.push(where ? `· ${where}: ${i.message}` : `· ${i.message}`);
    }
    return lines.join('\n');
  }
  if (e instanceof Error) return e.message;
  return String(e);
}

export function enc(s: string): string {
  return encodeURIComponent(s);
}

export type { Json };
