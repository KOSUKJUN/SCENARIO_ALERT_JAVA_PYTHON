// 로그인 상태 (화면 전체에서 하나). 토큰은 localStorage, 사용자 정보는 GET /auth/me.
import { reactive } from 'vue';
import { api, getToken, request, setToken } from './api';
import type { LoginResponse, Me, Role } from './types';

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, author: 2, admin: 3 };

export const auth = reactive<{ me: Me | null; ready: boolean }>({ me: null, ready: false });

let initPromise: Promise<void> | null = null;

/** 첫 화면 전에 한 번: 저장된 토큰이 있으면 사용자 정보를 받아 둔다. */
export function initAuth(): Promise<void> {
  if (!initPromise) {
    initPromise = (async () => {
      if (getToken()) {
        try {
          auth.me = await api.get<Me>('/auth/me');
        } catch {
          auth.me = null;
        }
      }
      auth.ready = true;
    })();
  }
  return initPromise;
}

export async function login(username: string, password: string): Promise<void> {
  const r = await request<LoginResponse>('POST', '/auth/login', { username, password }, { noRedirect: true });
  setToken(r.token);
  auth.me = await api.get<Me>('/auth/me');
}

export function logout(): void {
  api.post('/auth/logout').catch(() => undefined);
  setToken(null);
  auth.me = null;
}

/** 판정·사고 관련 항목을 보여 줄지 (설정 > 화면 에서 관리자가 켠다. 기본 숨김) */
export function showIncident(): boolean {
  return !!auth.me?.ui?.show_incident;
}

export function has(role: Role): boolean {
  return !!auth.me && RANK[auth.me.role] >= RANK[role];
}
