<script setup lang="ts">
// 공통 레이아웃: 상단 GNB(보안관제 > 시나리오 분석) + 왼쪽 메뉴 + 본문.
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { auth, logout } from '../auth';
import { ROLE_LABEL } from '../util';

const router = useRouter();
const route = useRoute();
/** 상단 메뉴: 이 화면은 보안관제 > 시나리오 분석 하나만 둔다. */
const gnb = [{ label: '보안관제', children: [{ to: '/scenarios', label: '시나리오 분석', id: 'gnb-scenarios' }] }];
const links = computed(() => {
  const l = [
    { to: '/', label: '현황', id: 'dashboard' },
    { to: '/scenarios', label: '시나리오 분석', id: 'scenarios' },
    { to: '/alerts', label: '경보', id: 'alerts' },
    { to: '/attack', label: 'ATT&CK', id: 'attack' },
    { to: '/d3fend', label: 'D3FEND 대응', id: 'd3fend' },
    { to: '/settings', label: '설정', id: 'settings' },
  ];
  if (auth.me?.dev_tools) l.push({ to: '/dev', label: '테스트 데이터', id: 'dev' });
  return l;
});
const isActive = (to: string) => (to === '/' ? route.path === '/' : route.path.startsWith(to));
function doLogout() {
  logout();
  void router.replace('/login');
}
</script>
<template>
  <div class="shell">
    <header class="top_bar" data-testid="top-bar">
      <div class="header_box">
        <div class="header_content">
          <RouterLink to="/" class="top_logo">시나리오 탐지</RouterLink>
          <ul class="gnb" data-testid="gnb">
            <li v-for="m in gnb" :key="m.label" class="on" tabindex="0">
              <span class="navigation-menu-label">{{ m.label }}</span>
              <span class="menu_line" />
              <ul>
                <li v-for="c in m.children" :key="c.to" :class="{ on: isActive(c.to) }">
                  <RouterLink :to="c.to" :data-testid="c.id">{{ c.label }}</RouterLink>
                </li>
              </ul>
            </li>
          </ul>
        </div>
        <div v-if="auth.me" class="userbox" data-testid="userbox">
          <span class="username">{{ auth.me.username }}</span>
          <span class="role">{{ ROLE_LABEL[auth.me.role] ?? auth.me.role }}</span>
          <button class="small" data-testid="logout" @click="doLogout">로그아웃</button>
        </div>
      </div>
    </header>
    <div class="app">
      <aside class="sidebar">
        <div class="sidebar-title">보안관제</div>
        <nav>
          <RouterLink v-for="l in links" :key="l.to" :to="l.to" :data-testid="`nav-${l.id}`" :class="{ active: isActive(l.to) }">
            {{ l.label }}
          </RouterLink>
        </nav>
      </aside>
      <div class="main">
        <main class="content">
          <RouterView :key="route.path" />
        </main>
      </div>
    </div>
  </div>
</template>
