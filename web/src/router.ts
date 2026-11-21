import { createRouter, createWebHistory } from 'vue-router';
import { auth, initAuth } from './auth';
import AppLayout from './components/AppLayout.vue';

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', component: () => import('./pages/LoginPage.vue'), meta: { public: true } },
    // 새 창(팝업): 메뉴 없이 이벤트 탐지모듈 목록만
    { path: '/popup/modules', component: () => import('./pages/scenarios/ModulesPopupPage.vue') },
    {
      path: '/',
      component: AppLayout,
      children: [
        { path: '', component: () => import('./pages/DashboardPage.vue') },
        // 시나리오 분석 (왼쪽 그룹 + 시나리오 리스트, 이벤트 탐지모듈 목록은 새 창 /popup/modules). 이벤트 탐지모듈은 서버 API 로는 /single-rules 다.
        { path: 'scenarios', component: () => import('./pages/scenarios/ScenarioHubPage.vue') },
        { path: 'scenarios/detections', redirect: '/scenarios' },
        { path: 'scenarios/detections/new', component: () => import('./pages/single-rules/RuleEditorPage.vue') },
        { path: 'scenarios/detections/import-snort', component: () => import('./pages/single-rules/SnortImportPage.vue') },
        { path: 'scenarios/detections/:ruleId', component: () => import('./pages/single-rules/RuleEditorPage.vue'), props: true },
        { path: 'scenarios/new', component: () => import('./pages/scenarios/ScenarioEditorPage.vue') },
        { path: 'scenarios/:scenarioId', component: () => import('./pages/scenarios/ScenarioEditorPage.vue'), props: true },
        // 예전 주소 (북마크, 사고처리 시스템에 남은 링크)
        { path: 'single-rules', redirect: '/scenarios' },
        { path: 'single-rules/:rest(.*)', redirect: (to) => `/scenarios/detections/${String(to.params.rest)}` },
        { path: 'alerts', component: () => import('./pages/alerts/AlertListPage.vue') },
        { path: 'alerts/:alertId', component: () => import('./pages/alerts/AlertDetailPage.vue'), props: true },
        { path: 'attack/:tab?', component: () => import('./pages/attack/AttackPage.vue'), props: true },
        { path: 'd3fend/:tab?', component: () => import('./pages/d3fend/D3fendPage.vue'), props: true },
        { path: 'settings/:tab?', component: () => import('./pages/settings/SettingsPage.vue'), props: true },
        { path: 'dev', component: () => import('./pages/DevPage.vue') },
        { path: ':rest(.*)*', redirect: '/' },
      ],
    },
  ],
});

router.beforeEach(async (to) => {
  await initAuth();
  if (to.meta.public) return auth.me && to.path === '/login' ? '/' : true;
  if (!auth.me) return { path: '/login', query: { from: to.fullPath } };
  return true;
});
