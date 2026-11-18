import { createRouter, createWebHistory } from 'vue-router';
import { auth, initAuth } from './auth';
import AppLayout from './components/AppLayout.vue';

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', component: () => import('./pages/LoginPage.vue'), meta: { public: true } },
    {
      path: '/',
      component: AppLayout,
      children: [
        { path: '', component: () => import('./pages/DashboardPage.vue') },
        { path: 'single-rules', component: () => import('./pages/single-rules/RuleListPage.vue') },
        { path: 'single-rules/new', component: () => import('./pages/single-rules/RuleEditorPage.vue') },
        { path: 'single-rules/import-snort', component: () => import('./pages/single-rules/SnortImportPage.vue') },
        { path: 'single-rules/:ruleId', component: () => import('./pages/single-rules/RuleEditorPage.vue'), props: true },
        { path: 'scenarios', component: () => import('./pages/scenarios/ScenarioListPage.vue') },
        { path: 'scenarios/new', component: () => import('./pages/scenarios/ScenarioEditorPage.vue') },
        { path: 'scenarios/:scenarioId', component: () => import('./pages/scenarios/ScenarioEditorPage.vue'), props: true },
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
