import { createApp } from 'vue';
import '@vue-flow/core/dist/style.css';
import '@vue-flow/core/dist/theme-default.css';
import '@vue-flow/controls/dist/style.css';
import '@vue-flow/minimap/dist/style.css';
import './styles.css';
import App from './App.vue';
import { setUnauthorizedHandler } from './api';
import { auth } from './auth';
import { router } from './router';

setUnauthorizedHandler(() => {
  auth.me = null;
  if (router.currentRoute.value.path !== '/login') {
    void router.replace({ path: '/login', query: { from: router.currentRoute.value.fullPath } });
  }
});

createApp(App).use(router).mount('#app');
