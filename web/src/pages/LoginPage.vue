<script setup lang="ts">
// 로그인: 통합 관제 화면의 로그인과 같은 모양 (어두운 배경, 물결, 반투명 카드, User ID / Password / Log In).
import { ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { login } from '../auth';
import ErrorBox from '../components/ErrorBox.vue';

const router = useRouter();
const route = useRoute();
const username = ref('');
const password = ref('');
const error = ref<unknown>(null);
const busy = ref(false);

async function submit() {
  busy.value = true;
  error.value = null;
  try {
    await login(username.value, password.value);
    const from = typeof route.query.from === 'string' ? route.query.from : '/';
    await router.replace(from);
  } catch (e) {
    error.value = e;
  } finally {
    busy.value = false;
  }
}
</script>
<template>
  <div class="login-screen">
    <div class="login-inner">
      <div class="login-waves" aria-hidden="true">
        <div class="wave -one" />
        <div class="wave -two" />
        <div class="wave -three" />
      </div>
      <div class="login-pages">
        <form class="login-area" @submit.prevent="submit">
          <div class="login-body">
            <h1 class="login-title">시나리오 탐지<small>보안관제 · 시나리오 분석</small></h1>
            <label>
              User ID
              <input v-model="username" data-testid="login-username" placeholder="User ID" autocomplete="username" autofocus required />
            </label>
            <label>
              Password
              <input v-model="password" type="password" data-testid="login-password" placeholder="Password" autocomplete="current-password" required />
            </label>
            <ErrorBox :error="error" />
            <button class="primary block" type="submit" :disabled="busy || !username" data-testid="login-submit">
              {{ busy ? 'Logging in…' : 'Log In' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>
