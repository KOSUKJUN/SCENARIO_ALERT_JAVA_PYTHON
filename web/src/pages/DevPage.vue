<script setup lang="ts">
// 개발·테스트 환경 전용: 지금 시각으로 공격 패턴 이벤트를 넣는다 (ENABLE_DEV_TOOLS).
import { ref } from 'vue';
import { api } from '../api';
import { has } from '../auth';
import { useAsync } from '../composables';
import CardBox from '../components/CardBox.vue';
import ErrorBox from '../components/ErrorBox.vue';
import LoadingBox from '../components/LoadingBox.vue';
import NoticeBox from '../components/NoticeBox.vue';
import RowsTable from '../components/RowsTable.vue';
import type { Org, Row } from '../types';

interface Catalog {
  scenarios: { key: string; title: string; expect: string; default_host: string }[];
  event_counts: Row[];
}
const cat = useAsync(() => api.get<Catalog>('/dev/sample-data'));
const orgs = useAsync(() => api.get<Org[]>('/orgs'));
const org = ref('ORG001');
const busy = ref<string | null>(null);
const err = ref<unknown>(null);
const result = ref<string | null>(null);

async function run(key: string, fn: () => Promise<unknown>) {
  busy.value = key;
  err.value = null;
  result.value = null;
  try {
    result.value = JSON.stringify(await fn(), null, 2);
    cat.reload();
  } catch (e) {
    err.value = e;
  } finally {
    busy.value = null;
  }
}
</script>
<template>
  <div class="page">
    <div class="page-head"><h2>테스트 데이터</h2></div>
    <NoticeBox kind="warn">개발·테스트 환경 전용 기능입니다. 운영 ClickHouse 에서는 꺼져 있어야 합니다 (ENABLE_DEV_TOOLS).</NoticeBox>
    <ErrorBox :error="err || cat.error.value" />
    <LoadingBox v-if="cat.loading.value && !cat.data.value" />
    <CardBox v-if="cat.data.value" title="시나리오 주입 (지금 시각)">
      <div class="form-row">
        <label class="inline">
          기관
          <select v-model="org">
            <option v-for="o in orgs.data.value ?? []" :key="o.org_id" :value="o.org_id">{{ o.org_id }} {{ o.name }}</option>
          </select>
        </label>
        <button class="small" :disabled="!!busy || !has('author')" @click="run('bg', () => api.post('/dev/sample-data/background', {}, { minutes: 5 }))">
          정상 트래픽 5분
        </button>
        <button class="small" :disabled="!!busy || !has('author')" @click="run('all', () => api.post('/dev/sample-data/inject', { scenario: 'all', org_id: org }))">
          전체 주입
        </button>
      </div>
      <table class="table compact">
        <thead><tr><th>키</th><th>내용</th><th>기대 결과</th><th>기본 대상</th><th /></tr></thead>
        <tbody>
          <tr v-for="s in cat.data.value.scenarios" :key="s.key">
            <td>{{ s.key }}</td><td>{{ s.title }}</td><td class="small">{{ s.expect }}</td><td>{{ s.default_host }}</td>
            <td>
              <button
                class="small"
                :disabled="!!busy || !has('author')"
                :data-testid="`inject-${s.key}`"
                @click="run(s.key, () => api.post('/dev/sample-data/inject', { scenario: s.key, org_id: org }))"
              >
                {{ busy === s.key ? '주입 중…' : '주입' }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      <p class="muted small">주입 후 1~2분 안에 이벤트 탐지모듈 히트와 경보가 생깁니다 (평가 주기 + 15초 지연).</p>
    </CardBox>
    <CardBox v-if="result" title="결과"><pre class="code small">{{ result }}</pre></CardBox>
    <CardBox v-if="cat.data.value" title="최근 30일 이벤트 (유형별)">
      <RowsTable :rows="cat.data.value.event_counts" />
    </CardBox>
  </div>
</template>
