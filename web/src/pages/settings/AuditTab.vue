<script setup lang="ts">
import { ref } from 'vue';
import { api } from '../../api';
import { useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import type { Row } from '../../types';
import { fmtTime } from '../../util';

const limit = ref(200);
const log = useAsync(() => api.get<Row[]>('/audit', { limit: limit.value }), [limit]);
const text = (v: unknown) => (v === null || v === undefined ? '' : typeof v === 'string' ? v : JSON.stringify(v));
</script>
<template>
  <CardBox title="감사 로그">
    <template #actions>
      <select v-model.number="limit">
        <option :value="200">최근 200건</option>
        <option :value="1000">최근 1000건</option>
      </select>
    </template>
    <ErrorBox :error="log.error.value" />
    <div v-if="log.data.value" class="table-wrap">
      <table class="table compact" data-testid="audit-log">
        <thead><tr><th>시각</th><th>사용자</th><th>동작</th><th>대상</th><th>내용</th></tr></thead>
        <tbody>
          <tr v-for="(r, i) in log.data.value" :key="i">
            <td>{{ fmtTime(r.at) }}</td><td>{{ text(r.actor) }}</td><td>{{ text(r.action) }}</td><td>{{ text(r.target) }}</td>
            <td class="small code-inline">{{ text(r.detail) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </CardBox>
</template>
