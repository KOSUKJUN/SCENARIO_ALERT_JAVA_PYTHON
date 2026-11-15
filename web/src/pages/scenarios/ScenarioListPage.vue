<script setup lang="ts">
import { computed, ref } from 'vue';
import { api } from '../../api';
import { has } from '../../auth';
import { useAsync } from '../../composables';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import SeverityBadge from '../../components/SeverityBadge.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import type { ScenarioSummary } from '../../types';
import { STATUSES, STATUS_LABEL, fmtSec, fmtTime } from '../../util';

const list = useAsync(() => api.get<ScenarioSummary[]>('/scenarios'));
const q = ref('');
const status = ref('');
const shown = computed(() => {
  const s = q.value.trim().toLowerCase();
  return (list.data.value ?? []).filter(
    (x) => (!status.value || x.status === status.value) && (!s || x.scenario_id.toLowerCase().includes(s) || x.name.toLowerCase().includes(s)),
  );
});
</script>
<template>
  <div class="page">
    <div class="page-head">
      <h2>시나리오 분석</h2>
      <div class="actions">
        <input v-model="q" placeholder="ID·이름 검색" data-testid="scenario-search" />
        <select v-model="status">
          <option value="">모든 상태</option>
          <option v-for="s in STATUSES" :key="s" :value="s">{{ STATUS_LABEL[s] }}</option>
        </select>
        <RouterLink v-if="has('author')" to="/scenarios/new" class="button primary" data-testid="scenario-new">새 순서도</RouterLink>
      </div>
    </div>
    <LoadingBox v-if="list.loading.value && !list.data.value" />
    <ErrorBox :error="list.error.value" />
    <div v-if="list.data.value" class="table-wrap card">
      <table class="table" data-testid="scenario-list">
        <thead>
          <tr>
            <th>ID</th><th>이름</th><th>상태</th><th>대상</th><th>참조 룰</th><th>경보 등급</th><th class="num">노드</th>
            <th>최대 기간</th><th>억제</th><th class="num">경보(24h)</th><th>수정</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in shown" :key="s.scenario_id">
            <td><RouterLink :to="`/scenarios/${s.scenario_id}`" :data-testid="`scenario-link-${s.scenario_id}`">{{ s.scenario_id }}</RouterLink></td>
            <td>{{ s.name }}</td>
            <td><StatusBadge :status="s.status" /></td>
            <td>{{ s.entity_type }}</td>
            <td class="small"><RouterLink v-for="r in s.rule_ids" :key="r" :to="`/single-rules/${r}`" class="chip">{{ r }}</RouterLink></td>
            <td><SeverityBadge v-for="v in s.severities" :key="v" :severity="v" /></td>
            <td class="num">{{ s.node_count }}</td>
            <td>{{ fmtSec(s.max_span_sec) }}</td>
            <td>{{ s.suppress_for }}</td>
            <td class="num">{{ s.alerts_24h ?? 0 }}</td>
            <td class="small">v{{ s.version }} · {{ fmtTime(s.updated_at) }}</td>
          </tr>
        </tbody>
      </table>
      <EmptyBox v-if="!shown.length">순서도가 없습니다</EmptyBox>
    </div>
  </div>
</template>
